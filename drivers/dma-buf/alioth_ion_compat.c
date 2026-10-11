// SPDX-License-Identifier: GPL-2.0-only
/* Modern ION ABI bridge for alioth vendor heaps. */
#include <linux/compat.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <uapi/linux/ion.h>
#include <uapi/linux/msm_ion.h>

#define ALIOTH_ION_CACHED 1

/* Heap query types are the donor ABI values, not the newer kernel enum. */
#define ALIOTH_ION_SYSTEM_SECURE 7
#define ALIOTH_ION_HYP_CMA 8
#define ALIOTH_ION_SECURE_CARVEOUT 9
#define ALIOTH_ION_CAMERA 10

struct alioth_ion_heap {
	struct ion_heap_data info;
	const char *cached;
	const char *uncached;
};

static const struct alioth_ion_heap alioth_heaps[] = {
	{ { .name = "camera", .type = ALIOTH_ION_CAMERA, .heap_id = 20 },
	  "qcom,system", "qcom,system-uncached" },
	{ { .name = "system", .type = ION_HEAP_TYPE_SYSTEM, .heap_id = 25 },
	  "qcom,system", "qcom,system-uncached" },
	{ { .name = "adsp", .type = ION_HEAP_TYPE_DMA, .heap_id = 22 },
	  "qcom,alioth-adsp", "qcom,alioth-adsp-uncached" },
	{ { .name = "user_contig", .type = ION_HEAP_TYPE_DMA, .heap_id = 26 },
	  "qcom,alioth-user-contig", "qcom,alioth-user-contig-uncached" },
	{ { .name = "qseecom", .type = ION_HEAP_TYPE_DMA, .heap_id = 27 },
	  "qcom,alioth-qseecom", "qcom,alioth-qseecom-uncached" },
	{ { .name = "qseecom_ta", .type = ION_HEAP_TYPE_DMA, .heap_id = 19 },
	  "qcom,alioth-qseecom-ta", "qcom,alioth-qseecom-ta-uncached" },
};

struct alioth_secure_heap {
	u32 flag;
	const char *name;
};
static const struct alioth_secure_heap alioth_secure_heaps[] = {
	{ ION_FLAG_CP_TOUCH, "qcom,secure-touch" },
	{ ION_FLAG_CP_BITSTREAM, "qcom,secure-bitstream" },
	{ ION_FLAG_CP_PIXEL, "qcom,secure-pixel" },
	{ ION_FLAG_CP_NON_PIXEL, "qcom,secure-non-pixel" },
	{ ION_FLAG_CP_CAMERA, "qcom,secure-camera" },
};

/* Legacy flag bits 16 and 28 have different meanings in DMA-BUF heaps.
 * Select a fixed-VMID exporter rather than forwarding legacy flags.
 */
static const char *alioth_secure_heap_name(u32 flags)
{
	unsigned int i;

	if (!(flags & ION_FLAG_SECURE) ||
	    flags & ~(ION_FLAG_SECURE | ION_FLAG_ALLOW_NON_CONTIG |
		      ION_FLAG_CP_TOUCH | ION_FLAG_CP_BITSTREAM |
		      ION_FLAG_CP_PIXEL | ION_FLAG_CP_NON_PIXEL |
		      ION_FLAG_CP_CAMERA))
		return NULL;
	for (i = 0; i < ARRAY_SIZE(alioth_secure_heaps); i++)
		if ((flags & ION_FLAGS_CP_MASK) == alioth_secure_heaps[i].flag)
			return alioth_secure_heaps[i].name;
	return NULL;
}

/* Heap 13 accepts the donor SPSS/HLOS target, with optional explicit HLOS
 * ownership, SECURE marker and CPU cache selection. Never forward ION flags.
 */
static const char *alioth_spss_heap_name(u32 flags)
{
	if (!(flags & ION_FLAG_CP_SPSS_HLOS_SHARED) ||
	    flags & ~(ION_FLAG_CP_SPSS_HLOS_SHARED | ION_FLAG_CP_HLOS |
		      ION_FLAG_SECURE | ALIOTH_ION_CACHED))
		return NULL;
	if (flags & ION_FLAG_CP_HLOS)
		return flags & ALIOTH_ION_CACHED ? "qcom,alioth-spss-hlos" :
			"qcom,alioth-spss-hlos-uncached";
	return flags & ALIOTH_ION_CACHED ? "qcom,alioth-spss" :
		"qcom,alioth-spss-uncached";
}

/* The donor ignores cache selection on protected CDSP carveout memory. */
static const char *alioth_cdsp_heap_name(u32 flags)
{
	if (!(flags & ION_FLAG_CP_CDSP) ||
	    flags & ~(ION_FLAG_CP_CDSP | ION_FLAG_SECURE | ALIOTH_ION_CACHED))
		return NULL;
	return "qcom,alioth-cdsp-secure";
}

/* Camera heap 20 has the donor nonsecure system-page allocation contract.
 * Preserve the camera/system fallback mask without accepting arbitrary masks.
 */
static const char *alioth_nonsecure_heap_name(u32 mask, u32 flags)
{
	unsigned int i;

	if (flags & ~ALIOTH_ION_CACHED)
		return NULL;
	if (mask == (BIT(20) | BIT(25)))
		mask = BIT(20);
	for (i = 0; i < ARRAY_SIZE(alioth_heaps); i++)
		if (mask == BIT(alioth_heaps[i].info.heap_id))
			return flags & ALIOTH_ION_CACHED ?
				alioth_heaps[i].cached : alioth_heaps[i].uncached;
	return NULL;
}

static bool alioth_secure_available(void)
{
	struct dma_heap *heap;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(alioth_secure_heaps); i++) {
		heap = dma_heap_find(alioth_secure_heaps[i].name);
		if (!heap)
			return false;
		dma_heap_put(heap);
	}
	return true;
}

static bool alioth_heap_available(const struct alioth_ion_heap *entry)
{
	struct dma_heap *cached = dma_heap_find(entry->cached);
	struct dma_heap *uncached = dma_heap_find(entry->uncached);
	bool available = cached && uncached;

	if (cached)
		dma_heap_put(cached);
	if (uncached)
		dma_heap_put(uncached);
	return available;
}

static long alioth_ion_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	void __user *user = (void __user *)arg;
	struct ion_allocation_data allocation;
	struct ion_heap_query query;
	struct ion_heap_data info[ARRAY_SIZE(alioth_heaps) + 4];
	unsigned int i, count = 0;
	struct dma_heap *heap;
	struct dma_buf *buffer;
	int fd;
	const char *heap_name;

	switch (cmd) {
	case ION_IOC_HEAP_QUERY:
		if (copy_from_user(&query, user, sizeof(query)))
			return -EFAULT;
		if (query.reserved0 || query.reserved1 || query.reserved2)
			return -EINVAL;
		for (i = 0; i < ARRAY_SIZE(alioth_heaps); i++)
			if (alioth_heap_available(&alioth_heaps[i]))
				info[count++] = alioth_heaps[i].info;
		if (alioth_secure_available()) {
			info[count++] = (struct ion_heap_data) {
				.name = "system_secure",
				.type = ALIOTH_ION_SYSTEM_SECURE,
				.heap_id = 9,
			};
		}
		heap = dma_heap_find("qcom,alioth-secure-display");
		if (heap) {
			info[count++] = (struct ion_heap_data) {
				.name = "secure_display",
				.type = ALIOTH_ION_HYP_CMA,
				.heap_id = 10,
			};
			dma_heap_put(heap);
		}
		{
			const struct alioth_ion_heap spss = {
				{ .name = "spss", .type = ALIOTH_ION_HYP_CMA, .heap_id = 13 },
				"qcom,alioth-spss", "qcom,alioth-spss-uncached"
			};

			if (alioth_heap_available(&spss))
				info[count++] = spss.info;
		}
		heap = dma_heap_find("qcom,alioth-cdsp-secure");
		if (heap) {
			info[count++] = (struct ion_heap_data) {
				.name = "secure_carveout",
				.type = ALIOTH_ION_SECURE_CARVEOUT,
				.heap_id = 14,
			};
			dma_heap_put(heap);
		}
		if (query.heaps && query.cnt &&
		    copy_to_user(u64_to_user_ptr(query.heaps), info,
				 min(query.cnt, count) * sizeof(info[0])))
			return -EFAULT;
		query.cnt = count;
		return copy_to_user(user, &query, sizeof(query)) ? -EFAULT : 0;
	case ION_IOC_ALLOC:
		if (copy_from_user(&allocation, user, sizeof(allocation)))
			return -EFAULT;
		if (allocation.unused)
			return -EINVAL;
		if (!allocation.len ||
		    allocation.len > SIZE_MAX - PAGE_SIZE + 1)
			return -EINVAL;
		if (allocation.heap_id_mask == BIT(9)) {
			heap_name = alioth_secure_heap_name(allocation.flags);
			if (!heap_name)
				return -EOPNOTSUPP;
		} else if (allocation.heap_id_mask == BIT(13)) {
			heap_name = alioth_spss_heap_name(allocation.flags);
			if (!heap_name)
				return -EOPNOTSUPP;
		} else if (allocation.heap_id_mask == BIT(14)) {
			heap_name = alioth_cdsp_heap_name(allocation.flags);
			if (!heap_name)
				return -EOPNOTSUPP;
		} else if (allocation.heap_id_mask == BIT(10)) {
			if (allocation.flags != (ION_FLAG_SECURE | ION_FLAG_CP_SEC_DISPLAY))
				return -EOPNOTSUPP;
			heap_name = "qcom,alioth-secure-display";
		} else {
			heap_name = alioth_nonsecure_heap_name(allocation.heap_id_mask,
						     allocation.flags);
			if (!heap_name)
				return -EOPNOTSUPP;
		}
		heap = dma_heap_find(heap_name);
		if (!heap)
			return -ENODEV;
		buffer = dma_heap_buffer_alloc(heap, allocation.len,
					       O_RDWR | O_CLOEXEC, 0);
		dma_heap_put(heap);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);
		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			dma_buf_put(buffer);
			return fd;
		}
		allocation.fd = fd;
		if (copy_to_user(user, &allocation, sizeof(allocation))) {
			put_unused_fd(fd);
			dma_buf_put(buffer);
			return -EFAULT;
		}
		fd_install(fd, buffer->file);
		return 0;
	default:
		/* libion probes the obsolete FREE ioctl: ENOTTY selects modern ABI. */
		return -ENOTTY;
	}
}

static const struct file_operations alioth_ion_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = alioth_ion_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
	.llseek = no_llseek,
};
static struct miscdevice alioth_ion_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ion",
	.fops = &alioth_ion_fops,
};
static int __init alioth_ion_init(void)
{
	return misc_register(&alioth_ion_device);
}
static void __exit alioth_ion_exit(void)
{
	misc_deregister(&alioth_ion_device);
}
module_init(alioth_ion_init);
module_exit(alioth_ion_exit);
MODULE_DESCRIPTION("Alioth ION heap compatibility");
MODULE_LICENSE("GPL");
