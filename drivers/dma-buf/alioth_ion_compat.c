// SPDX-License-Identifier: GPL-2.0-only
/* Modern ION ABI bridge for verified nonsecure alioth vendor heaps. */
#include <linux/compat.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <uapi/linux/ion.h>

#define ALIOTH_ION_CACHED 1

struct alioth_ion_heap {
	struct ion_heap_data info;
	const char *cached;
	const char *uncached;
};

static const struct alioth_ion_heap alioth_heaps[] = {
	{ { .name = "system", .type = ION_HEAP_TYPE_SYSTEM, .heap_id = 25 },
	  "qcom,system", "qcom,system-uncached" },
	{ { .name = "adsp", .type = ION_HEAP_TYPE_DMA, .heap_id = 22 },
	  "qcom,alioth-adsp", "qcom,alioth-adsp-uncached" },
	{ { .name = "user_contig", .type = ION_HEAP_TYPE_DMA, .heap_id = 26 },
	  "qcom,alioth-user-contig", "qcom,alioth-user-contig-uncached" },
};

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
	struct ion_heap_data info[ARRAY_SIZE(alioth_heaps)];
	const struct alioth_ion_heap *selected = NULL;
	unsigned int i, count = 0;
	struct dma_heap *heap;
	struct dma_buf *buffer;
	int fd;

	switch (cmd) {
	case ION_IOC_HEAP_QUERY:
		if (copy_from_user(&query, user, sizeof(query)))
			return -EFAULT;
		if (query.reserved0 || query.reserved1 || query.reserved2)
			return -EINVAL;
		for (i = 0; i < ARRAY_SIZE(alioth_heaps); i++)
			if (alioth_heap_available(&alioth_heaps[i]))
				info[count++] = alioth_heaps[i].info;
		if (query.heaps && query.cnt &&
		    copy_to_user(u64_to_user_ptr(query.heaps), info,
				 min(query.cnt, count) * sizeof(info[0])))
			return -EFAULT;
		query.cnt = count;
		return copy_to_user(user, &query, sizeof(query)) ? -EFAULT : 0;
	case ION_IOC_ALLOC:
		if (copy_from_user(&allocation, user, sizeof(allocation)))
			return -EFAULT;
		/* Never substitute ordinary memory for secure or carveout requests. */
		if (allocation.flags & ~ALIOTH_ION_CACHED || allocation.unused)
			return -EOPNOTSUPP;
		for (i = 0; i < ARRAY_SIZE(alioth_heaps); i++)
			if (allocation.heap_id_mask == BIT(alioth_heaps[i].info.heap_id))
				selected = &alioth_heaps[i];
		if (!selected)
			return -EOPNOTSUPP;
		if (!allocation.len ||
		    allocation.len > SIZE_MAX - PAGE_SIZE + 1)
			return -EINVAL;
		heap = dma_heap_find(allocation.flags & ALIOTH_ION_CACHED ?
				     selected->cached : selected->uncached);
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
MODULE_DESCRIPTION("Alioth nonsecure ION heap compatibility");
MODULE_LICENSE("GPL");
