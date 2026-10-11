# Experimental alioth GPU binding

`xiaomi,regulator-gdsc` on qcom,sm8250-gpucc opts into clocks/resets/voltage votes without registering CX/GX genpd domains. The DT must omit #power-domain-cells, replace every GPUCC domain consumer, and provide the separate qcom,gdsc regulators for KGSL. Those regulators are the sole owners of the GDSC controls. Other boards retain native genpd behavior.

The alioth node uses donor v2 speed bins and the v2.1 chip ID. Each nonzero level adds the matching donor OPP voltage corner required by release KGSL; DDR7/8 tables retain donor bandwidth arithmetic and indices. Bootloader DDR metadata must select the correct table. Clocks and interconnect use native symbolic bindings. GMU uses the release direct IOMMU binding, and its unchanged native zap-shader reservation remains subject to stock firmware handoff validation.
