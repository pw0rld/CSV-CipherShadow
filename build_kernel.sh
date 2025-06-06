yes "" | make oldconfig
./scripts/config --enable CONFIG_CRYPTO_DEV_CCP
./scripts/config --enable CONFIG_AMD_MEM_ENCRYPT
./scripts/config --enable CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT
./scripts/config --enable CONFIG_HYDCU_FIXUP_HEADER
./scripts/config --enable CONFIG_VFIO_MDEV
./scripts/config --enable CONFIG_VFIO_MDEV_DEVICE
./scripts/config --enable CONFIG_VFIO
./scripts/config --enable CONFIG_VFIO_IOMMU_TYPE1
./scripts/config --enable CONFIG_VFIO_PCI
./scripts/config --enable CONFIG_HYMCCP
./scripts/config -m CONFIG_BLK_DEV_NBD
./scripts/config -m CONFIG_CRYPTO_DEV_HCT
./scripts/config --disable CONFIG_DEBUG_INFO
./scripts/config --enable  CONFIG_CGROUPS
./scripts/config --enable  CONFIG_CGROUP_CPUACCT
./scripts/config --enable  CONFIG_XEN_PV
./scripts/config --enable  CONFIG_HYGON_CSV
./scripts/config --enable  CONFIG_CMA
./scripts/config --enable  CONFIG_HUGETLBFS
./scripts/config --enable  CONFIG_LIBCRC32C
./scripts/config --disable CONFIG_X86_CPU_RESCTRL
make olddefconfig
make -j$(getconf _NPROCESSORS_ONLN) LOCALVERSION="-csv"
make modules_install
make install
