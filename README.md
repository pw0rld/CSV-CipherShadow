# CSV-CipherShadow

This repository contains the experimental code and case studies presented in our paper:

"Shadows in Cipher Spaces: Exploiting Tweak Repetition in Hardware Memory Encryption" (USENIX Security'25)

## Overview

We conducted an in-depth investigation of Hygon CSV technology, a novel Trusted Execution Environment (TEE) implementation. CSV employs an innovative memory encryption approach based on key derivation, where encryption keys are dynamically generated based on physical addresses. Our research revealed the Shadows attack, which exploits the inconsistency between encryption granularity and tweak granularity in the system.

## Platform Requirements

Our experiments were conducted on the following platforms:
- Hygon C86 7390 32-core Processor (CSV v2)
- Hygon C86 5285 16-core Processor (CSV v1)
- Hygon C86 7490 32-core Processor (CSV v3)

## Setup Instructions

### 1. QEMU Setup
```bash
git clone https://gitee.com/anolis/hygon-qemu.git && cd hygon-qemu/
sed -i 's/bpf_program__set_socket_filter(/bpf_program__attach(/g' ./ebpf/ebpf_rss.c
./configure --target-list=x86_64-softmmu --enable-kvm --enable-virtfs \
    --enable-cmd-batch --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make CFLAGS="-Werror=nested-externs -Werror=implicit-function-declaration" -j$(nproc)
```

Verify the build:
```bash
./build/qemu-system-x86_64 --version
# Expected output: QEMU emulator version 6.2.0
```

### 2. Kernel Configuration
```bash
git clone https://gitee.com/openeuler/kernel.git && cd kernel
git checkout -f OLK-6.6
yes "" | make oldconfig

# Enable required configurations
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
./scripts/config --enable CONFIG_CGROUPS
./scripts/config --enable CONFIG_CGROUP_CPUACCT
./scripts/config --enable CONFIG_XEN_PV
./scripts/config --enable CONFIG_HYGON_CSV
./scripts/config --enable CONFIG_CMA
./scripts/config --enable CONFIG_HUGETLBFS
./scripts/config --enable CONFIG_LIBCRC32C
./scripts/config --disable CONFIG_X86_CPU_RESCTRL

make olddefconfig
make -j$(getconf _NPROCESSORS_ONLN) LOCALVERSION="-csv"
make modules_install
make install
reboot
```

### 3. OVMF Setup
```bash
git clone https://gitee.com/anolis/hygon-edk2.git && cd hygon-edk2
git submodule update --init
source edksetup.sh
make -j$(getconf _NPROCESSORS_ONLN) -C BaseTools/
nice build -v --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT=TRUE -n 32 -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
nice build -q --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT=TRUE -n $(getconf _NPROCESSORS_ONLN) -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
```

### 4. CSV Status Verification
Using the Hygon proprietary tool 'Hag' to verify CSV status:
```bash
hag csv platform_status
```

Expected output should show:
- CSV versions supported
- Platform state
- Security status
- Guest count

## Victim System Setup

1. Execute the provided `make_vm_img.sh` script
2. For CSV v2 and v3, install the modified VM kernel:
```bash
scp -P 2221 -r guest_kernel.zip root@127.0.0.1:/tmp
ssh root@127.0.0.1 -p 2221
cd /tmp && unzip guest_kernel.zip && cd x86_64
rpm -ivh *.rpm --force --nodeps
```

## VM Launch Commands

### CSV v1
```bash
qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 1 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=OVMF_code.fd,readonly=on \
    -hda vm0.qcow2 \
    -net user,hostfwd=tcp:127.0.0.1:2221-0.0.0.0:22 \
    -net nic -nographic \
    -object sev-guest,id=sev0,policy=0x1,cbitpos=47,reduced-phys-bits=5 \
    -monitor telnet:127.0.0.1:5551,server,nowait \
    -qmp tcp::5551,server,nowait \
    -machine memory-encryption=sev0
```

### CSV v2/v3
```bash
qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 1 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda vm0.qcow2 \
    -net user,hostfwd=tcp:127.0.0.1:2221-0.0.0.0:22 \
    -net nic -nographic \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5 \
    -monitor telnet:127.0.0.1:5551,server,nowait \
    -qmp tcp::5551,server,nowait \
    -machine memory-encryption=sev0
```

## Contributing

We welcome contributions from the security community! Please review our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program.

## Contact

[Your contact information]
