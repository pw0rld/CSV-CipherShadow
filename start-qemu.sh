#!/bin/bash
#path to ovmf binary (with grub included)
OVMF_PATH="OVMF_CODE.fd"
DH_CERT_FILE="attestation/dh_cert.base64"
SESSION_FILE="attestation/session.base64"
DISK_IMAGE="vm.qcow2"
SECRET_HEADER_FILE="attestation/secret_header.bin.b64"
SECRET_FILE="attestation/secret.bin.b64"


SECRET_MODE=0
while getopts "sc" opt; do
  case $opt in
    s)
      SECRET_MODE=1
      ;;
    c)
      SECRET_MODE=2
      ;;
    *)
      ;;
  esac
done

if [ $SECRET_MODE -eq 0 ]; then
    # Normal vm start
    echo "Starting normal vm"
    taskset -c 0 qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 1 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda "$DISK_IMAGE" \
    -net user,hostfwd=tcp:127.0.0.1:2221-0.0.0.0:22  \
    -net nic -nographic \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5\
    # -monitor telnet:127.0.0.1:5551,server,nowait   \
    # -qmp tcp::5551,server,nowait   \
    -machine memory-encryption=sev0

elif [ $SECRET_MODE -eq 2 ]; then
    # CSV start
    echo "Starting CSV vm"
    # 0x1 is the policy for CSV1
    # 0x5 is the policy for CSV2
    # 0x45 is the policy for CSV3
   taskset -c 0  qemu-system-x86_64  \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda "$DISK_IMAGE" -net nic \
    -machine memory-encryption=sev0 \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5  \
    -nographic -monitor pty -monitor unix:monitor,server,nowait \
    -net user,hostfwd=tcp:127.0.0.1:2221-0.0.0.0:22   \
    # -monitor telnet:127.0.0.1:5551,server,nowait   \
    # -qmp tcp:127.0.0.1:5551,server,nowait \
    -object memory-backend-file,id=ivshmem,share=on,mem-path=/dev/shm/ivshmem,size=4096 -device ivshmem-plain,memdev=ivshmem
else
    # Insert secret injection
    echo "Starting secret injection vm"
    taskset -c 0 qemu-system-x86_64  \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda "$DISK_IMAGE" -net nic \
    -machine memory-encryption=sev0 \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5,session-file="$SESSION_FILE",dh-cert-file="$DH_CERT_FILE",secret-header-file="$SECRET_HEADER_FILE",secret-file="$SECRET_FILE"  \
    -nographic -monitor pty -monitor unix:monitor,server,nowait \
    -net user,hostfwd=tcp:127.0.0.1:2221-0.0.0.0:22   \
    # -monitor telnet:127.0.0.1:5551,server,nowait   \
    # -qmp tcp:127.0.0.1:5551,server,nowait \
    -object memory-backend-file,id=ivshmem,share=on,mem-path=/dev/shm/ivshmem,size=4096 -device ivshmem-plain,memdev=ivshmem
fi

