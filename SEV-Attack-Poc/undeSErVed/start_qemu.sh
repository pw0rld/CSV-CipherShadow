#!/bin/bash
#path to ovmf binary (with grub included)
OVMF_PATH="OVMF_CODE.fd"
DH_CERT_FILE="dh_cert.base64"
SESSION_FILE="session.base64"
DISK_IMAGE="vm0.qcow2"
SECRET_HEADER_FILE="secret_header.bin.b64"
SECRET_FILE="secret.bin.b64"


SECRET_MODE=0
while getopts "s" opt; do
  case $opt in
    s)
      SECRET_MODE=1
      ;;
    *)
      ;;
  esac
done

if [ $SECRET_MODE -ne 1 ]; then

    # Normal start
    qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 1 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda "$DISK_IMAGE" \
    -net user,hostfwd=tcp:127.0.0.1:2222-0.0.0.0:22  \
    -net nic -nographic \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5\
    -monitor telnet:127.0.0.1:5555,server,nowait   \
    -qmp tcp::5550,server,nowait   \
    -machine memory-encryption=sev0

else
    # Insert secret injection
    qemu-system-x86_64  \
    -enable-kvm \
    -cpu host \
    -smp 4 \
    -m 4096M,slots=5,maxmem=30G -no-reboot \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_PATH",readonly=on \
    -hda "$DISK_IMAGE" -net nic \
    -machine memory-encryption=sev0 \
    -object sev-guest,id=sev0,policy=0x5,cbitpos=47,reduced-phys-bits=5,session-file="$SESSION_FILE",dh-cert-file="$DH_CERT_FILE",secret-header-file="$SECRET_HEADER_FILE",secret-file="$SECRET_FILE"  \
    -nographic -monitor pty -monitor unix:monitor,server,nowait \
    -net user,hostfwd=tcp:127.0.0.1:2222-0.0.0.0:22   \
    -monitor telnet:127.0.0.1:5555,server,nowait   \
    -qmp tcp:127.0.0.1:5550,server,nowait 
    # -S


fi
