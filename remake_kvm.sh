#/bin/sh
cores=$(nproc --all)
EXTRAVERSION=""
make clean M=arch/x86/kvm/ &&
make -j $cores scripts &&
make -j $cores prepare &&
make -j $cores modules_prepare &&
cp /usr/src/linux-headers-`uname -r`/Module.symvers arch/x86/kvm/Module.symvers  &&
cp /usr/src/linux-headers-`uname -r`/Module.symvers Module.symvers  &&
cp "/boot/System.map-$(uname -r)" . 
cp "/boot/System.map-$(uname -r)" arch/x86/kvm/
touch .scmversion &&
make -j $cores modules M=arch/x86/kvm/ LOCALVERSION= &&
make modules_install M=arch/x86/kvm/ LOCALVERSION= &&

echo "Unload old modules" 
modprobe -r kvm_amd kvm 
cp ./arch/x86/kvm/kvm.ko "/lib/modules/$(uname -r)/kernel/arch/x86/kvm/"
cp ./arch/x86/kvm/kvm-amd.ko "/lib/modules/$(uname -r)/kernel/arch/x86/kvm/"
echo "Load new modules"
modprobe kvm 
modprobe kvm-amd sev=1
