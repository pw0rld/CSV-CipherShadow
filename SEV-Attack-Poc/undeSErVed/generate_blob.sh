#!/bin/bash

hag_path="../hag"
# ovmf_path="/home/pw0rld/Desktop/hygon-edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd"
ovmf_path="OVMF_CODE.fd"
#  * csv guest policy, 4 bytes
#  *
#  * @nodebug     - disallow debug to guest
#  * @noks        - disallow sharing keys with other guests
#  * @csv2        - guest is csv2
#  * @nosend      - disallow sending the guest to another platform
#  * @domain      - disallow sending the guest to another platform of another domain
#  * @csv         - guest is csv.
#  * @csv3        - guest is csv3
#  * @asid_reuse  - multiple guest can reuse the same asid
#  * @hsk_version - HSK version
#  * @cek_version - CEK version

build_id=`sudo $hag_path csv platform_status  |grep "build id"`
echo ${build_id##*:}
build_id=`echo ${build_id##*:}`
$hag_path csv pdh_cert_export
$hag_path csv generate_policy -nodebug -es
$hag_path csv generate_launch_blob -build $build_id -bios $ovmf_path -verbose
tr -d '\n' < guest_owner_dh.cert > dh_cert.base64
tr -d '\n' < launch_blob.bin > session.base64

./pack-secret.py --passwd abc --build $build_id
base64 -w 0 secret.bin > secret.bin.b64
base64 -w 0 secret_header.bin > secret_header.bin.b64