#!/usr/bin/python3
##
# Python script to package a secret disk password for CSV VM
##
import sys
import os
import base64
import hmac
import hashlib
from argparse import ArgumentParser
from uuid import UUID
import qmp


if __name__ == "__main__":
    parser = ArgumentParser(description='Package secret for CSV')
    parser.add_argument('--passwd',
                        help='Disk Password',
                        required=True)
    parser.add_argument('--build',
                        help='Firmware Build Id',
                        required=True)
    args = parser.parse_args()

    disk_secret = args.passwd
    build_id = args.build
    print('\nFW Build Id is: ', build_id)
    print('\nSecret is: ', disk_secret)

    # total length of table: header plus one entry with trailing \0
    l = 16 + 4 + 16 + 4 + len(disk_secret) + 1
    # SEV-ES requires rounding to 16
    l = (l + 15) & ~15
    secret = bytearray(l);
    secret[0:16] = UUID('{1e74f542-71dd-4d66-963e-ef4287ff173b}').bytes_le
    secret[16:20] = len(secret).to_bytes(4, byteorder='little')
    print('\t1st len: ', len(secret))
    secret[20:36] = UUID('{736869e5-84f0-4973-92ec-06879ce3da0b}').bytes_le
    secret[36:40] = (16 + 4 + len(disk_secret) + 1).to_bytes(4, byteorder='little')
    print('\t2nd len: ', 16 + 4 + len(disk_secret) + 1)
    secret[40:40+len(disk_secret)] = disk_secret.encode()

    # save to file secret.txt as hag expected
    print('Save secret to secret.txt')
    fh=open("secret.txt", 'wb')
    fh.write(secret)
    fh.close()

    print('Package secret data used by qemu')
    cmd = "sudo hag csv package_secret -build {} -flag 0x2".format(build_id)
    os.system(cmd)

    print('\nSecret Package Succeed !')
