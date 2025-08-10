for cpu in /sys/devices/system/cpu/cpu*; do
    n=$(basename $cpu | sed 's/cpu//')
    if [[ $n -gt 1 ]]; then
        echo 0 | sudo tee $cpu/online
    fi
done
