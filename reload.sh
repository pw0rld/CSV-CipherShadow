#!/bin/bash

sudo rmmod kvm_amd kvm
sudo modprobe kvm
sudo modprobe kvm_amd