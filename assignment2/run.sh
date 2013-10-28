#!/bin/bash

rmmod interposer_v1

make clean

make

insmod interposer_v1.ko

echo "500" > /proc/sysmon_uid

echo "1" > /proc/sysmon_toggle
