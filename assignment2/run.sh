#!/bin/bash

kill -s SIGTERM $(ps -e | grep deamon_interpos | awk {'print $1'})

rmmod interposer_v1

make clean

make

insmod interposer_v1.ko

echo "50" > /proc/sysmon_uid

echo "1" > /proc/sysmon_toggle

echo "0" > infile.txt

./deamon_interpos.o infile.txt outfile.txt
