#!/bin/bash

i=0

while [ $i -lt 10000 ]
do
	strace -o >(cat >>datafile) -T mkdir temp;
	strace -o >(cat >>datafile) -T cat temp;
	strace -o >(cat >>datafile) -T ls -la;
	strace -o >(cat >>datafile) -T touch temp2;
	strace -o >(cat >>datafile) -T rm temp2;
	strace -o >(cat >>datafile) -T mv temp/ temp/;
	strace -o >(cat >>datafile) -T rmdir temp;
	i=$(( $i + 1 ))
done
