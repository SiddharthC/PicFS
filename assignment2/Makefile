obj-m += interposer_v1.o

all:
	gcc -ggdb deamon_interposer.c -o deamon_interpos.o
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm deamon_interpos.o
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
