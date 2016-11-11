obj-m += firewall.o

INC_PATH=/usr/include/linux
ccflags-y=-I$(INC_PATH)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load:
	sudo insmod firewall.ko

unload:
	sudo rmmod firewall

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
