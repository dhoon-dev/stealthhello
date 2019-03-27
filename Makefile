obj-m += stealthhello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

debug:
	EXTRA_CFLAGS=-DDEBUG make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
