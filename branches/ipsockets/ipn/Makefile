#
## Makefile for the IPN (Inter Process Networking) domain socket layer.
#
#

EXTRA_CFLAGS += -DIPN_STEALING

ifneq ($(KERNELRELEASE),)

	obj-m      += ipn.o

	ipn-objs   := af_ipn.o ipn_netdev.o ipn_chrdev.o ipn_msgbuf.o

else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

