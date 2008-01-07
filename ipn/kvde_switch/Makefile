# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
#KERNELDIR = "/usr/src/experimental/linux-source-2.6.22-utrace-viewos"
#KERNELDIR = "/mnt/sorgenti/KernelStuff/kernels/linux-2.6.22.1/"
#KERNELDIR = "/extra/renzo/linux-2.6.24-rc5-ipn-curr"

ifneq ($(KERNELRELEASE),)
	kvde_switch-objs := kvde_switch_main.o 
	obj-m += kvde_switch.o 
	obj-m += ipn_hash.o 
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
