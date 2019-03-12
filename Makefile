# SPDX-License-Identifier: GPL-2.0

.PHONY: modules modules_install clean test all

KVERSION := $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KVERSION)/build

all: modules test

test:
	$(MAKE) -C test

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

modules_install: modules
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
	$(MAKE) -C test clean
	@rm -f Module.symvers *.o .*.cmd *.mod.c *.ko
