obj-m += sbi_fuzz.o

KDIR ?= $(HOME)/projects/srcs/linux

ARCH ?= riscv
CROSS_COMPILE ?= riscv64-linux-gnu-

all:
	make -C $(KDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) V=1 modules

clean:
	make -C $(KDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) clean


