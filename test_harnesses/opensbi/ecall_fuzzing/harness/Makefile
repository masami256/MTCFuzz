CROSS_COMPILE ?= riscv64-linux-gnu-

target = harness

objs = main.o 

all: $(objs)
	$(CROSS_COMPILE)gcc $(objs) -o $(target)

.c.o:
	$(CROSS_COMPILE)gcc -c -g -I./ $<


clean:
	rm -f $(target) *.o

