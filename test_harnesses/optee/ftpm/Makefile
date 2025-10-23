target = ftpm_fuzz

CC = gcc
CFALGS = -Wall -g -I.

objs = main.o \
	common.o \
	ftpm_ta.o \
	ftpm_nv.o \
	ftpm_tpm2_quote.o

$(target): $(objs)
	$(CC) $(CFALGS) $(objs) -o $(target) -lteec -ltss2-mu -ltss2-sys -ltss2-tctildr -ltss2-tcti-device

.c.o:
	$(CC) $(CFALGS) -c $<

clean:
	rm -fr $(target) ${objs}

.PHONY: $(target)
