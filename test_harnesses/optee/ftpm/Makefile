target=ftpm_nv_test

$(target):
	gcc -Wall $(target).c -o $(target) -lteec -ltss2-mu -ltss2-sys -ltss2-tctildr -ltss2-tcti-device

clean:
	rm -fr $(target)

.PHONY: $(target)
