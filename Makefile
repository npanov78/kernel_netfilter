obj-m += filter.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -rf .* filter.mod* filter.o Mod* mod*
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
