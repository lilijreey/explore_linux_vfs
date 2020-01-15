#obj-m += myfs.o
obj-m += tcp_flowstat.o
#CFLAGS_myfs.o += -DDEBUG -std=gun99

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
