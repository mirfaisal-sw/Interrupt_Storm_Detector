
obj-m += hr-timer.o

ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

KDIR = /home/mir/My_Workspace/TMDS64EVM/TMDS64EVM_SDK_Install/SDK_Install_Path/board-support/ti-linux-kernel-6.1.46+gitAUTOINC+247b2535b2-g247b2535b2 
 
all:
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -C $(KDIR)  M=$(shell pwd) modules
 
clean:
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -C $(KDIR)  M=$(shell pwd) clean
