# Statically links crackpin for Android / ARM environment.
# Requires cross-compiled PolarSSL library "libpolarssl.a"
# Contact: tilo.mueller@informatik.uni-erlangen.de

 NDK := /usr/src/android/android-ndk-r8b/
PATH := ${PATH}:${NDK}/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/
ARCH := arm
CROSS:= arm-linux-androideabi-

CC = $(CROSS)gcc 
LD = $(CROSS)ld
AR = $(CROSS)ar 

CFLAGS	+= -I./include -D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement -O
LDFLAGS	+= -L./library -lpolarssl
CFLAGS  += -I${NDK}/platforms/android-4/arch-arm/usr/include/ -nostdlib
LDFLAGS += -nostdlib -static -lm -lc -lstdc++ -lgcc -L${NDK}/platforms/android-4/arch-arm/usr/lib/ -Wl,--entry=main,-rpath-link=${NDK}/platforms/android-4/arch-arm/usr/lib/

crackpin: crackpin.c
	$(CC) $(CFLAGS) $(OFLAGS) crackpin.c $(LDFLAGS) -o $@

clean:
	rm crackpin
