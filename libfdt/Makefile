vecho = @echo
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar

LIBNAME := libfdt.a
C_SOURCES := fdt.c fdt_ro.c
CFLAGS := -march=armv8-a -ffreestanding  --sysroot=$(BUILDTOOLS) --no-sysroot-suffix

AS_OBJ := $(patsubst $(notdir %.S),%.o,$(notdir $(AS_SOURCES)))
C_OBJ := $(patsubst %.c,%.o,$(notdir $(C_SOURCES)))
OBJS := $(C_OBJ) $(AS_OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(LIBNAME): $(OBJS)
	$(AR) rcsTP $(LIBNAME) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBNAME)
