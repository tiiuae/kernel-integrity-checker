vecho = @echo
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar

LIBNAME := libstdlib.a
C_SOURCES := sanity.c string.c memset_chk.c memcpy_chk.c abort.c exit.c explicit_bzero.c
C_SOURCES += printf.c putchar.c puts.c sscanf.c subr_prf.c
AS_SOURCES = strcmp.S strlen.S memmove.S memcpy.S memset.S memcmp.S
CFLAGS := -march=armv8-a -ffreestanding -I../

AS_OBJ := $(patsubst $(notdir %.S),%.o,$(notdir $(AS_SOURCES)))
C_OBJ := $(patsubst %.c,%.o,$(notdir $(C_SOURCES)))
OBJS := $(C_OBJ) $(AS_OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(LIBNAME): $(OBJS)
	$(AR) rcsTP $(LIBNAME) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBNAME)
