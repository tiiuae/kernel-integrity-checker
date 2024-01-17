export CC=aarch64-linux-gnu-gcc
export ARCH=arm64

CROSS_COMPILE := aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
SUBDIRS := mbedtls aarch64 aarch64/stdlib

OBJCOPY := $(CROSS_COMPILE)objcopy
MBEDTLS_CFLAGS := '-O2 -DMBEDTLS_USER_CONFIG_FILE=\"$(PWD)/mbedconfig.h\"'
LDFLAGS := -static -T ld.out -Lmbedtls/library -L./aarch64 -L./aarch64/stdlib -L/usr/lib/gcc-cross/aarch64-linux-gnu/11 --nostdlib
LDLIBS :=  -lgcc -lmbedcrypto -lstdlib -larch -lgcc
vecho = @echo
DIR := $(shell pwd)

OBJS := ic_loader.o heap.o
CFLAGS := -march=armv8-a -Imbedtls/include -Iaarch64 -g -ffreestanding
PROG = ic_loader

GUEST_IMAGE_DIR ?= .
KEYS_DIR := keys
SCRIPTS := scripts

IMAGE ?= Image
CERT_REQ_FILE ?= cert_req.crt
CERT_FILE ?= cert.crt
PRIV_KEY ?= $(KEYS_DIR)/sign_priv.pem
PUB_KEY ?= $(KEYS_DIR)/sign_pub.txt


GUEST_ID ?= "no"
DTB_ADDR ?= 0x8fc00000
DTB_FILE ?= guest.dtb
TMP_FILE := $(shell mktemp)


$(PROG).hex: $(PROG).bin
	cat $(PROG).bin | hexdump -ve '"0x%08X,"' > $(PROG).hex

$(PROG).bin: $(PROG)
	$(OBJCOPY) -O binary $(PROG) $(PROG).bin
libs:
	make CFLAGS=$(MBEDTLS_CFLAGS) -C mbedtls lib
	make -C aarch64
	make -C aarch64/stdlib

$(PROG): $(OBJS) | libs
	$(vecho) [LD] $@
	$(LD) $(OBJS) $(LDFLAGS) -o $(PROG) $(LDLIBS) -static

%.o: %.c root_pubkey.h
	$(vecho) [CC] $@
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(CERT_FILE): | $(PUB_KEY)
	$(SCRIPTS)/create_cert_req.sh  \
		-s $(KEYS_DIR)/sign_pub.txt \
		-o $(CERT_REQ_FILE)

	# send certificate creation request to CA
	make -f Makefile.customer -C dummy-CA \
		CERT_FILE=$(DIR)/$(CERT_FILE) \
		CERT_REQ_FILE=$(DIR)/$(CERT_REQ_FILE) \
		sign_guest_cert

root_pubkey.h:
	make -f Makefile.customer -C dummy-CA ROOT_PUBKEY=$(TMP_FILE)  get_rootkey
	openssl ec -in $(TMP_FILE) -pubin -noout -text | \
		$(SCRIPTS)/convert_to_h.py pub root_pubkey > root_pubkey.h
	rm $(TMP_FILE)

sign_guest: | $(CERT_FILE) $(PRIV_KEY)
	$(SCRIPTS)/sign_guest_kernel.sh \
		-p "$(PRIV_KEY)" \
		-k "$(IMAGE)" \
		-o "$(GUEST_IMAGE_DIR)"/$(notdir ${IMAGE}).sign \
		-D "${DTB_FILE}" -d "$(DTB_ADDR)" \
		-g "$(GUEST_ID)" \
		-c "$(CERT_FILE)"

$(PRIV_KEY) $(PUB_KEY):
	make -C $(KEYS_DIR) all



clean:
	rm -f $(OBJS) root_pubkey.h $(PROG) $(PROG).hex $(PROG).bin
	make -C mbedtls clean
	make -C aarch64 clean
	make -C aarch64/stdlib clean

distclean: clean
	rm -f cert.crt $(CERT_REQ_FILE) $(CERT_FILE)
	make -C $(KEYS_DIR) clean

.PHONY: libs clean keys distclean
