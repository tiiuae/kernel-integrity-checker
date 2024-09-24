
export ARCH=arm64
export BUILDTOOLS := $(PWD)/../pkvm-aarch64/buildtools
export CROSS_COMPILE := $(BUILDTOOLS)/usr/bin/aarch64-linux-gnu-
export CC := $(CROSS_COMPILE)gcc

LD := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy

COMMON_CFLAGS := -march=armv8-a -g -ffreestanding --sysroot=$(BUILDTOOLS) --no-sysroot-suffix

MBEDTLS_CFLAGS := '-O2 -DMBEDTLS_USER_CONFIG_FILE=\"$(PWD)/mbedconfig.h\" $(COMMON_CFLAGS)'
LDFLAGS := -static -T ld.out -Lmbedtls/library -L./aarch64 -L./aarch64/stdlib -L./libfdt -L$(BUILDTOOLS)/usr/lib/gcc/aarch64-linux-gnu/9.5.0/
LDLIBS :=  -lmbedcrypto -lfdt -lstdlib -larch -lgcc 
vecho = @echo
DIR := $(shell pwd)

OBJS := ic_loader.o heap.o
CFLAGS := $(COMMON_CFLAGS) -Imbedtls/include -Iaarch64 -Ilibfdt 
PROG := ic_loader

GUEST_IMAGE_DIR ?= .
KEYS_DIR := keys
SCRIPTS := scripts

IMAGE ?= Image
CERT_REQ_FILE ?= cert_req.crt
CERT_FILE ?= cert.crt
PRIV_KEY ?= $(KEYS_DIR)/sign_priv.pem
PUB_KEY ?= $(KEYS_DIR)/sign_pub.txt
GUEST_ID ?= "no"

TMP_FILE := $(shell mktemp)

$(PROG).hex: $(PROG).bin
	cat $(PROG).bin | hexdump -ve '"0x%08X,"' > $(PROG).hex

$(PROG).bin: $(PROG)
	$(OBJCOPY) -O binary $(PROG) $(PROG).bin
libs:
	make CFLAGS=$(MBEDTLS_CFLAGS) -C mbedtls lib
	make CFLAGS='$(COMMON_CFLAGS)' -C aarch64
	make CFLAGS='$(COMMON_CFLAGS)' -C aarch64/stdlib
	make CFLAGS='$(COMMON_CFLAGS)' -C libfdt

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
	make -f Makefile.customer -C dummy-CA ROOT_PUBKEY=$(TMP_FILE) get_rootkey
	openssl ec -in $(TMP_FILE) -pubin -noout -text | \
		$(SCRIPTS)/convert_to_h.py pub root_pubkey > root_pubkey.h
	rm $(TMP_FILE)

sign_guest: | $(CERT_FILE) $(PRIV_KEY)
	$(SCRIPTS)/sign_guest_kernel.sh \
		-p "$(PRIV_KEY)" \
		-k "$(IMAGE)" \
		-o "$(GUEST_IMAGE_DIR)"/$(notdir ${IMAGE}).sign \
		-D "${DTB_FILE}" \
		-g "$(GUEST_ID)" \
		-c "$(CERT_FILE)"
		@if [ -z "${DTB_FILE}" ]; then\
			echo "If you want to use signed dtb-file use:"; \
			echo "    make sign_guest DTB_FILE=<dtb-file>";\
 		fi

$(PRIV_KEY) $(PUB_KEY):
	make -C $(KEYS_DIR) all

clean:
	rm -f $(OBJS) root_pubkey.h $(PROG) $(PROG).hex $(PROG).bin
	make -C mbedtls clean
	make -C aarch64 clean
	make -C aarch64/stdlib clean
	make -C libfdt clean

distclean: clean
	rm -f cert.crt $(CERT_REQ_FILE) $(CERT_FILE)
	make -C $(KEYS_DIR) clean

.PHONY: libs clean keys distclean
