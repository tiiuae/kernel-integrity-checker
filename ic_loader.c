// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "mbedtls/build_info.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "platform.h"
#include "kic_defs.h"
#include "heap.h"
#include "root_pubkey.h"
#include  "libfdt/libfdt.h"
extern const uint64_t *_start;
extern const uint64_t *_stack_top;

void __flush_dcache_area(void *addr, size_t sz);
int mmio_guard_map(uint64_t *info);
int mmio_guard_unmap(uint64_t *info);

__attribute__((__section__(".heap"))) uint32_t hyp_malloc_pool[1024 * 4];
__attribute__((__section__(".stack"))) uint32_t stack[1024 * 32];

#define CHECKRES(x, expected, err_handler) \
	do {                               \
		if ((x) != (expected)) {   \
			goto err_handler;  \
		}                          \
	} while (0)

int is_allowed_memory(uint64_t begin, size_t size)
{
	uint64_t end = begin + size - 1;
	const uintptr_t disallowed_begin = (uintptr_t) &_start;
	const uintptr_t disallowed_end = (uintptr_t) &_stack_top;

	return (begin < disallowed_begin && end < disallowed_begin) ||
		(begin > disallowed_end && end > disallowed_end);
}

void hexdump(const char *c, int len)
{
	while (len--) {
		printf("%02x  ",*(c++));
	}
	printf("\n");
}

int do_ecdsa(const uint8_t *sign, const uint8_t *hash,
	     const uint8_t *pub, size_t pub_size)
{
	mbedtls_ecdsa_context ctx;
	mbedtls_ecp_group grp;
	mbedtls_ecp_keypair key;
	int err = KIC_FAILED;
	uint32_t sign_len;
	int ret;

	if (!sign || !hash || sign[0] != 0x30 || sign[2] != 0x02) {
		return KIC_FAILED;
	}

	sign_len = sign[1] + 2;
	mbedtls_ecdsa_init(&ctx);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_keypair_init(&key);
	mbedtls_ecp_point_init(&key.private_Q);

	ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_point_read_binary(&grp, &key.private_Q, pub, pub_size);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_group_copy(&key.private_grp, &grp);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecdsa_from_keypair(&ctx, &key);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_check_pubkey(&grp, &ctx.private_Q);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecdsa_read_signature(&ctx, hash, 32, sign, sign_len);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	err = KIC_PASSED;

err_handler:
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_keypair_free(&key);
	mbedtls_ecdsa_free(&ctx);
	return err;
}

int calc_hash(void *hash, void *start, size_t len)
{
	mbedtls_sha256_context ctx;
	int ret = mbedtls_sha256_starts(&ctx, 0);

	if (ret != MBEDTLS_EXIT_SUCCESS) {
		printf("mbedtls_sha256_starts_ret %d", ret);
		return KIC_FAILED;
	}

	ret = mbedtls_sha256_update(&ctx, start, len);
	if (ret != MBEDTLS_EXIT_SUCCESS) {
		printf("mbedtls_sha256_update_ret %d", ret);
		return KIC_FAILED;
	}

	ret = mbedtls_sha256_finish(&ctx, hash);
	if (ret != MBEDTLS_EXIT_SUCCESS) {
		printf("mbedtls_sha256_finish_ret %d", ret);
		return KIC_FAILED;
	}
	return KIC_PASSED;
}

int image_check_init(gad_t *gad)
{
	uint8_t hash[32];
	int ret;
	int i;

	if (gad->magic != GAD_MAGIC) {
		printf("No signature magic\n");
		return KIC_FAILED;
	}
	if (gad->version != GAD_VERSION) {
		printf("Incorrect GAD version %x != %x\n",
			gad->version, GAD_VERSION);
		return KIC_FAILED;
	}
	/* Check guest certificate */
	ret = calc_hash(hash, &gad->cert, offsetof(guest_cert_t, signature));

	if (ret != MBEDTLS_EXIT_SUCCESS)	{
		printf("mbedtls_sha256_update_ret %d", ret);
		return KIC_FAILED;
	}

	if ((do_ecdsa((void *)gad->cert.signature, hash, root_pubkey,
		     sizeof(root_pubkey))) != KIC_PASSED) {
		printf("Certificate fail\n");
		return KIC_FAILED;
	}
	printf("Certificate OK\n");

	/* Check guest authenticated data */
	ret = calc_hash(hash, gad, offsetof(gad_t, signature));
	if (ret != MBEDTLS_EXIT_SUCCESS) {
		printf("mbedtls_sha256_update_ret %d", ret);
		return KIC_FAILED;
	}

	if ((do_ecdsa((void *)gad->signature, hash, gad->cert.sign_key.key,
		     gad->cert.sign_key.size)) != KIC_PASSED) {
		printf("signatuire fail\n");
		return KIC_FAILED;
	}
	printf("Signature OK\n");

	return 0;
}

int check_guest_image(kic_image_t *image, void *load_addr)
{
	uint8_t hash[32];
	int i;
	int ret;

	ret = calc_hash(hash, load_addr, image->size);
	if (ret != MBEDTLS_EXIT_SUCCESS) {
		return KIC_FAILED;
	}

	if (!memcmp(hash, image->hash, 32))
		return KIC_PASSED;

	return KIC_FAILED;
}
char *get_image_name(uint32_t magic)
{
	char *p = "Error";

	switch (magic) {
	case KERNEL_MAGIC:
		p = "Kernel";
		break;
	case DTB_MAGIC:
		p = "Device tree";
		break;
	default:
		p = 0;
	}

	return p;
}

void ic_loader(uint64_t *fdt, uint64_t *image_addr)
{
	uint8_t *name;
	kic_image_t *img;
	int ret;
	int i;
	gad_t gad;
	uint32_t len;
	void *laddr[KIC_IMAGE_COUNT];
	int offset;
	const struct fdt_property *prop;
	int kernel_check = 0;

	ret = mmio_guard_map(0);
	printf("Integrity check loader started\n");

	/* Get the address of the image from the device tree generated by crosvm */
	offset = fdt_path_offset((void *) *fdt, "/config");
	prop = fdt_get_property((void *) *fdt, offset, "kernel-address", &len);
	if (len != sizeof(uint32_t)) {
		printf("Illegal size\n");
		abort();
	}
	*image_addr = (uint64_t) __builtin_bswap32(*prop->data);

	set_heap(hyp_malloc_pool, sizeof(hyp_malloc_pool));
	memcpy(&gad, (void *) *image_addr, sizeof(gad));
	// TODO: Add device tree checks  if needed
	if (image_check_init(&gad))
		abort();

	for (i = 0; i < KIC_IMAGE_COUNT; i++) {
		img = &gad.images[i];

		if (img->magic) {
			len = ROUND_UP(img->size, sizeof(uint64_t));
			if ((len == 0) || (len > KIC_MAX_IMAGE_SIZE)) {
				printf("illegal length\n");
				abort();
			}

			name = get_image_name(img->magic);
			if (!name) {
				printf("Unknown magic\n");
				abort();
			}

			if (img->magic == KERNEL_MAGIC) {
				laddr[i] = (void *)  *image_addr;
			} else	if (img->magic == DTB_MAGIC) {
				/* If the guest authenticated data contains a device tree
				 * use it instead of the device tree generated by crosvm
				 */
				laddr[i] = (void *) *fdt;
			} else
				laddr[i] = img->load_addr;

			/* do not overwrite ic-loader code/data */
			if (is_allowed_memory((uint64_t)laddr[i], len)) {
				printf("copy '%s image' %d bytes from 0x%llx to 0x%llx\n",
					name,
					len,
					((uint8_t *) *image_addr) + img->offset,
					laddr[i]);
					memmove(laddr[i], ((uint8_t *) *image_addr) + img->offset, len);
					__flush_dcache_area(laddr[i], len);
			} else {
				printf("Not allowed address %d %llx\n", i, laddr[i]);
				abort();
			}
		} else
			break;
	}

	for (i = 0; i < KIC_IMAGE_COUNT; i++) {
		if (gad.images[i].magic == 0)
			break;

		name = get_image_name(gad.images[i].magic);
		if (!name) {
			printf("Unknown magic\n");
			abort;
		}

		printf("check %s\n", name);
		if (check_guest_image(&gad.images[i], laddr[i])) {
			printf("Check failed\n");
			abort();
		} else {
			printf("%s: passed\n", name);
		}

		if (gad.images[i].magic == KERNEL_MAGIC)
			kernel_check = 1;
	}

	if (!kernel_check) {
		printf("Kernel has not been checked\n");
		abort();
	}

	printf("Done\n");
	/* for some reason, if guard_uumap() is called, the guest kernel
	 * will not boot
	 */
	//io_guard_unmap(0x0);
}

