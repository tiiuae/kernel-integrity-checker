/* SPDX-License-Identifier: GPL-2.0-only */

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

extern const uint64_t *_start;
extern const uint64_t *_stack_top;

__attribute__((__section__(".heap"))) uint32_t hyp_malloc_pool[1024 * 4];
__attribute__((__section__(".stack"))) uint32_t stack[1024 * 16];

#define CHECKRES(x, expected, err_handler) \
	do {                               \
		if ((x) != (expected)) {   \
			goto err_handler;  \
		}                          \
	} while (0)

int allowed_memory(uint64_t begin, size_t size)
{
	uint64_t end = begin + size - 1;
	const uintptr_t disallowed_begin = (uintptr_t) &_start;
	const uintptr_t disallowed_end = (uintptr_t) &_stack_top;

	return (begin < disallowed_begin && end < disallowed_begin) ||
		(begin > disallowed_end && end > disallowed_end);
}
typedef uint32_t u32;
typedef uint8_t u8;

typedef u32 phandle;

struct list_head {
	struct list_head *next, *prev;
};
struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct property {
	char	*name;
	int	length;
	void	*value;
	struct property *next;
#if defined(CONFIG_OF_DYNAMIC) || defined(CONFIG_SPARC)
	unsigned long _flags;
#endif
#if defined(CONFIG_OF_PROMTREE)
	unsigned int unique_id;
#endif
#if defined(CONFIG_OF_KOBJ)
	struct bin_attribute attr;
#endif
};

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;

	struct	property *properties;
	struct	property *deadprops;	/* removed properties */
	struct	device_node *parent;
	struct	device_node *child;
	struct	device_node *sibling;
#if defined(CONFIG_OF_KOBJ)
	struct	kobject kobj;
#endif
	unsigned long _flags;
	void	*data;
#if defined(CONFIG_SPARC)
	unsigned int unique_id;
	struct of_irq_controller *irq_trans;
#endif
};

#define of_prop_cmp(s1, s2)		strcmp((s1), (s2))

struct property *of_find_property(const struct device_node *np,
					   const char *name, int *lenp)
{
	struct property *pp;

	if (!np)
		return NULL;

	for (pp = np->properties; pp; pp = pp->next) {
		if (of_prop_cmp(pp->name, name) == 0) {
			if (lenp)
				*lenp = pp->length;
			break;
		}
	}

	return pp;
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
	ret = mbedtls_ecp_point_read_binary(&grp, &key.private_Q,
					    pub, pub_size);

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

int check_guest_image(kic_image_t *image, uint64_t load_addr)
{
	uint8_t hash[32];
	int i;
	int ret;

	ret = calc_hash(hash, (void *)load_addr,
			image->size);
	if (ret != MBEDTLS_EXIT_SUCCESS) {
		return KIC_FAILED;

	}
	if (memcmp(hash, image->hash, 32)) {
		return KIC_FAILED;
	} else
		return KIC_PASSED;
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
		p = "Unknown";
	}
	return p;
}

void ic_loader(uint64_t sp[], uint64_t image_addr)
{
	uint8_t *p;
	kic_image_t *img;
	int ret;
	int i;
	gad_t gad;
	uint32_t len;
	uint64_t laddr[KIC_IMAGE_COUNT];
	struct	property *prop;

	printf("Integrity check loader started %llx %llx %llx\n",sp[0],sp[1],sp[2]);
	//korjaa crosvm, puukotettu versio ei taida tehdä dtb filua
	//prop = of_find_property(sp[0], "kernel-address", 0);
	//printf("kernel addr %s\n", prop->name);
	//printf("kernel addr %x\n", prop->value);
	set_heap(hyp_malloc_pool, sizeof(hyp_malloc_pool));
	memcpy(&gad, (void *)image_addr, sizeof(gad));

	ret = image_check_init(&gad);
	if (ret)
		abort();

	for (i = 0; i < KIC_IMAGE_COUNT; i++) {
		img = &gad.images[i];
		if (img->magic) {
			len = ROUND_UP(img->size, sizeof(uint64_t));
			if ((len == 0) || (len > KIC_MAX_IMAGE_SIZE))
				abort();

			if (img->flags & KIC_LOAD_ARRD_FROM_X0) {
				/* x0 contains the load address */
				laddr[i] = sp[0];
			} else {
				if (img->magic == KERNEL_MAGIC) {
					laddr[i] = image_addr;
				} else
					laddr[i] = img->load_addr;
				if (img->flags & KIC_LOAD_ADDR_TO_X0) {
					/* load address to x0 via stack */
					sp[0] = img->load_addr;
				}
			}

			if (allowed_memory(laddr[i], len))
				/* do not overwrite ic-loader code/data */
				memmove((void *)laddr[i],
					(void *)image_addr + img->offset,
					len);
				else
					abort();

			printf("copy '%s image' %d bytes from 0x%x to 0x%x\n",
				get_image_name(img->magic),
				len,
				image_addr + img->offset,
				laddr[i]);

		} else
			break;
	}

	for (i = 0; i < KIC_IMAGE_COUNT; i++) {
		if (gad.images[i].magic == 0)
			break;

		if (check_guest_image(&gad.images[i], laddr[i])) {
			printf("Check failed\n");
			abort();
		} else {
			printf("%s: passed\n",
				get_image_name(gad.images[i].magic));
		}
	}
	printf("Done\n");
}

