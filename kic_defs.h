// SPDX-License-Identifier: GPL-2.0-only

#ifndef KIC_DEFS_H_
#define KIC_DEFS_H_

#define GAD_MAGIC 	0x4e474953
#define KERNEL_MAGIC 	0x4c4e524b
#define DTB_MAGIC 	0x54564544
#define GAD_VERSION	0x0300
#define GUEST_ID_MAX_LEN 16
#define SIGNATURE_MAX_LEN 80
#define PUBKEY_MAX_LEN 80
#define KIC_IC_LOADER_MAPPED 1
#define SZ_1K (1024UL)
#define SZ_1M (SZ_1K * 1024)
#define SZ_1G (SZ_1M * 1024)

#define KIC_MAX_IMAGE_SIZE  (256 * SZ_1M)
#define HASH_LEN 32
#define KIC_IMAGE_COUNT 3

#define KIC_PASSED 0
#define KIC_FAILED  (-1)

#define KIC_LOAD_ADDR_TO_X0 (1<<4)
#define KIC_LOAD_ARRD_FROM_X0 (1<<5)
typedef struct {
	uint32_t code0;		/* Executable code */
	uint32_t code1;		/* Executable code */
	uint64_t text_offset;	/* Image load offset, little endian */
	uint64_t image_size;	/* Effective Image size, little endian */
	uint64_t flags;		/* kernel flags, little endian */
	uint64_t res2;		/* reserved */
	uint64_t res3;		/* reserved */
	uint64_t res4;		/* reserved */
	uint32_t magic;		/* Magic number, little endian, "ARM\x64" */
	uint32_t res5;		/* reserved (used for PE COFF offset) */
} dummy_t;

typedef struct {
	uint32_t magic;
	uint32_t size;
	uint8_t key[PUBKEY_MAX_LEN];
} public_key_t;

typedef struct {
	uint32_t magic;
	uint32_t version;
	public_key_t sign_key;
	uint8_t signature[SIGNATURE_MAX_LEN];
} guest_cert_t;

typedef struct {
	uint32_t magic;
	uint32_t flags;
	uint32_t size;
	uint32_t offset;
	uint64_t load_addr;
	uint8_t hash[HASH_LEN];
} kic_image_t;

/* Guest Authenticated Data */
typedef struct {
	dummy_t hdr; /* crosvm requires that  ARM\x64  magic is in the place */
	uint32_t magic;
	uint32_t version;
	guest_cert_t cert;
	kic_image_t images[KIC_IMAGE_COUNT];
	uint8_t guest_id[GUEST_ID_MAX_LEN];
	uint8_t signature[SIGNATURE_MAX_LEN];
} gad_t;

#endif /* KIC_DEFS_H_ */
