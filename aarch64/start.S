// SPDX-License-Identifier: GPL-2.0-only

//
// Input
// ------
// MMU = off, D-cache = off, I-cache = off
// CPU in EL1
// x0 : device tree address from VMM
// x1 : original guest start address from VMM

.set TT_S1_TABLE,           0x00000000000000003    // NSTable=0, PXNTable=0, UXNTable=0, APTable=0
.set TT_S1_NORMAL_WBWA,     0x00000000000000405    // Index = 1, AF=1
.set TT_S1_DEVICE_nGnRnE,   0x00600000000000409    // Index = 2, AF=1, PXN=1, UXN=1
.set TT_S1_INNER_SHARED,    (3 << 8)               // Inner-shareable
.set AArch64_EL1_SP1,      0x05    // EL1h

.global _start
_start:
	adr x29, _stack_top
	mov sp, x29
	sub sp, sp, #(8 * 4)
	stp x0, x1, [sp, #(8 * 0)]
	stp x2, x3, [sp, #(8 * 2)]

// allow SIMD registers
	ldr x0, =(3<<20)
	msr CPACR_EL1, x0

// set execption handler
	adr x29, el1_vectors
	msr VBAR_EL1, x29

// clean tranlation tables
	adr x0, xtables
	adr x1, tables_end
setzero:
	str xzr,[x0], #8
	cmp x0, x1
	b.lo setzero

// Set the Base address
// ---------------------
	ldr x0, =l1_table
	msr TTBR0_EL1, x0

// Set up memory attributes
// -------------------------
// This equates to:
// 0 = b01000100 = Normal, Inner/Outer Non-Cacheable
// 1 = b11111111 = Normal, Inner/Outer WB/WA/RA
// 2 = b00000000 = Device-nGnRnE
	mov x0, #0x000000000000FF44
	msr MAIR_EL1, x0

// Set up TCR_EL1
// ---------------
	mov x0, #0x1c // T0SZ=0b11100 Limits VA space to 34 bits
	orr x0, x0, #(0x1 << 8) // IGRN0=0b01 Walks to TTBR0 are Inner WB/WA
	orr x0, x0, #(0x1 << 10) // OGRN0=0b01 Walks to TTBR0 are Outer WB/WA
	orr x0, x0, #(0x3 << 12) // SH0=0b11 Inner Shareable
	orr x0, x0, #(0x1 << 23) // EPD1=0b1 Disable table walks from TTBR1
				// TBI0=0b0
				// TG0=0b00 4KB granule for TTBR0
				// A1=0 TTBR0 contains the ASID
				// AS=0 8-bit ASID
	orr x0, x0, #(0x1 << 32) // IPS=001 36-bit IPA space
	msr TCR_EL1, x0

  	isb

// Invalidate TLBs
// ----------------
	TLBI VMALLE1
	DSB SY
	ISB

// Generate L1 table
	ldr x1, =l1_table
	ldr x0, =TT_S1_TABLE
	ldr x2, =l2_0000
	orr x2, x0, x2
	str x2, [x1] // VA 0x00000000

	ldr x2, =l2_4000
	orr x2, x0, x2
	str x2, [x1, #8]  //0x40000000

	ldr x2, =l2_8000
	orr x2, x0, x2
	str x2, [x1, #16] //0x80000000

	ldr x2, =l2_C000
	orr x2, x0, x2
	str x2, [x1, #24] //0xC0000000

	ldr x2, =l2_10000
	orr x2, x0, x2
	str x2, [x1, #32] //0x100000000

	ldr x2, =l2_14000
	orr x2, x0, x2
	str x2, [x1, #40] //0x140000000

// Generate L2 table for 00000000 - 3fffffff
	ldr x1, =l2_0000
	ldr x2, =0x00000000  //phys address
	bl create_l2_tbl

// Generate L2  table for 40000000 - 7fffffff
	ldr x1, =l2_4000
	ldr x2, =0x40000000  //phys address
	bl create_l2_tbl

// Generate L2  table for 80000000 - bfffffff
	ldr x1, =l2_8000
	ldr x2, =0x80000000  //phys address
	bl create_l2_tbl

// Generate L2  table for C0000000 - ffffffff
	ldr x1, =l2_C000
	ldr x2, =0xC0000000  //phys address
	bl create_l2_tbl

// Generate L2  table for 100000000 - 13fffffff
	ldr x1, =l2_10000
	ldr x2, =0x100000000  //phys address
	bl create_l2_tbl

// Generate L2  table for 140000000 - 17fffffff
	ldr x1, =l2_14000
	ldr x2, =0x140000000  //phys address
	bl create_l2_tbl
	dsb sy

// Enable MMU
	mov x0, #(1 << 0)	// M=1 bit Enable the stage 1 MMU
	orr x0, x0, #(1 << 2)	// C=1 bit Enable data and unified caches
	orr x0, x0, #(1 << 12)	// I=1     Enable instruction fetches to allocate into unified caches
				// A=0     Strict alignment checking disabled
				// SA=0    Stack alignment checking disabled
				// WXN=0   Write permission does not imply XN
				// EE=0    EL3 data accesses are little endian
	msr SCTLR_EL1, x0
	isb
	nop
	nop
	nop
	nop
// MMU is now enabled

// Invalidate cache
	ldr x0,=_start
	ldr x1,=0x400000
	bl __inval_dcache_area

//do the job
	ldp x0, x1, [sp, #(8 * 0)]
	mov x0, sp
	bl ic_loader

//images has been checked, prepare the kernel start
//flush images from cache
	ldr x0, =0x80000000
	ldr x1, =0x100000000
	bl __flush_dcache_area

//flush ic_loader data from cache
	ldr x0, =_start
	ldr x1, =0x60000
	bl __flush_dcache_area

// disable MMU
	mov x0, xzr
 	msr SCTLR_EL1, x0
	isb
	nop
	nop
	nop
	nop
// MMU is now disabled

	mov x1, xzr
	ldp x0, lr, [sp, #(8 * 0)]
	ldp x2, x3, [sp, #(8 * 2)]
	mov x4, xzr
	mov x5, xzr
	mov x6, xzr
	mov x7, xzr
	mov x8, xzr
	mov x9, xzr
	mov x10, xzr
	mov x11, xzr
	mov x12, xzr
	mov x13, xzr
	mov x14, xzr
	mov x15, xzr
	mov x16, xzr
	mov x17, xzr
	mov x18, xzr
	mov x19, xzr
	mov x20, xzr
	mov x21, xzr
	mov x22, xzr
	mov x23, xzr
	mov x24, xzr
	mov x25, xzr
	mov x26, xzr
	mov x27, xzr
	mov x28, xzr
	mov x29, xzr

	// jump to kernel
	br lr

create_l2_tbl:
	mov 	x4, xzr
	mov	x3, #0x200000
l2loop:
	ldr	x0, =TT_S1_NORMAL_WBWA
	orr	x0, x0, #TT_S1_INNER_SHARED
	orr	x0, x0, x2
	str 	x0, [x1], #8
	add	x2, x2, x3
	add 	x4, x4, #1
	cmp 	x4, #0x200
	b.lo 	l2loop
	ret

.section xtables
.align 12
l1_table: .space 4096
l2_0000: .space 4096
l2_4000: .space 4096
l2_8000: .space 4096
l2_C000: .space 4096
l2_10000: .space 4096
l2_14000: .space 4096

tables_end:
