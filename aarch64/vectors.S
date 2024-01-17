	.section .vectors
	.align 11

.set sync_el1_t,1
.set irq_el1_t,2
.set fiq_el1_t,3
.set err_el1_t,4
.set sync_el1_h,5
.set irq_el1_h,6
.set fiq_el1_h,7
.set err_el1_h,8

.macro entry id
	sub sp, sp, #(8 * 8)
	stp x0, x1, [sp, #(8 * 0)]
	stp x2, x3, [sp, #(8 * 2)]
	stp x4, x5, [sp, #(8 * 4)]
	stp x6, x7, [sp, #(8 * 6)]

	mov x0, \id
	mov x1, sp
	b dump_regs
        .balign 128
.endm

.global el1_vectors


el1_vectors:
	entry sync_el1_t
	entry irq_el1_t
	entry fiq_el1_t
	entry err_el1_t
	entry sync_el1_h
	entry irq_el1_h
	entry fiq_el1_h
	entry err_el1_h
