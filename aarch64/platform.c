#include <stdio.h>
#include <stdint.h>
#include "psci.h"

#define UART01x_FR_BUSY 0x40
#define UART01x_FR 0x5 /* Flag register (Read only). */
#define UART01x_DR 0x00 /* Data read or written from the interface. */
#define VIRT_UART  0x03f8
#define string(x) #x
#define read_reg(r)                           \
	__extension__({                           \
		uint64_t value;                       \
		__asm__ __volatile__("mrs	%0, " string(r) \
				     : "=r"(value));                \
		value;                                      \
	})

int _IO_putc(int c, struct _IO_FILE *__fp)
{
	volatile uint8_t *uart = (uint8_t *)VIRT_UART;

	while (!(*(uart + UART01x_FR) & UART01x_FR_BUSY));
	*(uart + UART01x_DR) = c;

	return 0;
}

int console_putc(unsigned char c)
{
	return _IO_putc((int)c, NULL);
}

int call_hyp(uint64_t fid, uint64_t x1)
{
	register uint64_t ret;

	__asm__ __inline__ __volatile__(
	    "mov x0, %[x0]\n\t"
	    "mov x1, %[x1]\n\t"
	    "hvc    #0\n"
	    "mov %[ret], x0\n\t"
	    : [ret] "=r"(ret)
	    : [x0] "r"(fid), [x1] "r"(x1)
	    : "x0", "x1", "memory");

	return ret;
}

void systemoff(void)
{
	call_hyp(PSCI_0_2_FN_SYSTEM_OFF, 0);
}

int mmio_guard_map(uint64_t addr)
{
	return call_hyp(0x00000000c6000007, addr);
}

int mmio_guard_unmap(uint64_t addr)
{
	return call_hyp(0x00000000c6000008, addr);
}

void dump_regs(uint64_t x, uint64_t sp[])
{
	uint64_t esr_el1 = read_reg(ESR_EL1);
	uint64_t far_el1 = read_reg(FAR_EL1);
	uint64_t elr_el1 = read_reg(ELR_EL1);

	printf("exception %x\n", x);
	printf("x0 : %llx\n", sp[0]);
	printf("x1 : %llx\n", sp[1]);
	printf("x2 : %llx\n", sp[2]);
	printf("x3 : %llx\n", sp[3]);
	printf("x4 : %llx\n", sp[4]);
	printf("x5 : %llx\n", sp[5]);
	printf("x6 : %llx\n", sp[6]);
	printf("x7 : %llx\n", sp[7]);
	printf("esr_el1: %llx\n", esr_el1);
	printf("far_el1: %llx\n", far_el1);
	printf("elr_el1: %llx\n", elr_el1);
	systemoff();
}
