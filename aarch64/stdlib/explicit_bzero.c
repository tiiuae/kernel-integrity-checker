#include <string.h>
#include <stdlib.h>

#define unlikely(x) __builtin_expect(!!(x), 0)

void __explicit_bzero_chk(void *dst, size_t len, size_t destlen)
{
	if (unlikely(destlen < len))
		abort();
	memset(dst, 0, len);
}

void explicit_bzero(void *dst, size_t len)
{
	memset(dst, 0, len);
}
