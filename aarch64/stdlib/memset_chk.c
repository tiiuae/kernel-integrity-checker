#include <stdlib.h>
#include <string.h>

#define unlikely(x) __builtin_expect(!!(x), 0)

void *__memset_chk(void *dest, int c, size_t n, size_t dest_len)
{
	if (unlikely(n > dest_len)) {
		abort();
	}
	return memset(dest, c, n);
}
