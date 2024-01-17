#include <stdlib.h>
#include <string.h>

#define unlikely(x) __builtin_expect(!!(x), 0)

void *__memcpy_chk(void *dest, const void *source, size_t n, size_t dest_len)
{
	if (unlikely(n > dest_len)) {
		abort();
	}
	return memcpy(dest, source, n);
}
