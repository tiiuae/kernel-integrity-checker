#include <stdio.h>
#include "platform.h"

/*
 * This is a basic implementation. This could be improved.
 */
void abort(void)
{
	printf("ABORT\n");
	systemoff();
}
