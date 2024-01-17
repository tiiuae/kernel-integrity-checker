#include <stdio.h>
#include "platform.h"

void exit(int v)
{
	printf("exit called with code %d\n", v);
	systemoff();
}
