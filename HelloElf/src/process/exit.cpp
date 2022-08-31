#include <stdio.h>
#include <stdlib.h>

#include "linux_errno.h"

intptr_t sys_exit(int error_code)
{
	exit(error_code);
	// Should not reach this line.
	fprintf(stderr, "sys_exit: should not reach this line.\n");
	return -LINUX_EAGAIN;
}
