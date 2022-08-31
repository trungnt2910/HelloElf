#include <errno.h>
#include <io.h>
#include <stdint.h>

#include "errno_conversion.h"

intptr_t sys_write(unsigned int fd, const char* buf, size_t count)
{
	int result = write(fd, buf, (unsigned int)count);

	if (result == -1)
	{
		return -ErrnoWindowsToLinux(errno);
	}

	return result;
}
