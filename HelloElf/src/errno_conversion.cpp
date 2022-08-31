#include <errno.h>
#include <stdio.h>

#include "errno_conversion.h"
#include "linux_errno.h"

int ErrnoWindowsToLinux(int windowsErrno)
{
	switch (windowsErrno)
	{
#define SUPPORTED_ERRNO(name) \
		case name: return LINUX_##name;
#include "errno_values.h"
#undef SUPPORTED_ERRNO
		default:
			fprintf(stderr, "Unknown errno value: %i\n", windowsErrno);
			return LINUX_EINVAL;
	}
}
