#include <stdio.h>

#include "linux_errno.h"
#include "syscalls.h"

intptr_t sys_unimplemented()
{
	__debugbreak();
	return -LINUX_ENOSYS;
}

const void* syscall_table[SYSCALL_COUNT] =
{
	sys_unimplemented,
	sys_write,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_exit,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
	sys_unimplemented,
};
