#ifndef __SYSCALL_TABLE_H__
#define __SYSCALL_TABLE_H__

#include <stdint.h>

// See https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl

#define SYSCALL_COUNT 548

extern const void* syscall_table[SYSCALL_COUNT];
typedef intptr_t(*syscall_handler_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

intptr_t sys_unimplemented();

// Syscalls

// 1
intptr_t sys_write(unsigned int fd, const char* buf, size_t count);

// 60
intptr_t sys_exit(int error_code);

#endif // __SYSCALL_TABLE_H__