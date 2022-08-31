# HelloElf

This project is an attempt to load and run x86_64 Linux ELF binaries on Windows.

The project implements a loader, a dynamic binary translator (based on [Zydis](https://github.com/zyantific/zydis)), and a syscall handler, all on userland.

Right now, only the "Hello World" binary included with the source code works.