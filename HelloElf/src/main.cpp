#include <assert.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include <Windows.h>

#include "dbt.h"
#include "elf.h"

#ifdef _WIN64
#define ElfW(type) Elf64_##type
#elif defined _WIN32
#define ElfW(type) Elf32_##type
#endif

int read_all(int fd, void* dst, unsigned int size)
{
	size_t alreadyRead = 0;
	while (size > 0)
	{
		int currentRead = read(fd, dst, size);
		if (currentRead < 0)
		{
			return (int)alreadyRead;
		}
		alreadyRead += currentRead;
		assert((unsigned int)currentRead <= size);
		size -= (unsigned int)currentRead;
	}
	return (int)alreadyRead;
}

int ElfProtectionToWindows(ElfW(Word) elfFlags)
{
	static const int table[2][2][2] =
	{
		// Not executable
		{
			// Not writable
			{ PAGE_NOACCESS, PAGE_READONLY },
			// Writable
			{ PAGE_READWRITE, PAGE_READWRITE }
		},
		// Executable
		{
			// Not writable
			{ PAGE_EXECUTE, PAGE_EXECUTE_READ },
			// Writable
			{ PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE }
		}
	};

	return table[(bool)(elfFlags & PF_X)][(bool)(elfFlags & PF_W)][(bool)(elfFlags & PF_R)];
}

int main()
{
	int elfFile = open("hello", O_BINARY | O_RDONLY);
	if (elfFile == -1)
	{
		fprintf(stderr, "Failed to open test binary: %s.", strerror(errno));
		abort();
	}

	ElfW(Ehdr) header;

	if (read_all(elfFile, &header, sizeof(header)) != sizeof(header))
	{
		fprintf(stderr, "Failed to read binary: %s.", strerror(errno));
		abort();
	}

	if (!IS_ELF(header))
	{
		fprintf(stderr, "Not an ELF file.\n");
		abort();
	}

	if (lseek(elfFile, (long)header.e_phoff, SEEK_SET) == 1)
	{
		fprintf(stderr, "Failed to seek: %s", strerror(errno));
	}

	assert(header.e_phentsize == sizeof(ElfW(Phdr)));

	std::vector<ElfW(Phdr)> programHeaders(header.e_phnum);

	ElfW(Addr) minAddr = -1;
	ElfW(Addr) maxAddr = 0;


	for (ElfW(Half) i = 0; i < header.e_phnum; ++i)
	{
		ElfW(Phdr)& programHeader = programHeaders[i];
		if (read_all(elfFile, &programHeader, sizeof(programHeader)) != sizeof(programHeader))
		{
			fprintf(stderr, "Failed to read program header: %s.", strerror(errno));
			abort();
		}
#ifdef _DEBUG
		fprintf(stderr, "File size: %#06llx Memory size: %#06llx Align: %04lld File offset: 0x%04llx Memory offset 0x%6llx\n",
			(long long)programHeader.p_filesz,
			(long long)programHeader.p_memsz,
			(long long)programHeader.p_align,
			(long long)programHeader.p_offset,
			(long long)programHeader.p_vaddr);
#endif
		minAddr = min(minAddr, programHeader.p_vaddr);
		maxAddr = max(minAddr, programHeader.p_vaddr + programHeader.p_memsz);
	}

	int pageSize;
	int allocationGranuality;

	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		pageSize = info.dwPageSize;
		allocationGranuality = info.dwAllocationGranularity;
	}

	maxAddr = ((maxAddr + pageSize - 1) / pageSize) * pageSize;

#ifdef _DEBUG
	fprintf(stderr, "Should allocate from: %p to: %p\n", (void*)minAddr, (void*)maxAddr);
#endif

	void* imageBase;
	ElfW(Addr) memoryOffset;

	if (header.e_type == ET_EXEC)
	{
		assert(minAddr != NULL);
		imageBase = VirtualAlloc((LPVOID)minAddr, maxAddr - minAddr, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		assert(imageBase == (void*)minAddr);
		memoryOffset = 0;
	}
	else
	{
		fprintf(stderr, "e_type != ET_EXEC not implemented.\n");
		abort();
	}

	for (const auto& programHeader : programHeaders)
	{
		void* headerAddress = (void*)(programHeader.p_vaddr + memoryOffset);
		lseek(elfFile, (long)programHeader.p_offset, SEEK_SET);
		read_all(elfFile, headerAddress, (unsigned int)programHeader.p_filesz);
		unsigned long _;
		if (!VirtualProtect(headerAddress, programHeader.p_memsz, ElfProtectionToWindows(programHeader.p_flags), &_))
		{
			int error = GetLastError();
			char* messageBuffer = NULL;
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPSTR)&messageBuffer, 0, NULL);
			fprintf(stderr, "Failed to protect memory at 0x%p: %s", headerAddress, messageBuffer);
			LocalFree(messageBuffer);
		}
	}

#ifdef _DEBUG
	fprintf(stderr, "Jumping to entry point: %p\n", (void*)header.e_entry);
#endif

	size_t mainExecutableDbtSize = maxAddr - minAddr;
	mainExecutableDbtSize *= 3;
	mainExecutableDbtSize /= 2;
	mainExecutableDbtSize = ((mainExecutableDbtSize + pageSize - 1) / pageSize) * pageSize;

	size_t mainExecutableDbtBase = memoryOffset + maxAddr;
	mainExecutableDbtBase = ((mainExecutableDbtBase + allocationGranuality - 1) / allocationGranuality) * allocationGranuality;

	if (!dbt_init((void*)mainExecutableDbtBase, mainExecutableDbtSize))
	{
		fprintf(stderr, "Failed to initialize dbt.");
		abort();
	}

	dbt_enter((void*)header.e_entry);

	close(elfFile);
}