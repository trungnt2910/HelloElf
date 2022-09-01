#include <stdio.h>

#include <array>
#include <vector>

#include <io.h>

#include <Windows.h>

#include <Zydis/Zydis.h>

#include "dbt.h"
#include "saved_registers.h"
#include "syscall_trampoline.h"
#include "syscalls.h"

ZydisDecoder sZydisDecoder;
ZydisFormatter sZydisFormatter;

// Cache for main executable object
static void* sMainDbtCache;
static size_t sMainDbtCacheSize = 0;
static size_t sMainDbtCacheCapacity = 0;
// Cache for dynamic libraries
static void* sDynDbtCache;
static size_t sDynDbtCacheSize = 0;
static size_t sDynDbtCacheCapacity = 0;
static size_t sDynDbtCacheCommitted = 0;

static int sPageSize;

const size_t kDynDbtInitialCacheSize = 256 * 1024 * 1024;

struct DbtInstructionInfo
{
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	void* address;
};

bool dbt_init(void* mainCacheBegin, size_t mainInitialCacheSize)
{
	sDynDbtCache = VirtualAlloc(NULL, kDynDbtInitialCacheSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
	sMainDbtCache = VirtualAlloc(mainCacheBegin, mainInitialCacheSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!sMainDbtCache)
	{
		return false;
	}

	sMainDbtCacheCapacity = mainInitialCacheSize;
	sDynDbtCacheCapacity = kDynDbtInitialCacheSize;

	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	sPageSize = sysinfo.dwPageSize;

#ifdef _WIN64
	ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LONG_64;
	ZydisStackWidth stackWidth = ZYDIS_STACK_WIDTH_64;
#else
	ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LEGACY_32;
	ZydisStackWidth stackWidth = ZYDIS_STACK_WIDTH_32;
#endif

	if (!ZYAN_SUCCESS(ZydisDecoderInit(&sZydisDecoder, machineMode, stackWidth)))
	{
		return false;
	}

	if (!ZYAN_SUCCESS(ZydisFormatterInit(&sZydisFormatter, ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		return false;
	}

	return true;
}

size_t dbt_emit_trampoline(void* newInstructionAddress, void* jumpTarget, void* nextAddress)
{
	ZydisEncoderRequest newInstruction = {};
	ZyanUSize newInstructionLength = -1;
	void* currentNewInstructionAddress = newInstructionAddress;

	newInstruction.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;

	// We used to use "sub rsp, 8" but this affects EFLAGS.
	// push rax
	newInstruction.mnemonic = ZYDIS_MNEMONIC_PUSH;
	newInstruction.operand_count = 1;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[0].reg.value = ZYDIS_REGISTER_RAX;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	// push rax
	newInstruction.mnemonic = ZYDIS_MNEMONIC_PUSH;
	newInstruction.operand_count = 1;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[0].reg.value = ZYDIS_REGISTER_RAX;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	// mov rax, nextAddress
	newInstruction.mnemonic = ZYDIS_MNEMONIC_MOV;
	newInstruction.operand_count = 2;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[0].reg.value = ZYDIS_REGISTER_RAX;
	newInstruction.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	newInstruction.operands[1].imm.u = (uintptr_t)nextAddress;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	// mov QWORD_PTR[rsp + 8], rax
	newInstruction.mnemonic = ZYDIS_MNEMONIC_MOV;
	newInstruction.operand_count = 2;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
	newInstruction.operands[0].mem.base = ZYDIS_REGISTER_RSP;
	newInstruction.operands[0].mem.displacement = 8;
	newInstruction.operands[0].mem.size = 8;
	newInstruction.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[1].reg.value = ZYDIS_REGISTER_RAX;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	// mov rax, syscall_trampoline
	newInstruction.mnemonic = ZYDIS_MNEMONIC_MOV;
	newInstruction.operand_count = 2;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[0].reg.value = ZYDIS_REGISTER_RAX;
	newInstruction.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	newInstruction.operands[1].imm.u = (uintptr_t)jumpTarget;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	// jmp rax
	newInstruction.mnemonic = ZYDIS_MNEMONIC_JMP;
	newInstruction.operand_count = 1;
	newInstruction.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	newInstruction.operands[0].reg.value = ZYDIS_REGISTER_RAX;

	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
		&newInstruction, currentNewInstructionAddress,
		&newInstructionLength)))
	{
		goto encode_fail;
	}

	currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
	newInstructionLength = -1;

	return (uintptr_t)currentNewInstructionAddress - (uintptr_t)newInstructionAddress;

encode_fail:
	return (size_t)-1;
}

void* dbt_translate(void* address)
{
	std::vector<DbtInstructionInfo> instructions;

	void* currentAddress = address;
	bool endOfBlock = false;

	while (!endOfBlock)
	{
		instructions.emplace_back();

		auto& [currentInstruction, currentOperands, currentInstructionAddress] = instructions.back();

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
			&sZydisDecoder, currentAddress, (ZyanUSize)-1,
			&currentInstruction, currentOperands,
			ZYDIS_MAX_OPERAND_COUNT, 0)))
		{
			fprintf(stderr, "Failed to decode instruction\n");
			exit(EXIT_FAILURE);
		}

		currentInstructionAddress = currentAddress;

		switch (currentInstruction.mnemonic)
		{
			case ZYDIS_MNEMONIC_CALL:
			case ZYDIS_MNEMONIC_JB:
			case ZYDIS_MNEMONIC_JBE:
			case ZYDIS_MNEMONIC_JCXZ:
			case ZYDIS_MNEMONIC_JECXZ:
			case ZYDIS_MNEMONIC_JKNZD:
			case ZYDIS_MNEMONIC_JKZD:
			case ZYDIS_MNEMONIC_JL:
			case ZYDIS_MNEMONIC_JLE:
			case ZYDIS_MNEMONIC_JMP:
			case ZYDIS_MNEMONIC_JNB:
			case ZYDIS_MNEMONIC_JNBE:
			case ZYDIS_MNEMONIC_JNL:
			case ZYDIS_MNEMONIC_JNLE:
			case ZYDIS_MNEMONIC_JNO:
			case ZYDIS_MNEMONIC_JNP:
			case ZYDIS_MNEMONIC_JNS:
			case ZYDIS_MNEMONIC_JNZ:
			case ZYDIS_MNEMONIC_JO:
			case ZYDIS_MNEMONIC_JP:
			case ZYDIS_MNEMONIC_JRCXZ:
			case ZYDIS_MNEMONIC_JS:
			case ZYDIS_MNEMONIC_JZ:
			case ZYDIS_MNEMONIC_RET:
			case ZYDIS_MNEMONIC_SYSCALL:
				endOfBlock = true;
			break;
		}

		currentAddress = (void*)((uintptr_t)currentAddress + currentInstruction.length);
	}

#ifdef _DEBUG
	char fmt_buf[256];
	for (const auto& [currentInstruction, currentOperands, currentInstructionAddress] : instructions)
	{
		// Format & print the original instruction.
		if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&sZydisFormatter, &currentInstruction, currentOperands,
			currentInstruction.operand_count, fmt_buf, sizeof(fmt_buf), (ZyanU64)(intptr_t)currentInstructionAddress, NULL)))
		{
			fprintf(stderr, "Failed to format instruction.\n");
			exit(EXIT_FAILURE);
		}
		printf("%p: %s\n", currentInstructionAddress, fmt_buf);
	}
#endif

	void* nextAddress = currentAddress;
	void* newInstructionAddress = (void*)((uintptr_t)sMainDbtCache + sMainDbtCacheSize);
	void* currentNewInstructionAddress = newInstructionAddress;

	for (const auto& [currentInstruction, currentOperands, currentInstructionAddress] : instructions)
	{
		ZyanUSize newInstructionLength = -1;

		switch (currentInstruction.mnemonic)
		{
			case ZYDIS_MNEMONIC_SYSCALL:
			{
				newInstructionLength = dbt_emit_trampoline(currentNewInstructionAddress, syscall_trampoline, nextAddress);
				if (newInstructionLength == (ZyanUSize)-1)
				{
					fprintf(stderr, "Failed to emit syscall trampoline.\n");
					exit(EXIT_FAILURE);
				}

				currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
			}
			break;
			default:
			{
				ZydisEncoderRequest newInstruction;
				if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
					&currentInstruction, currentOperands,
					currentInstruction.operand_count_visible, &newInstruction)))
				{
					fprintf(stderr, "Failed to convert decoded instruction.\n");
					exit(EXIT_FAILURE);
				}

				if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
					&newInstruction, currentNewInstructionAddress,
					&newInstructionLength)))
				{
					goto encode_fail;
				}

				currentNewInstructionAddress = (void*)((uintptr_t)currentNewInstructionAddress + newInstructionLength);
			}
			break;
		}
	}

#ifdef _DEBUG
	fprintf(stderr, "Next block address: %p\n", currentAddress);

	for (void* addr = newInstructionAddress; addr < currentNewInstructionAddress; )
	{
		ZydisDecodedInstruction currentInstruction;
		ZydisDecodedOperand currentOperands[ZYDIS_MAX_OPERAND_COUNT];
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
			&sZydisDecoder, addr, (ZyanUSize)-1,
			&currentInstruction, currentOperands,
			ZYDIS_MAX_OPERAND_COUNT, 0)))
		{
			fprintf(stderr, "Failed to decode instruction\n");
			exit(EXIT_FAILURE);
		}

		// Format & print the original instruction.
		if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&sZydisFormatter, &currentInstruction, currentOperands,
			currentInstruction.operand_count, fmt_buf, sizeof(fmt_buf), (ZyanU64)(intptr_t)addr, NULL)))
		{
			fprintf(stderr, "Failed to format instruction.\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "%p: %s\n", addr, fmt_buf);

		addr = (void*)((uintptr_t)addr + currentInstruction.length);
	}
#endif

	sMainDbtCacheSize = ((uintptr_t)currentNewInstructionAddress) - ((uintptr_t)sMainDbtCache);

	return newInstructionAddress;

encode_fail:
	fprintf(stderr, "Failed to encode instruction.\n");
	exit(EXIT_FAILURE);
}

void* dbt_enter(void* address)
{
	void* newInstructionAddress = dbt_translate(address);

	((void(*)(void))newInstructionAddress)();

	fprintf(stderr, "Unimplemented\n");
	exit(EXIT_FAILURE);
}

extern "C"
void* dbt_syscall(SavedRegisters* registers, void* continueAddress)
{
	syscall_handler_t syscallFunction = (syscall_handler_t)sys_unimplemented;
	if (registers->rax < SYSCALL_COUNT)
	{
		syscallFunction = (syscall_handler_t)syscall_table[registers->rax];
	}

	registers->rax = syscallFunction(registers->rdi, registers->rsi, registers->rdx,
		registers->r10, registers->r8, registers->r9);

	void* newInstructionAddress = dbt_translate(continueAddress);
	return newInstructionAddress;

	fprintf(stderr, "Unimplemented.\n");
	exit(EXIT_FAILURE);
}
