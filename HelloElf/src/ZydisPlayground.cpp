/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Joel Hoener

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

/**
 * @file
 *
 * Example that takes raw instruction bytes as command line argument, decoding the instruction and
 * changing a range of things about it before encoding it again, printing the new instruction bytes.
 *
 * `jz` instructions are rewritten to `jnz`, `add` is replaced with `sub`. Immediate operand
 * constants are changed to `0x42` and the displacement in memory operands is changed to `0x1337`.
 *
 * The example always consumes and generates code in 64-bit mode.
 */

#include <Zydis/Zydis.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <inttypes.h>

#include <vector>

 /* ============================================================================================== */
 /* Entry point                                                                                    */
 /* ============================================================================================== */

const uint8_t bytes[] = { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x0E, 0x48, 0xBB, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x53, 0x48, 0xBB, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0A, 0x00, 0x00, 0x53, 0x48, 0x83, 0xC4, 0x02, 0x48, 0x89, 0xE6, 0x48, 0x83, 0xEE, 0x0E, 0x48, 0xC7, 0xC2, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05 };
//const uint8_t bytes[] = { 0x65, 0x8B, 0x04, 0x25, 0x14, 0x00, 0x00, 0x00, 0x67, 0x89, 0x45, 0xF4 };
//const uint8_t bytes[] = { 0x75, 0x02, 0xFF, 0xE0, 0xFF, 0xD0, 0xC3 };
const size_t num_bytes = sizeof(bytes) / sizeof(uint8_t);
uint8_t new_bytes[num_bytes * 2];

int syscall_function;

static void ExpectSuccess(ZyanStatus status)
{
    if (ZYAN_FAILED(status))
    {
        fprintf(stderr, "Something failed: 0x%08X\n", status);
        exit(EXIT_FAILURE);
    }
}

int main__(int argc, char** argv)
{
    // Initialize decoder in X86-64 mode.
    ZydisDecoder decoder;
    ExpectSuccess(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

    // Initialize the formatter.
    ZydisFormatter fmt;
    ExpectSuccess(ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL));

    const uint8_t* currentPtr = bytes;

    std::vector<ZydisEncoderRequest> encoder_requests;

    const auto display_block = [&]()
    {
        printf("Instruction block:\n");
        for (const auto& enc_req : encoder_requests)
        {
            // Encode the instruction back to raw bytes.
            uint8_t new_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
            ZyanUSize new_instr_length = sizeof(new_bytes);
            ExpectSuccess(ZydisEncoderEncodeInstruction(&enc_req, new_bytes, &new_instr_length));

            ZydisDecodedInstruction instr;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            char fmt_buf[256];

            ExpectSuccess(ZydisDecoderDecodeFull(&decoder, new_bytes, new_instr_length, &instr,
                operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY));
            ExpectSuccess(ZydisFormatterFormatInstruction(&fmt, &instr, operands,
                instr.operand_count_visible, fmt_buf, sizeof(fmt_buf), 0, NULL));
            printf("New instruction:      %s\n", fmt_buf);
        }
        encoder_requests.clear();
    };

    while (currentPtr - bytes < num_bytes)
    {
        // Attempt to decode the given bytes as an X86-64 instruction.
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, currentPtr, num_bytes, &instr, operands,
            ZYDIS_MAX_OPERAND_COUNT, 0);
        if (ZYAN_FAILED(status))
        {
            fprintf(stderr, "Failed to decode instruction: %02" PRIx32, status);
            exit(EXIT_FAILURE);
        }

        // Format & print the original instruction.
        char fmt_buf[256];
        ExpectSuccess(ZydisFormatterFormatInstruction(&fmt, &instr, operands,
            instr.operand_count, fmt_buf, sizeof(fmt_buf), (ZyanU64)(intptr_t)currentPtr, NULL));
        printf("Original instruction: %s\n", fmt_buf);

        /*for (size_t i = 0; i < instr.operand_count; ++i)
        {
            ExpectSuccess(ZydisFormatterFormatOperand(&fmt, &instr, &operands[i], fmt_buf, sizeof(fmt_buf), (ZyanU64)(intptr_t)currentPtr, NULL));
            if (operands[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE && operands[i].reg.value == ZYDIS_REGISTER_RIP)
            {
                printf("This instruction modifies rip.\n");
            }
            printf("Operand: %s\n", fmt_buf);
        }*/

        // Create an encoder request from the previously decoded instruction.
        ZydisEncoderRequest enc_req;
        ExpectSuccess(ZydisEncoderDecodedInstructionToEncoderRequest(&instr, operands,
            instr.operand_count_visible, &enc_req));

        switch (enc_req.mnemonic)
        {
            case ZYDIS_MNEMONIC_SYSCALL:
            {
                ZydisEncoderRequest temp_enc_req;

                memset(&temp_enc_req, 0, sizeof(temp_enc_req));
                temp_enc_req.mnemonic = ZYDIS_MNEMONIC_PUSH;
                temp_enc_req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                temp_enc_req.operand_count = 1;
                temp_enc_req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                temp_enc_req.operands[0].reg.value = ZYDIS_REGISTER_RAX;
                encoder_requests.push_back(temp_enc_req);

                memset(&temp_enc_req, 0, sizeof(temp_enc_req));
                temp_enc_req.mnemonic = ZYDIS_MNEMONIC_MOV;
                temp_enc_req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                temp_enc_req.operand_count = 2;
                temp_enc_req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                temp_enc_req.operands[0].reg.value = ZYDIS_REGISTER_RAX;
                temp_enc_req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                temp_enc_req.operands[1].imm.u = (uintptr_t)&syscall_function;
                encoder_requests.push_back(temp_enc_req);

                memset(&temp_enc_req, 0, sizeof(temp_enc_req));
                temp_enc_req.mnemonic = ZYDIS_MNEMONIC_CALL;
                temp_enc_req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                temp_enc_req.operand_count = 1;
                temp_enc_req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                temp_enc_req.operands[0].reg.value = ZYDIS_REGISTER_RAX;
                encoder_requests.push_back(temp_enc_req);
                display_block();
            }
            break;
            default:
                encoder_requests.push_back(enc_req);
            break;
        }

        currentPtr += instr.length;
    }

    return 0;

#if 0
    // Create an encoder request from the previously decoded instruction.
    ZydisEncoderRequest enc_req;
    ExpectSuccess(ZydisEncoderDecodedInstructionToEncoderRequest(&instr, operands,
        instr.operand_count_visible, &enc_req));

    // Now, change some things about the instruction!

    // Change `jz` -> `jnz` and `add` -> `sub`.
    switch (enc_req.mnemonic)
    {
    case ZYDIS_MNEMONIC_ADD:
        enc_req.mnemonic = ZYDIS_MNEMONIC_SUB;
        break;
    case ZYDIS_MNEMONIC_JZ:
        enc_req.mnemonic = ZYDIS_MNEMONIC_JNZ;
        break;
    default:
        // Don't change other instructions.
        break;
    }

    // Walk the operand list and look for things to change.
    for (int i = 0; i < enc_req.operand_count; ++i)
    {
        ZydisEncoderOperand* op = &enc_req.operands[i];

        switch (op->type)
        {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            // For immediate operands, change the constant to `0x42`.
            op->imm.u = 0x42;
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            // For memory operands, change the displacement to `0x1337` and the scale to `2`.
            op->mem.displacement = 0x1337;
            break;
        default:
            // Any other operands remain unchanged.
            break;
        }
    }

    // Encode the instruction back to raw bytes.
    uint8_t new_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize new_instr_length = sizeof(new_bytes);
    ExpectSuccess(ZydisEncoderEncodeInstruction(&enc_req, new_bytes, &new_instr_length));

    // Decode and print the new instruction. We re-use the old buffers.
    ExpectSuccess(ZydisDecoderDecodeFull(&decoder, new_bytes, new_instr_length, &instr,
        operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY));
    ExpectSuccess(ZydisFormatterFormatInstruction(&fmt, &instr, operands,
        instr.operand_count_visible, fmt_buf, sizeof(fmt_buf), 0, NULL));
    printf("New instruction:      %s\n", fmt_buf);

    // Print the new instruction as hex-bytes.
    printf("New raw bytes:        ");
    for (ZyanUSize i = 0; i < new_instr_length; ++i)
    {
        printf("%02" PRIx8 " ", new_bytes[i]);
    }
    putchar('\n');
#endif
}

/* ============================================================================================== */