#include "TTD_FunctionAnalysis.hpp"
#include <Windows.h>

static ZydisDecoder Decoder;

void TTD_AnalyzerInit(uint16_t MachineMode)
{
	if (MachineMode == PROCESSOR_ARCHITECTURE_INTEL)
	{
		ZydisDecoderInit(&Decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
	}
	else if (MachineMode == PROCESSOR_ARCHITECTURE_AMD64)
	{
		ZydisDecoderInit(&Decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	}
}

TTD_ProcessVirtualAddress
GetFunctionEnd(TTD_Process& Process, TTD_ProcessVirtualAddress Start)
{
	ZydisDecoderContext context;
	ZydisDecodedInstruction dinstruction;
	uint8_t instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
	size_t offset = 0;
	TTD_ProcessVirtualAddress end;

	for (;;)
	{
		Process.ReadMemory(Start + offset, instruction, sizeof(instruction));
		ZydisDecoderDecodeInstruction(&Decoder, &context, instruction, sizeof(instruction), &dinstruction);

		if (dinstruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_RET)
		{
			end = Start + offset;
			break;
		}

		offset += dinstruction.length;
	}

	return end;
}

std::vector<TTD_ProcessVirtualAddress> 
GetFunctionCalls(
	TTD_Process& Process, 
	TTD_MemoryModule& Module, 
	TTD_ProcessVirtualAddress Function)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS32 nt32;
	IMAGE_NT_HEADERS64 nt64;
	TTD_ProcessVirtualAddress module_code_base;
	TTD_ProcessVirtualAddress module_base;
	TTD_ProcessVirtualAddress module_end;
	ZydisDecoderContext context;
	ZydisDecodedInstruction dinstruction;
	uint8_t instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
	size_t offset = 0;

	module_base = Module.Base();
	module_end = module_base + Module.Size();

	Process.ReadMemory(module_base, &dos, sizeof(dos));
	Process.ReadMemory(module_base + dos.e_lfanew, &nt32, sizeof(nt32));
	Process.ReadMemory(module_base + dos.e_lfanew, &nt64, sizeof(nt64));

	if (nt32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		module_code_base = module_base + nt32.OptionalHeader.BaseOfCode;
	}
	else if (nt64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		module_code_base = module_base + nt64.OptionalHeader.BaseOfCode;
	}
	else
	{
		throw std::exception("invalid memory module in trace");
	}

	for (;;)
	{
		Process.ReadMemory(module_code_base + offset, instruction, sizeof(instruction));
		ZydisDecoderDecodeInstruction(&Decoder, &context, instruction, sizeof(instruction), &dinstruction);

		if (dinstruction.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
			ZydisDecoderDecodeOperands(&Decoder, &context, &dinstruction, operands, dinstruction.operand_count);
		}

		offset += dinstruction.length;
	}
}
