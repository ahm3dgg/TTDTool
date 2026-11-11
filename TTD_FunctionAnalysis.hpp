#pragma once

#include <Zydis/Zydis.h>
#include <vector>
#include "TTD_Types.hpp"

struct TTD_Process;
struct TTD_MemoryModule;

void TTD_AnalyzerInit(uint16_t MachineMode);

TTD_ProcessVirtualAddress
GetFunctionEnd(TTD_Process& Process, TTD_ProcessVirtualAddress Start);

std::vector<TTD_ProcessVirtualAddress>
GetFunctionCalls(TTD_Process& Process, TTD_ProcessVirtualAddress Function);