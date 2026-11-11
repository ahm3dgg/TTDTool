#include "TTD.hpp"
#include "TTD_FunctionAnalysis.hpp"
#include <cstdio>
#include <windows.h>

int wmain(int argc, wchar_t* argv[])
{
	TTD_Process Process(L"qbot01.run");	

	TTD_AnalyzerInit(PROCESSOR_ARCHITECTURE_INTEL);

	auto kernel32_module = Process.QueryModuleByName(L"KERNELBASE.DLL");
	auto ntdll_module = Process.QueryModuleByName(L"NTDLL.DLL");

	auto pVirtualAlloc = kernel32_module.GetProcAddress("VirtualAlloc");
	auto pRtlAllocateHeap = ntdll_module.GetProcAddress("RtlAllocateHeap");
	
	Process.QueryCalls(
		pVirtualAlloc, 
		[](HookContext& ctx) {}, 
		[](X86_NT5_CONTEXT ctx) {}
	);
}