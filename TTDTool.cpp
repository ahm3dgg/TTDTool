#include <cstdio>
#include "TTD.hpp"
#include <windows.h>

int wmain(int argc, wchar_t* argv[])
{
	TTD_Process Process(L"qbot01.run");
	auto module = Process.QueryModuleByName(L"KERNEL32.DLL");
	auto ntdll_module = Process.QueryModuleByName(L"NTDLL.DLL");
	module.Index();
	ntdll_module.Index();

	auto virtual_alloc_addr = module.GetProcAddress("VirtualAlloc");
	auto pRtlAllocateHeap = ntdll_module.GetProcAddress("RtlAllocateHeap");

	if (static_cast<uint64_t>(virtual_alloc_addr) == 0)
	{
		std::printf("VirtualAlloc not found in KERNEL32.DLL\n");
		return -1;
	}

	Process.InstallHook<uint32_t, uint32_t, uint32_t>(
		pRtlAllocateHeap,
		[](uint32_t HeapHandle, uint32_t Flags, uint32_t Size)
		{
			printf("RtlAllocateHeap(%lx, %lx, %lx)\n", HeapHandle, Flags, Size);
		}
	);

	Process.InstallHook<uint32_t, uint32_t, uint32_t, uint32_t>(virtual_alloc_addr,
		[]
		(
			uint32_t lpAddress,
			uint32_t dwSize,
			uint32_t flAllocationType,
			uint32_t flProtect)

		{
			printf("VirtualAlloc(%lx, %lx, %lx, %lx)\n", lpAddress, dwSize, flAllocationType, flProtect);
		}
	);

	Process.Continue();
}