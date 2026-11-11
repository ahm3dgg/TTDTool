#include "TTD.hpp"
#include <Windows.h>
#include <cwchar>
#include <cstring>

TTD_Process::TTD_Process(const wchar_t* trace_path)
{
	auto result = CreateReplayEngine(m_engine, __uuidof(IReplayEngineView));

	if (result != 0)
	{
		throw std::exception("failed to create replay engine");
	}

	if (!m_engine->Initialize(trace_path))
	{
		throw std::exception("failed to open trace");
	}

	m_cursor = m_engine->NewCursor();
	m_cursor->SetPosition(m_engine->GetFirstPosition());

	HookInit();
}

void TTD_Process::ReadMemory(
	TTD_ProcessVirtualAddress VirtualAddress, 
	void* Buffer, 
	size_t BufferSize, 
	bool UseThread, 
	const IThreadView* Thread)
{
	if (UseThread)
	{
		Thread->QueryMemoryBuffer(static_cast<GuestAddress>(VirtualAddress), BufferView{ Buffer, BufferSize });
	}
	else
	{
		m_cursor->QueryMemoryBuffer(static_cast<GuestAddress>(VirtualAddress), BufferView{ Buffer, BufferSize });
	}
}

void TTD_Process::ReadString(TTD_ProcessVirtualAddress VirtualAddress, char* Buffer, size_t BufferCap)
{
	std::memset(Buffer, 0, BufferCap);

	for (size_t i = 0; i + 1 < BufferCap; i++)
	{
		m_cursor->QueryMemoryBuffer(static_cast<GuestAddress>(VirtualAddress + i), BufferView{ &Buffer[i], sizeof(char) });

		if (Buffer[i] == '\x00')
		{
			break;
		}
	}
}

TTD_MemoryModule TTD_Process::QueryModuleByName(const wchar_t* ModuleName)
{
	for (const auto& module :
		std::span<const Module>(m_engine->GetModuleList(), m_engine->GetModuleCount()))
	{
		if (!module.pName)
		{
			continue;
		}

		const wchar_t* module_name = wcsrchr(module.pName, L'\\');
		module_name = module_name ? module_name + 1 : module.pName;

		if (!_wcsicmp(module_name, ModuleName))
		{
			return  { this, module.pName, static_cast<TTD_ProcessVirtualAddress>(module.Address), module.Size };
		}
	}

	return {};
}

void TTD_Process::WatchMemory(
	TTD_ProcessVirtualAddress VirtualAddress,
	TTD_MemoryWatchInterest MemoryWatchInterest,
	size_t Size)
{
	m_cursor->AddMemoryWatchpoint(MemoryWatchpointData{
		static_cast<GuestAddress>(VirtualAddress),
		Size,
		DataAccessMask(MemoryWatchInterest)
		});
}

void TTD_Process::HookInit()
{
	m_cursor->SetMemoryWatchpointCallback(
		[](uintptr_t context, const ICursorView::MemoryWatchpointResult& Result, const IThreadView* Thread) -> bool
		{
			return reinterpret_cast<TTD_Process*>(context)->OnWatchpoint(Result, Thread);
		},
		reinterpret_cast<uintptr_t>(this));

	m_cursor->SetEventMask(EventMask::MemoryWatchpoint);
	m_hook_init = true;
}

bool TTD_Process::OnWatchpoint(const ICursorView::MemoryWatchpointResult& Result, const IThreadView* Thread)
{
	auto it = m_hooks.find(static_cast<TTD_ProcessVirtualAddress>(Result.Address));

	if (it != m_hooks.end())
	{
		HookContext ctx{this, Thread };
		it->second(ctx);
	}

	return false;
}

void TTD_Process::Travel(const TTD::Replay::Position& Position)
{
	m_cursor->SetPosition(Position);
}

void TTD_Process::Continue()
{
	m_cursor->ReplayForward();
}

void TTD_Process::Reset()
{
	m_cursor->SetPosition(m_engine->GetFirstPosition());
}

void TTD_Process::IndexAllocations()
{
	m_cursor->SetPosition(m_engine->GetFirstPosition());

	auto kernel32_module = QueryModuleByName(L"KERNELBASE.DLL");
	auto ntdll_module = QueryModuleByName(L"NTDLL.DLL");

	auto pVirtualAlloc = kernel32_module.GetProcAddress("VirtualAlloc");
	auto pRtlAllocateHeap = ntdll_module.GetProcAddress("RtlAllocateHeap");

	auto pVirtualAlloc_End = GetFunctionEnd(*this, pVirtualAlloc);
	auto pRtlAllocateHeap_End = GetFunctionEnd(*this, pRtlAllocateHeap);
	
    m_func_start_end[pVirtualAlloc] = pVirtualAlloc_End;
    m_func_end_start[pVirtualAlloc_End] = pVirtualAlloc;

    m_func_start_end[pRtlAllocateHeap] = pRtlAllocateHeap_End;
    m_func_end_start[pRtlAllocateHeap_End] = pRtlAllocateHeap;

    InstallHook<uint32_t, uint32_t, uint32_t>(
		pRtlAllocateHeap,
		[=](HookContext& ctx, uint32_t HeapHandle, uint32_t Flags, uint32_t Size) {
            auto thread = ctx.Thread();
            auto thread_id = uint32_t(thread->GetThreadInfo().UniqueId);
            auto proc = ctx.Process();
			puts("RtlAllocateHeap Start.");

            auto memalloc = MemoryAllocation{};
            memalloc.start = thread->GetPosition();
            memalloc.protection = MemoryProtection::ReadWrite;
            memalloc.size = Size;
            memalloc.source = pRtlAllocateHeap;

			InsertCall(pRtlAllocateHeap, thread_id, memalloc);
        }
	);

	InstallHook<uint32_t, uint32_t, uint32_t, uint32_t>(pVirtualAlloc,
		[=](HookContext& ctx, uint32_t lpAddress, uint32_t dwSize,
			uint32_t flAllocationType, uint32_t flProtect) {
			auto thread = ctx.Thread();
            auto thread_id = uint32_t(thread->GetThreadInfo().UniqueId);
            auto proc = ctx.Process();

			puts("VirtualAlloc Start.");

            auto memalloc = MemoryAllocation{};
            memalloc.start = thread->GetPosition();
            memalloc.preferred_address = lpAddress;
            memalloc.protection = MemoryProtection(flProtect);
            memalloc.size = dwSize;
            memalloc.source = pVirtualAlloc;

			InsertCall(pVirtualAlloc, thread_id, memalloc);
		});

	InstallHook(pVirtualAlloc_End, [=](HookContext& ctx) {
		auto thread = ctx.Thread();
		auto pctx = thread->GetCrossPlatformContext();
		auto regs = reinterpret_cast<X86_NT5_CONTEXT*>(&pctx);
        auto thread_id = uint32_t(thread->GetThreadInfo().UniqueId);

		puts("VirtualAlloc End.");
		
		auto routine = m_func_end_start[pVirtualAlloc_End];
		auto memalloc = QueryLastCall<MemoryAllocation>(routine, thread_id);
		memalloc.returned_address = regs->Eax;
		memalloc.end = thread->GetPosition();
	});

	InstallHook(pRtlAllocateHeap_End, [=](HookContext& ctx) {
		auto thread = ctx.Thread();
		auto pctx = thread->GetCrossPlatformContext();
		auto regs = reinterpret_cast<X86_NT5_CONTEXT*>(&pctx);
        auto thread_id = uint32_t(thread->GetThreadInfo().UniqueId);

		puts("RtlAllocateHeap End.");

		auto routine = m_func_end_start[pRtlAllocateHeap_End];
		auto memalloc = QueryLastCall<MemoryAllocation>(routine, thread_id);
		memalloc.returned_address = regs->Eax;
		memalloc.end = thread->GetPosition();
    });

	m_cursor->ReplayForward();
}

void TTD_Process::InsertCall(TTD_ProcessVirtualAddress Routine, uint32_t ThreadId, std::any Context)
{
    std::lock_guard lk(sync);
    
    CallContextId call_ctx { ThreadId, Routine };
    m_calls[call_ctx].push_back(Context);
}

TTD_ProcessVirtualAddress 
TTD_Process::GetFunctionStartFromEnd(TTD_ProcessVirtualAddress End)
{
    return m_func_end_start[End];
}

TTD_ProcessVirtualAddress 
TTD_Process::GetFunctionEndFromStart(TTD_ProcessVirtualAddress Start)
{
    return m_func_start_end[Start];
}

uint16_t TTD_Process::MachineMode()
{
	return m_engine->GetSystemInfo().System.ProcessorArchitecture;
}

void TTD_MemoryModule::Index()
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS32 nt32;
	IMAGE_NT_HEADERS64 nt64;
	IMAGE_EXPORT_DIRECTORY export_dir;
	uint32_t export_dir_rva;

	m_process->ReadMemory(m_base, &dos, sizeof(dos));
	m_process->ReadMemory(m_base + dos.e_lfanew, &nt32, sizeof(nt32));
	m_process->ReadMemory(m_base + dos.e_lfanew, &nt64, sizeof(nt64));

	if (nt32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		export_dir_rva = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if (nt64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		export_dir_rva = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		throw std::exception("invalid memory module in trace");
	}

	m_process->ReadMemory(m_base + export_dir_rva, &export_dir, sizeof(export_dir));

	char export_name[256] = { 0 };
	for (size_t i = 0; i < export_dir.NumberOfNames; i++)
	{
		uint32_t export_name_rva;

		m_process->ReadMemory(
			m_base + export_dir.AddressOfNames + i * sizeof(uint32_t),
			&export_name_rva,
			sizeof(export_name_rva)
		);

		m_process->ReadString(m_base + export_name_rva, export_name, sizeof(export_name));

		uint16_t export_ordinal;
		uint32_t export_rva;

		m_process->ReadMemory(
			m_base + export_dir.AddressOfNameOrdinals + i * sizeof(uint16_t),
			&export_ordinal,
			sizeof(export_ordinal)
		);

		m_process->ReadMemory(
			m_base + export_dir.AddressOfFunctions + export_ordinal * sizeof(uint32_t),
			&export_rva,
			sizeof(export_rva)
		);

		m_exports[std::string(export_name)] = m_base + export_rva;
	}

	m_indexed = true;
}

const wchar_t* TTD_MemoryModule::Path() const
{
	return m_path;
}

const TTD_ProcessVirtualAddress TTD_MemoryModule::Base() const
{
	return m_base;
}

const uint64_t TTD_MemoryModule::Size() const
{
	return m_size;
}

TTD_Process* TTD_MemoryModule::Process() const
{
	return m_process;
}

TTD_ProcessVirtualAddress TTD_MemoryModule::GetProcAddress(const char* ProcedureName)
{
	if (m_indexed)
	{
		auto it = m_exports.find(ProcedureName);
		return it != m_exports.end() ? it->second : TTD_ProcessVirtualAddress{};
	}

	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS32 nt32;
	IMAGE_NT_HEADERS64 nt64;
	IMAGE_EXPORT_DIRECTORY export_dir;
	uint32_t export_dir_rva;

	m_process->ReadMemory(m_base, &dos, sizeof(dos));
	m_process->ReadMemory(m_base + dos.e_lfanew, &nt32, sizeof(nt32));
	m_process->ReadMemory(m_base + dos.e_lfanew, &nt64, sizeof(nt64));

	if (nt32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		export_dir_rva = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if (nt64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		export_dir_rva = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		throw std::exception("invalid memory module in trace");
	}

	m_process->ReadMemory(m_base + export_dir_rva, &export_dir, sizeof(export_dir));

	char export_name[256] = { 0 };
	for (size_t i = 0; i < export_dir.NumberOfNames; i++)
	{
		uint32_t export_name_rva;

		m_process->ReadMemory(
			m_base + export_dir.AddressOfNames + i * sizeof(uint32_t),
			&export_name_rva,
			sizeof(export_name_rva)
		);

		m_process->ReadString(m_base + export_name_rva, export_name, sizeof(export_name));

		if (!strcmp(export_name, ProcedureName))
		{
			uint16_t export_ordinal;
			uint32_t export_rva;

			m_process->ReadMemory(
				m_base + export_dir.AddressOfNameOrdinals + i * sizeof(uint16_t),
				&export_ordinal,
				sizeof(export_ordinal)
			);

			m_process->ReadMemory(
				m_base + export_dir.AddressOfFunctions + export_ordinal * sizeof(uint32_t),
				&export_rva,
				sizeof(export_rva)
			);

			return m_base + export_rva;
		}
	}

	return {};
}

uint32_t HookContext::Arg(size_t i)
{
	uint32_t value = 0;

	m_process->ReadMemory(
		static_cast<TTD_ProcessVirtualAddress>(m_thread->GetStackPointer() + 4 + i * 4),
		&value, 
		sizeof(value),
		true,
		m_thread
	);

	return value;
}

const IThreadView* HookContext::Thread()
{
	return m_thread;
}

TTD_Process* HookContext::Process()
{
    return m_process;
}