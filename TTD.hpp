#pragma once

#define _TTD_PROCESS_H

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h> 
#include <span>
#include <unordered_map>
#include <functional>
#include <string>
#include <utility>
#include <cstdint>
#include <any>
#include <mutex>
#include "TTD_FunctionAnalysis.hpp"

using namespace TTD;
using namespace TTD::Replay;

using TTD_ProcessVirtualAddress = GuestAddress;
using ReturnFunc32 = std::function<void(X86_NT5_CONTEXT)>;

struct TTD_Process;
struct TTD_MemoryModule;
struct HookContext;

enum class TTD_MemoryWatchInterest
{
	Read = DataAccessMask::Read,
	Write = DataAccessMask::Write,
	Execute = DataAccessMask::Execute,
	CodeFetch = DataAccessMask::CodeFetch,
	Overwrite = DataAccessMask::Overwrite,
	DataMismatch = DataAccessMask::DataMismatch,
	NewData = DataAccessMask::NewData,
	RedundantData = DataAccessMask::RedundantData,
};

enum MemoryProtection
{
	Execute = 0x10,
	ExecuteRead = 0x20,
	ExecuteReadWrite = 0x40,
	ExecuteWriteCopy = 0x80,
	NoAccess = 0x01,
	ReadOnly = 0x02,
	ReadWrite = 0x04,
	WriteCopy = 0x08,
	TargetsInvalid = 0x40000000,
	TargetsNoUpdate = 0x40000000,
	Guard = 0x100,
	NoCache = 0x200,
	WriteCombine = 0x400
};

enum class MachineMode
{
	x86 = 0,
	x64
};

struct MemoryAllocation
{
	Position start;
	Position end;
	TTD_ProcessVirtualAddress source;
	uint64_t preferred_address;
	uint64_t returned_address;
	uint64_t size;
	MemoryProtection protection;
};

struct CallContextId
{
	uint32_t ThreadId;
	TTD_ProcessVirtualAddress RoutineAddress;

	bool operator==(const CallContextId&) const = default;
};

namespace std
{
	template <>
	struct hash<CallContextId>
	{
		size_t operator()(const CallContextId& id) const noexcept
		{
			size_t h1 = std::hash<uint32_t>{}(id.ThreadId);
			size_t h2 = std::hash<uint64_t>{}(static_cast<uint64_t>(id.RoutineAddress));
			return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
		}
	};
}

struct HookContext
{
	uint32_t Arg(size_t i);

	HookContext(TTD_Process* Process, const IThreadView* Thread)
		: m_process(Process), m_thread(Thread) {}

	const IThreadView* Thread();
	TTD_Process* Process();
	std::unordered_map<CallContextId, std::vector<std::any>> call_context;
private:
	TTD_Process* m_process;
	const IThreadView* m_thread;
};

using HookFunc = std::function<void(HookContext&)>;

template <typename F, typename... Args, size_t... I>
void InvokeHook(F& fn, HookContext& ctx, std::index_sequence<I...>)
{
	if constexpr (std::is_invocable_v<F&, HookContext&, Args...>)
		fn(ctx, static_cast<Args>(ctx.Arg(I))...);
	else
		fn(static_cast<Args>(ctx.Arg(I))...);
}

struct TTD_MemoryModule
{
	TTD_MemoryModule() = default;

	TTD_MemoryModule(TTD_Process* Process, const wchar_t* Path, TTD_ProcessVirtualAddress Base, uint64_t Size)
		: m_process(Process), m_path(Path), m_base(Base), m_size(Size) {
	}

	void Index();
	const wchar_t* Path() const;
	const TTD_ProcessVirtualAddress Base() const;
	const uint64_t Size() const;
	TTD_Process* Process() const;
	TTD_ProcessVirtualAddress GetProcAddress(const char* ProcedureName);

private:
	TTD_Process* m_process{};
	const wchar_t* m_path{};
	TTD_ProcessVirtualAddress m_base{};
	uint64_t m_size{};
	std::unordered_map<std::string, TTD_ProcessVirtualAddress> m_exports{};
	bool m_indexed{};
};

struct TTD_Process
{
	TTD_Process(const wchar_t* trace_path);
	TTD_Process(const TTD_Process&) = delete;
	TTD_Process& operator=(const TTD_Process&) = delete;

	void ReadMemory(TTD_ProcessVirtualAddress VirtualAddress, void* Buffer, size_t BufferSize, bool UseThread = false, const IThreadView* Thread = nullptr);
	void ReadString(TTD_ProcessVirtualAddress VirtualAddress, char* Buffer, size_t BufferCap);
	TTD_MemoryModule QueryModuleByName(const wchar_t* ModuleName);
	void WatchMemory(TTD_ProcessVirtualAddress VirtualAddress, TTD_MemoryWatchInterest MemoryWatchInterest, size_t Size);
	void Travel(const TTD::Replay::Position& Position);

	template<typename ...Args, typename F>
	void InstallHook(TTD_ProcessVirtualAddress Address, F fn);

	void Continue();
	void Reset();
	void IndexAllocations();

	uint16_t MachineMode();

	void InsertCallStartContext(TTD_ProcessVirtualAddress Address, uint32_t ThreadId, std::any Context);
	void InsertCall(TTD_ProcessVirtualAddress Routine, uint32_t ThreadId, std::any Context);


	template <typename T>
	T& QueryLastCall(TTD_ProcessVirtualAddress Routine, uint32_t ThreadId)
	{
		std::lock_guard lk(sync);
		CallContextId call_ctx{ ThreadId, Routine };
		T& last = std::any_cast<T&>(m_calls[call_ctx].back());
		return last;
	}

	TTD_ProcessVirtualAddress GetFunctionStartFromEnd(TTD_ProcessVirtualAddress End);
	TTD_ProcessVirtualAddress GetFunctionEndFromStart(TTD_ProcessVirtualAddress Start);

	template<typename T, typename EntryFunc>
	std::vector<T>
	QueryCalls(TTD_ProcessVirtualAddress RoutineAddress, EntryFunc Entry, ReturnFunc32 ReturnFunc);

	std::mutex sync;

private:
	void HookInit();
	bool OnWatchpoint(const ICursorView::MemoryWatchpointResult& Result, const IThreadView* Thread);

	bool m_hook_init = false;
	ICursor* m_cursor;
	IReplayEngine* m_engine;
	
	std::unordered_map<TTD_ProcessVirtualAddress, TTD_ProcessVirtualAddress> m_func_start_end;
	std::unordered_map<TTD_ProcessVirtualAddress, TTD_ProcessVirtualAddress> m_func_end_start;
	std::unordered_map<TTD_ProcessVirtualAddress, HookFunc> m_hooks;
	std::unordered_map<TTD_ProcessVirtualAddress, MemoryAllocation> m_allocations;
	
	std::unordered_map<CallContextId, std::vector<std::any>> m_calls;
};

template<typename ...Args, typename F>
inline void TTD_Process::InstallHook(TTD_ProcessVirtualAddress Address, F fn)
{
	auto hook = [fn](HookContext& ctx) mutable
		{
			InvokeHook<F, Args...>(fn, ctx, std::index_sequence_for<Args...>{});
		};

	m_hooks[Address] = std::move(hook);

	WatchMemory(Address, TTD_MemoryWatchInterest::Execute, 1);
}

template<typename T, typename EntryFunc>
inline std::vector<T> 
TTD_Process::QueryCalls(TTD_ProcessVirtualAddress RoutineAddress, EntryFunc Entry, ReturnFunc32 ReturnFunc)
{
	m_cursor->SetPosition(m_engine->GetFirstPosition());

	auto RoutineEnd = GetFunctionEnd(*this, RoutineAddress);

	std::vector<T> calls;

	InstallHook(
		RoutineAddress,
		Entry	
	);
	
	m_cursor->ReplayForward();

	return calls;
}