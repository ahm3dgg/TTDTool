#pragma once

#include <TTD/IReplayEngineStl.h>
#include <span>
#include <unordered_map>
#include <functional>
#include <string>
#include <utility>
#include <cstdint>

using namespace TTD;
using namespace TTD::Replay;

using TTD_ProcessVirtualAddress = GuestAddress;

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

struct HookContext
{
	uint32_t Arg(size_t i);

	HookContext(TTD_Process* Process, const IThreadView* Thread)
		: m_process(Process), m_thread(Thread) {}
private:
	TTD_Process* m_process;
	const IThreadView* m_thread;
};

using HookFunc = std::function<void(HookContext&)>;

template <typename F, typename ...Args, size_t... I>
void InvokeHook(F& fn, HookContext& ctx, std::index_sequence<I...>)
{
	fn(static_cast<Args>(ctx.Arg((int)I))...);
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

	void ReadMemory(TTD_ProcessVirtualAddress VirtualAddress, void* Buffer, size_t BufferSize, bool UseThread, const IThreadView* Thread);
	void ReadString(TTD_ProcessVirtualAddress VirtualAddress, char* Buffer, size_t BufferCap);
	TTD_MemoryModule QueryModuleByName(const wchar_t* ModuleName);
	void WatchMemory(TTD_ProcessVirtualAddress VirtualAddress, TTD_MemoryWatchInterest MemoryWatchInterest, size_t Size);
	void Travel(const TTD::Replay::Position& Position);

	template<typename ...Args, typename F>
	void InstallHook(TTD_ProcessVirtualAddress Address, F fn);

	void Continue();

private:
	void HookInit();
	bool OnWatchpoint(const ICursorView::MemoryWatchpointResult& Result, const IThreadView* Thread);

	ICursor* m_cursor;
	IReplayEngine* m_engine;
	std::unordered_map<TTD_ProcessVirtualAddress, HookFunc> m_hooks;
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