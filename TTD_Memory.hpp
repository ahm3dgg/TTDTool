#pragma once

#include <TTD/IReplayEngineStl.h>

using namespace TTD;
using namespace TTD::Replay;

struct TTD_MemoryReader
{
	ICursorView& Cursor;

	TTD_MemoryReader(ICursorView& vCursor) : Cursor(vCursor) {};
};

template <typename T>
T ReadGuestValue(const UniqueCursor& Cursor, GuestAddress Address)
{
	T Value;
	Cursor->QueryMemoryBuffer(Address, BufferView{ &Value, sizeof(T) });
	return Value;
}

void ReadGuestBuffer(const UniqueCursor& Cursor, GuestAddress Address, char* Buffer, size_t BufferSize);
void ReadGuestString(const UniqueCursor& Cursor, GuestAddress Address, char* Buffer, size_t BufferCap);