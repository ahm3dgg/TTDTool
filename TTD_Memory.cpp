#include "TTD_Memory.hpp"

void ReadGuestBuffer(const UniqueCursor& Cursor, GuestAddress Address, char* Buffer, size_t BufferSize)
{
	Cursor->QueryMemoryBuffer(Address, BufferView{ Buffer, BufferSize });
}

void ReadGuestString(const UniqueCursor& Cursor, GuestAddress Address, char* Buffer, size_t BufferCap)
{
	for (size_t i = 0; i < BufferCap; i++)
	{
		Cursor->QueryMemoryBuffer(Address + i, BufferView{ &Buffer[i], sizeof(char) });

		if (Buffer[i] == '\x00')
		{
			break;
		}
	}
}