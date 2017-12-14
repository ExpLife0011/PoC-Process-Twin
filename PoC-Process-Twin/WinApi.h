#pragma once
#include <Windows.h>
#include "WinInternals.h"

#ifndef TXFS_MINIVERSION_COMMITTED_VIEW
#define TXFS_MINIVERSION_COMMITTED_VIEW 0x0000
#endif

#ifndef TXFS_MINIVERSION_DIRTY_VIEW
#define TXFS_MINIVERSION_DIRTY_VIEW 0xFFFF
#endif

#ifndef TXFS_MINIVERSION_DEFAULT_VIEW
#define TXFS_MINIVERSION_DEFAULT_VIEW 0xFFFE
#endif

namespace PoC
{
	void CopyFileContent(HANDLE destination, HANDLE source);

	class Transaction : public Handle
	{
	public:
		void Commit();
		void Rollback();

		static Transaction Create();
	};
}
