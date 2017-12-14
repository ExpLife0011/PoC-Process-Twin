#include <stdafx.h>
#include "WinApi.h"

#include <DbgHelp.h>
#include <KtmW32.h>
#pragma comment(lib, "KtmW32.lib")

namespace PoC
{
	void CopyFileContent(HANDLE destination, HANDLE source)
	{
		const auto sourceSize = ::GetFileSize(source, NULL);
		constexpr DWORD bufferSize = 4096;
		BYTE buffer[bufferSize];
		DWORD bytesRead;
		DWORD bytesWritten;
		do
		{
			const auto read = ::ReadFile(
				source,
				buffer,
				bufferSize,
				&bytesRead,
				NULL
			);
			const auto written = ::WriteFile(
				destination,
				buffer,
				bytesRead,
				&bytesWritten,
				NULL
			);

		} while (bytesRead > 0);
	}

	void Transaction::Commit()
	{
		const auto success = ::CommitTransaction(m_handle);
		if (!success)
			throw "Failed to commit transaction";
	}

	void Transaction::Rollback()
	{
		const auto success = ::RollbackTransaction(m_handle);
		if (!success)
			throw "Failed to rollback transaction";
	}

	Transaction Transaction::Create()
	{
		Transaction transaction;
		transaction.m_handle = ::CreateTransaction(
			NULL, // lpTransactionAttributes [in, optional]
			0,    // UOW [in, optional] - Reserved. Must be zero (0).
			0,    // CreateOptions [in, optional] - Any optional hTransaction instructions.
			0,    // IsolationLevel [in, optional] - Reserved; specify zero (0).
			0,    // IsolationFlags [in, optional] - Reserved; specify zero (0).
			0,    // Timeout [in, optional] - Specify zero (0) or INFINITE to provide an infinite time-out.
			NULL  // Description [in, optional] - A user-readable description of the hTransaction.
		);
		return transaction;
	}
}
