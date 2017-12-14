#pragma once

namespace PoC
{
	void CheckIfAllFunctionsAreAvailable();

	class Handle
	{
	public:
		Handle(void* handle = nullptr);
		Handle(Handle&&);
		Handle& operator=(Handle&& other);
		~Handle();

		operator void*() const;
		void** operator&();

	public:
		void* m_handle;
	};

	class Section : public Handle
	{
	public:
		void* GetEntryPoint() const;

		static Section Create(void* hFile);
	};

	class Process : public Handle
	{
	public:
		static Process Create(void* hSection);
	};

	class Thread : public Handle
	{
	public:
		void Resume() const;

		static Thread Create(const wchar_t* path, void* hProcess, void* entryPoint);
	};
}
