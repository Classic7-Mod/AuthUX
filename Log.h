#pragma once

#include <windows.h>

namespace AuthLog
{
	void EnsureInit();
	void Write(const wchar_t* format, ...);
	void DumpCredentialProviders();
	void ArmWatchdog(const wchar_t* label, DWORD timeoutMs);
	void DisarmWatchdog();

	class Scope
	{
	public:
		Scope(const char* name);
		~Scope();
		void SetResult(HRESULT hr);

	private:
		const char* m_name;
		HRESULT m_hr;
		DWORD m_thread;
		LARGE_INTEGER m_start;
	};
}

#define LOG_SCOPE() AuthLog::Scope _authScope(__FUNCTION__)
#define LOG_TRACE(...) AuthLog::Write(__VA_ARGS__)
