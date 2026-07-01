#include "pch.h"

#include "Log.h"

#include <stdio.h>
#include <wil/result.h>

namespace AuthLog
{
	static SRWLOCK g_lock = SRWLOCK_INIT;
	static HANDLE g_file = INVALID_HANDLE_VALUE;
	static LONG g_state = 0;
	static LARGE_INTEGER g_freq = {};

	static void WriteRaw(const wchar_t* text, int length)
	{
		if (g_file == INVALID_HANDLE_VALUE || length <= 0)
			return;

		DWORD written = 0;
		WriteFile(g_file, text, static_cast<DWORD>(length) * sizeof(wchar_t), &written, nullptr);
	}

	static void __stdcall OnWilFailure(const wil::FailureInfo& failure) noexcept
	{
		Write(L"[WIL] hr=0x%08X %hs (%hs:%u) %ls",
			failure.hr,
			failure.pszFunction ? failure.pszFunction : "",
			failure.pszFile ? failure.pszFile : "",
			failure.uLineNumber,
			failure.pszMessage ? failure.pszMessage : L"");
	}

	void EnsureInit()
	{
		if (g_state)
			return;

		AcquireSRWLockExclusive(&g_lock);

		if (!g_state)
		{
			QueryPerformanceFrequency(&g_freq);

			g_file = CreateFileW(L"C:\\log.txt", GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);

			if (g_file != INVALID_HANDLE_VALUE)
			{
				WORD bom = 0xFEFF;
				DWORD written = 0;
				WriteFile(g_file, &bom, sizeof(bom), &written, nullptr);
			}

			g_state = 1;

			wil::SetResultLoggingCallback(&OnWilFailure);
		}

		ReleaseSRWLockExclusive(&g_lock);
	}

	void Write(const wchar_t* format, ...)
	{
		EnsureInit();

		wchar_t body[1024];
		va_list args;
		va_start(args, format);
		int bodyLen = _vsnwprintf_s(body, _countof(body), _TRUNCATE, format, args);
		va_end(args);

		if (bodyLen < 0)
			bodyLen = static_cast<int>(wcslen(body));

		SYSTEMTIME st;
		GetLocalTime(&st);

		wchar_t line[1200];
		int lineLen = _snwprintf_s(line, _countof(line), _TRUNCATE, L"[%02u:%02u:%02u.%03u][tid=%u] %s\r\n",
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId(), body);

		if (lineLen < 0)
			lineLen = static_cast<int>(wcslen(line));

		AcquireSRWLockExclusive(&g_lock);
		WriteRaw(line, lineLen);
		ReleaseSRWLockExclusive(&g_lock);
	}

	Scope::Scope(const char* name)
		: m_name(name), m_hr(S_OK), m_thread(GetCurrentThreadId())
	{
		QueryPerformanceCounter(&m_start);
		Write(L">>> %hs", m_name);
	}

	Scope::~Scope()
	{
		LARGE_INTEGER now;
		QueryPerformanceCounter(&now);

		double ms = g_freq.QuadPart ? static_cast<double>(now.QuadPart - m_start.QuadPart) * 1000.0 / g_freq.QuadPart : 0.0;
		Write(L"<<< %hs (hr=0x%08X, %.1f ms)", m_name, m_hr, ms);
	}

	void Scope::SetResult(HRESULT hr)
	{
		m_hr = hr;
	}
}
