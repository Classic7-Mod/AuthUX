#include "pch.h"

#include "Log.h"

#include <stdio.h>
#include <tlhelp32.h>
#include <wil/result.h>

namespace AuthLog
{
	static SRWLOCK g_lock = SRWLOCK_INIT;
	static HANDLE g_file = INVALID_HANDLE_VALUE;
	static LONG g_state = 0;
	static LARGE_INTEGER g_freq = {};

	static HANDLE g_watchdogEvent = nullptr;
	static wchar_t g_watchdogLabel[128] = {};
	static DWORD g_watchdogTimeout = 0;

	typedef BOOL(WINAPI* PFN_MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, DWORD, void*, void*, void*);
	static const DWORD kDumpType = 0x00000000 | 0x00001000;

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

	static void DumpProviderKey(const wchar_t* subkey, const wchar_t* label)
	{
		HKEY key;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
		{
			Write(L"providers[%s]: key not present", label);
			return;
		}

		wchar_t name[256];
		DWORD index = 0;

		for (;;)
		{
			DWORD nameLen = _countof(name);
			if (RegEnumKeyExW(key, index++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
				break;

			wchar_t friendly[256] = L"";
			DWORD friendlyBytes = sizeof(friendly);
			RegGetValueW(key, name, nullptr, RRF_RT_REG_SZ, nullptr, friendly, &friendlyBytes);

			wchar_t clsidPath[320];
			_snwprintf_s(clsidPath, _countof(clsidPath), _TRUNCATE, L"CLSID\\%s\\InprocServer32", name);

			wchar_t dll[MAX_PATH] = L"";
			DWORD dllBytes = sizeof(dll);
			RegGetValueW(HKEY_CLASSES_ROOT, clsidPath, nullptr, RRF_RT_REG_SZ, nullptr, dll, &dllBytes);

			Write(L"providers[%s]: %s name='%s' dll='%s'", label, name, friendly, dll);
		}

		RegCloseKey(key);
	}

	void DumpCredentialProviders()
	{
		DumpProviderKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers", L"PLAP");
		DumpProviderKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers", L"CredProv");
	}

	static void LogLoadedModules()
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
		if (snap == INVALID_HANDLE_VALUE)
			return;

		MODULEENTRY32W me;
		me.dwSize = sizeof(me);

		Write(L"WATCHDOG: loaded modules follow");

		if (Module32FirstW(snap, &me))
		{
			do
			{
				Write(L"  module %s (%s)", me.szModule, me.szExePath);
			} while (Module32NextW(snap, &me));
		}

		CloseHandle(snap);
	}

	static void WriteMiniDump(const wchar_t* reason)
	{
		HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
		if (!dbghelp)
		{
			Write(L"WATCHDOG: dbghelp.dll not available");
			return;
		}

		PFN_MiniDumpWriteDump miniDumpWriteDump = reinterpret_cast<PFN_MiniDumpWriteDump>(GetProcAddress(dbghelp, "MiniDumpWriteDump"));
		if (!miniDumpWriteDump)
		{
			Write(L"WATCHDOG: MiniDumpWriteDump not found");
			FreeLibrary(dbghelp);
			return;
		}

		SYSTEMTIME st;
		GetLocalTime(&st);

		wchar_t path[MAX_PATH];
		_snwprintf_s(path, _countof(path), _TRUNCATE, L"C:\\authux-hang-%02u%02u%02u-%02u%02u%02u.dmp", st.wYear % 100, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

		HANDLE dumpFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (dumpFile == INVALID_HANDLE_VALUE)
		{
			Write(L"WATCHDOG: could not create dump file (err %u)", GetLastError());
			FreeLibrary(dbghelp);
			return;
		}

		BOOL ok = miniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dumpFile, kDumpType, nullptr, nullptr, nullptr);
		Write(L"WATCHDOG: %s dump %s -> %s", reason, ok ? L"written" : L"FAILED", path);

		CloseHandle(dumpFile);
		FreeLibrary(dbghelp);
	}

	static DWORD WINAPI WatchdogProc(void*)
	{
		DWORD result = WaitForSingleObject(g_watchdogEvent, g_watchdogTimeout);
		if (result == WAIT_TIMEOUT)
		{
			Write(L"WATCHDOG: %s did not complete within %u ms; capturing diagnostics", g_watchdogLabel, g_watchdogTimeout);
			DumpCredentialProviders();
			LogLoadedModules();
			WriteMiniDump(g_watchdogLabel);
		}

		return 0;
	}

	void ArmWatchdog(const wchar_t* label, DWORD timeoutMs)
	{
		EnsureInit();

		if (!g_watchdogEvent)
			g_watchdogEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		else
			ResetEvent(g_watchdogEvent);

		wcsncpy_s(g_watchdogLabel, label, _TRUNCATE);
		g_watchdogTimeout = timeoutMs;

		Write(L"WATCHDOG: armed for %s (%u ms)", label, timeoutMs);

		HANDLE thread = CreateThread(nullptr, 0, WatchdogProc, nullptr, 0, nullptr);
		if (thread)
			CloseHandle(thread);
	}

	void DisarmWatchdog()
	{
		if (g_watchdogEvent)
			SetEvent(g_watchdogEvent);
	}
}
