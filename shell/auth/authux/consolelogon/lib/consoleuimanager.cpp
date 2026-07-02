#include "pch.h"

#include "consoleuimanager.h"

#include "animationstrip.h"
#include "combobox.h"
#include "labeledcheckbox.h"
#include "logonframe.h"
#include "restrictededit.h"
#include "DirectUI/DirectUI.h"
#include "ShellScalingApi.h"
#include "zoomableelement.h"

using namespace Microsoft::WRL;

ConsoleUIManager::ConsoleUIManager()
	: m_UIThreadInitResult(E_FAIL)
{
}

HRESULT ConsoleUIManager::Initialize()
{
	// m_UIThreadQuitEvent = nullptr; // @MOD Don't need this line
	m_UIThreadQuitEvent.reset(CreateEventExW(nullptr, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS));
	return m_UIThreadQuitEvent ? S_OK : ResultFromKnownLastError();
}

HRESULT ConsoleUIManager::StartUI()
{
	auto scopeExit = wil::scope_exit([this]() -> void { StopUI(); });

	Wrappers::SRWLock::SyncLockExclusive lock = m_lock.LockExclusive();

	if (!m_UIThreadHandle)
	{
		wil::unique_handle quitEvent(CreateEventExW(nullptr, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS));
		RETURN_LAST_ERROR_IF_NULL(quitEvent); // 43

		m_UIThreadQuitEvent = std::move(quitEvent);

		RETURN_IF_WIN32_BOOL_FALSE(SHCreateThreadWithHandle(
			s_UIThreadHostThreadProc,
			this,
			CTF_COINIT,
			s_UIThreadHostStartThreadProc,
			&m_UIThreadHandle)); // 52
	}

	scopeExit.release();
	return S_OK;
}

HRESULT ConsoleUIManager::StopUI()
{
	Wrappers::SRWLock::SyncLockExclusive lock = m_lock.LockExclusive();
	if (m_UIThreadHandle)
	{
		SetEvent(m_UIThreadQuitEvent.get());

		DWORD dwIndex = 0;
		CoWaitForMultipleHandles(COWAIT_ALERTABLE | COWAIT_DISPATCH_CALLS | COWAIT_DISPATCH_WINDOW_MESSAGES, INFINITE, 1, m_UIThreadHandle.addressof(), &dwIndex);
		m_UIThreadHandle.reset();

		ResetEvent(m_UIThreadQuitEvent.get());
		m_UIThreadInitResult = E_FAIL;
	}

	return S_OK;
}

HRESULT ConsoleUIManager::EnsureUIStarted()
{
	RETURN_HR_IF(E_ABORT, !m_Dispatcher.Get());
	return S_OK;
}

DWORD ConsoleUIManager::s_UIThreadHostStartThreadProc(void* parameter)
{
	auto pThis = static_cast<ConsoleUIManager*>(parameter);
	pThis->AddRef();
	pThis->UIThreadHostStartThreadProc();
	return 0;
}

HRESULT ConsoleUIManager::UIThreadHostStartThreadProc()
{
	HRESULT hr;
	auto scopeExit = wil::scope_exit([&]() -> void { m_UIThreadInitResult = hr; });

	RETURN_IF_FAILED(hr = MakeNotificationDispatcher<CNotificationDispatcher>(&m_Dispatcher)); // 219

	return S_OK;
}

DWORD ConsoleUIManager::s_UIThreadHostThreadProc(void* parameter)
{
	auto pThis = static_cast<ConsoleUIManager*>(parameter);

	HRESULT hr = S_OK;
	if (SUCCEEDED(pThis->m_UIThreadInitResult))
	{
		hr = pThis->UIThreadHostThreadProc();
	}
	pThis->Release();
	return hr;
}

DWORD ConsoleUIManager::UIThreadHostThreadProc()
{
	DWORD dwIndex = WAIT_IO_COMPLETION;

	HANDLE waitHandles[] = { m_UIThreadQuitEvent.get() };

	SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
	CoInitializeEx(nullptr, 0);
	DirectUI::InitProcessPriv(14, HINST_THISCOMPONENT, false, true, true);

	DirectUI::InitThread(2);
	DirectUI::RegisterAllControls();

	CDUIAnimationStrip::Register();
	CLogonFrame::Register();
	CDUIUserTileElement::Register();
	CDUIZoomableElement::Register();
	CDUIRestrictedEdit::Register();
	CDUIComboBox::Register();
	UserList::Register();
	CDUIFieldContainer::Register();
	CDUILabeledCheckbox::Register();

	CLogonNativeHWNDHost* nativeHWNDHost = nullptr;
	THROW_IF_FAILED(CLogonNativeHWNDHost::Create(0,0,GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN),&nativeHWNDHost));

	CLogonFrame::Create(nativeHWNDHost);

	while (dwIndex == WAIT_IO_COMPLETION)
	{
		MSG Msg {};
		while ( PeekMessageW(&Msg, nullptr, 0, 0, PM_REMOVE) )
		{
			if (Msg.message == WM_QUIT)
			{
				break;
			}

			TranslateMessage(&Msg);
			DispatchMessageW(&Msg);
		}

		CoWaitForMultipleHandles(
			COWAIT_ALERTABLE | COWAIT_INPUTAVAILABLE | COWAIT_DISPATCH_CALLS | COWAIT_DISPATCH_WINDOW_MESSAGES,
			INFINITE, ARRAYSIZE(waitHandles), waitHandles, &dwIndex);
	}

	if (m_Dispatcher.Get())
	{
		ComPtr<IObjectWithBackReferences> objWithBackRefs;
		if (SUCCEEDED(m_Dispatcher.As(&objWithBackRefs)))
		{
			objWithBackRefs->RemoveBackReferences();
		}

		m_Dispatcher.Reset();
	}

	DirectUI::UnInitThread();
	DirectUI::UnInitProcessPriv(HINST_THISCOMPONENT);
	CoUninitialize();

	//FreeConsole();
	return 0;
}
