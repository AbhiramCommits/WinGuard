// ---------------------------------------------------------------------------
// WinGuard ETW consumer — Microsoft-Windows-Kernel-Process image-load events.
//
// A real-time ETW session is started with StartTrace, enabled for the
// Kernel-Process provider and consumed with OpenTrace/ProcessTrace on a
// dedicated thread. Each image-load event is decoded with TDH and handed to the
// managed agent through the wg_image_load_callback registered at start time.
//
// Windows-only; see ../README.md.
// ---------------------------------------------------------------------------

#include "winguard_native.h"

#if defined(_WIN32)

#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <string>
#include <vector>

namespace
{

// Microsoft-Windows-Kernel-Process
const GUID WG_KERNEL_PROCESS_PROVIDER =
    {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

// KERNEL_PROCESS_KEYWORD_IMAGE
const ULONGLONG WG_KERNEL_PROCESS_IMAGE_KEYWORD = 0x40;

// ImageLoad
const USHORT WG_IMAGE_LOAD_EVENT_ID = 5;

struct EtwSession
{
    std::wstring sessionName;
    TRACEHANDLE sessionHandle = 0;
    TRACEHANDLE traceHandle = 0;
    HANDLE traceThread = nullptr;
    wg_image_load_callback callback = nullptr;
    volatile LONG stopRequested = 0;
};

std::vector<BYTE> MakeProperties(const std::wstring& name)
{
    const size_t nameBytes = (name.size() + 1) * sizeof(wchar_t);
    const size_t total = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;

    std::vector<BYTE> buffer(total, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());

    properties->Wnode.BufferSize = static_cast<ULONG>(total);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1; // QPC
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    memcpy(buffer.data() + sizeof(EVENT_TRACE_PROPERTIES), name.c_str(), nameBytes);
    return buffer;
}

// Reads a named property out of a TDH-decoded event.
bool ReadProperty(PEVENT_RECORD record, PTRACE_EVENT_INFO info,
                  const wchar_t* name, PBYTE buffer, ULONG* size)
{
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
    {
        const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
        const wchar_t* propertyName =
            reinterpret_cast<const wchar_t*>(reinterpret_cast<const BYTE*>(info) + property.NameOffset);

        if (_wcsicmp(propertyName, name) != 0)
        {
            continue;
        }

        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
        descriptor.ArrayIndex = ULONG_MAX;

        return TdhGetProperty(record, 0, nullptr, 1, &descriptor, *size, buffer) == ERROR_SUCCESS;
    }

    return false;
}

void WG_CALL OnEvent(PEVENT_RECORD record, EtwSession* session)
{
    if (record == nullptr || record->EventHeader.EventDescriptor.Id != WG_IMAGE_LOAD_EVENT_ID)
    {
        return;
    }

    ULONG infoSize = 0;
    if (TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize) != ERROR_INSUFFICIENT_BUFFER)
    {
        return;
    }

    std::vector<BYTE> infoBuffer(infoSize);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS)
    {
        return;
    }

    WG_ImageLoadEvent evt{};
    evt.pid = record->EventHeader.ProcessId;

    ULONG size = sizeof(ULONGLONG);
    ReadProperty(record, info, L"ImageBase", reinterpret_cast<PBYTE>(&evt.image_base), &size);

    size = sizeof(ULONGLONG);
    ReadProperty(record, info, L"ImageSize", reinterpret_cast<PBYTE>(&evt.image_size), &size);

    size = WG_PATH_CHARS * sizeof(wchar_t);
    ReadProperty(record, info, L"ImageName", reinterpret_cast<PBYTE>(evt.image_path), &size);

    ULONG pidSize = sizeof(uint32_t);
    ReadProperty(record, info, L"ProcessID", reinterpret_cast<PBYTE>(&evt.pid), &pidSize);

    if (session->callback != nullptr)
    {
        session->callback(&evt);
    }
}

VOID WINAPI EventRecordCallback(PEVENT_RECORD record)
{
    auto* session = static_cast<EtwSession*>(record->UserContext);
    if (session != nullptr)
    {
        OnEvent(record, session);
    }
}

DWORD WINAPI ProcessTraceThread(LPVOID parameter)
{
    auto* session = static_cast<EtwSession*>(parameter);
    ProcessTrace(&session->traceHandle, 1, nullptr, nullptr);
    return 0;
}

} // namespace

WG_API int32_t WG_CALL wg_etw_start(const wchar_t* session_name, wg_image_load_callback callback, uint64_t* session_handle)
{
    if (session_name == nullptr || session_handle == nullptr)
    {
        return WG_ERR_FAILURE;
    }

    auto* session = new (std::nothrow) EtwSession();
    if (session == nullptr)
    {
        return WG_ERR_FAILURE;
    }

    session->sessionName = session_name;
    session->callback = callback;

    auto properties = MakeProperties(session->sessionName);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.data());

    // Stop a stale session with the same name before starting a new one.
    ControlTraceW(0, session_name, props, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&session->sessionHandle, session_name, props);
    if (status != ERROR_SUCCESS)
    {
        delete session;
        return WG_ERR_FAILURE;
    }

    status = EnableTraceEx2(
        session->sessionHandle,
        &WG_KERNEL_PROCESS_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        WG_KERNEL_PROCESS_IMAGE_KEYWORD,
        0,
        0,
        nullptr);

    if (status != ERROR_SUCCESS)
    {
        ControlTraceW(session->sessionHandle, session_name, props, EVENT_TRACE_CONTROL_STOP);
        delete session;
        return WG_ERR_FAILURE;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(session->sessionName.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;
    logfile.Context = session;

    session->traceHandle = OpenTraceW(&logfile);
    if (session->traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        ControlTraceW(session->sessionHandle, session_name, props, EVENT_TRACE_CONTROL_STOP);
        delete session;
        return WG_ERR_FAILURE;
    }

    session->traceThread = CreateThread(nullptr, 0, ProcessTraceThread, session, 0, nullptr);
    if (session->traceThread == nullptr)
    {
        CloseTrace(session->traceHandle);
        ControlTraceW(session->sessionHandle, session_name, props, EVENT_TRACE_CONTROL_STOP);
        delete session;
        return WG_ERR_FAILURE;
    }

    *session_handle = reinterpret_cast<uint64_t>(session);
    return WG_OK;
}

WG_API int32_t WG_CALL wg_etw_stop(uint64_t session_handle)
{
    if (session_handle == 0)
    {
        return WG_ERR_FAILURE;
    }

    auto* session = reinterpret_cast<EtwSession*>(session_handle);

    InterlockedExchange(&session->stopRequested, 1);

    auto properties = MakeProperties(session->sessionName);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.data());
    ControlTraceW(session->sessionHandle, session->sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);

    if (session->traceHandle != 0)
    {
        CloseTrace(session->traceHandle);
        session->traceHandle = 0;
    }

    if (session->traceThread != nullptr)
    {
        WaitForSingleObject(session->traceThread, 5000);
        CloseHandle(session->traceThread);
        session->traceThread = nullptr;
    }

    delete session;
    return WG_OK;
}

#endif // _WIN32
