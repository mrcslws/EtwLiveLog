#include "stdafx.h"
#include "EventPayload.h"

#define USAGE L"Usage:\r\n EtwLiveLog.exe [RealtimeSessionName]\r\n\r\nUse a different tool like xperf.exe to start a realtime session, then consume it from here."

static bool _s_fIsEnding = false;
static bool _s_fIsClosed = false;

static void WINAPI _HandleEvent(_In_ PEVENT_RECORD per);

int __cdecl wmain(int argc, wchar_t* argv[])
{
    bool fPrintUsage = true;
    if (argc == 2)
    {
        if (!SetConsoleCtrlHandler([](_In_ DWORD) {
            _s_fIsEnding = true;
            return TRUE;
        }, TRUE /*Add*/))
        {
            wprintf(L"Erm, looks like ctrl+c isn't going to exit cleanly.");
        }

        TRACEHANDLE hTrace = 0;

        // Open the session
        EVENT_TRACE_LOGFILE etlTrace = { 0 };
        etlTrace.LoggerName = argv[1];
        etlTrace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        etlTrace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)&_HandleEvent;
        etlTrace.Context = &hTrace;

        hTrace = OpenTrace(&etlTrace);
        if (hTrace != INVALID_PROCESSTRACE_HANDLE)
        {
            TRACEHANDLE rghTrace[] = { hTrace };
            ULONG ulProcessTrace = ProcessTrace(rghTrace, ARRAYSIZE(rghTrace), nullptr, nullptr);
            if (ulProcessTrace == ERROR_SUCCESS)
            {
                fPrintUsage = false;
            }
            else
            {
                wprintf(L"ProcessTrace failed. (%u)\r\n", ulProcessTrace);
            }

            if (!_s_fIsClosed)
            {
                CloseTrace(hTrace);
                _s_fIsClosed = true;
            }
        }
        else
        {
            wprintf(L"OpenTrace failed.\r\n");
        }
    }

    if (fPrintUsage)
    {
        wprintf(USAGE);
    }
}

static void WINAPI _HandleEvent(_In_ PEVENT_RECORD per)
{
    if (!_s_fIsEnding)
    {
        PTRACE_EVENT_INFO ptei = nullptr;

        // Populate ptei.
        {
            DWORD cbEventInfo = 0;
            DWORD status = TdhGetEventInformation(per, 0, nullptr, nullptr, &cbEventInfo);
            if (ERROR_INSUFFICIENT_BUFFER == status)
            {
                ptei = (TRACE_EVENT_INFO*)malloc(cbEventInfo);
                if (ptei != nullptr)
                {
                    status = TdhGetEventInformation(per, 0, nullptr, ptei, &cbEventInfo);
                    if (status != ERROR_SUCCESS)
                    {
                        free(ptei);
                        ptei = nullptr;
                    }
                }
            }
        }

        // Timestamp
        {
            FILETIME ft;
            ft.dwHighDateTime = per->EventHeader.TimeStamp.HighPart;
            ft.dwLowDateTime = per->EventHeader.TimeStamp.LowPart;
            SYSTEMTIME st;
            FileTimeToSystemTime(&ft, &st);
            SystemTimeToTzSpecificLocalTime(nullptr, &st, &st);
            wchar_t wszDate[100];
            GetDateFormatEx(LOCALE_NAME_INVARIANT, NULL, &st, L"yyyyy-MM-dd", wszDate, ARRAYSIZE(wszDate), nullptr);
            wchar_t wszTime[100];
            GetTimeFormatEx(LOCALE_NAME_INVARIANT, NULL, &st, L"HH:mm:ss", wszTime, ARRAYSIZE(wszTime));

            // yyyy-MM-dd HH:mm:ss:fffffff
            // Windows refuses to give us milliseconds for free, let alone fractions of milliseconds
            wprintf(L"%s ", wszDate);
            wprintf(L"%s", wszTime);
            wprintf(L".%07u, ", ft.dwLowDateTime % ((1000000000 /*nanoseconds per second*/) / (100 /* nanoseconds per interval */)));
        }

        // Thread ID
        wprintf(L"Thread %lu, ", per->EventHeader.ThreadId);

        // Provider name or GUID
        {
            const wchar_t* providerName = ptei ? TEI_PROVIDER_NAME(ptei) : nullptr;
            if (providerName != nullptr)
            {
                wprintf(L"%s, ", (BYTE*)ptei + ptei->ProviderNameOffset);
            }
            else
            {
                BSTR bstrGuid;
                if (SUCCEEDED(StringFromCLSID(per->EventHeader.ProviderId, &bstrGuid)))
                {
                    wprintf(L"%s, ", bstrGuid);
                    ::CoTaskMemFree(bstrGuid);
                }
            }
        }

        // Task name or id
        {
            const wchar_t* taskName = ptei ? TEI_TASK_NAME(ptei) : nullptr;
            if (taskName != nullptr)
            {
                wprintf(L"%s, ", taskName);
            }
            else
            {
                // printf converts 8-bit chars to 16-bit ints, in case you don't know
                wprintf(L"%hu, ", per->EventHeader.EventDescriptor.Task);
            }
        }

        // Event ID
        // wprintf(L"%hu, ", per->EventHeader.EventDescriptor.Id);

        // Activity ID
        //{
        //    BSTR bstrGuid;
        //    if (SUCCEEDED(StringFromCLSID(per->EventHeader.ActivityId, &bstrGuid)))
        //    {
        //        wprintf(L"%s, ", bstrGuid);
        //        ::CoTaskMemFree(bstrGuid);
        //    }
        //}

        // Opcode name or ID
        {
            wchar_t* opcodeName = ptei ? TEI_OPCODE_NAME(ptei) : nullptr;
            if (opcodeName != nullptr)
            {
                wprintf(L"%s, ", (BYTE*)ptei + ptei->OpcodeNameOffset);
            }
            else
            {
                wprintf(L"%hu, ", per->EventHeader.EventDescriptor.Opcode);
            }
        }

        // Payload
        if (EVENT_HEADER_FLAG_STRING_ONLY == (per->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
        {
            wprintf(L"%s", (LPWSTR)per->UserData);
        }
        else
        {
            for (USHORT i = 0; i < ptei->TopLevelPropertyCount; i++)
            {
                DWORD status = PrintProperties(per, ptei, i, nullptr, 0);
                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"Printing top level properties failed.");
                }

                wprintf(L", ");
            }
        }

        // endl
        wprintf(L"\r\n");

        // combat stdout buffering
        _flushall();

        if (ptei != nullptr)
        {
            free(ptei);
            ptei = nullptr;
        }
    }
    else
    {
        if (!_s_fIsClosed)
        {
            CloseTrace(*((TRACEHANDLE*)per->UserContext));
            _s_fIsClosed = true;
        }
    }
}
