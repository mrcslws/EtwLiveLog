#include "stdafx.h"

#define USAGE L"Usage:\r\n EtwLiveLog.exe [RealtimeSessionName]\r\n\r\nUse a different tool like xperf.exe to start a realtime session, then consume it from here."

static bool _s_fIsEnding = false;
static bool _s_fIsClosed = false;

static void WINAPI _HandleEvent(_In_ PEVENT_RECORD per);

int _tmain(int argc, _TCHAR* argv[])
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
		TRACEHANDLE rghTrace[] = { hTrace };
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
		DWORD cbEventInfo = 0;
		DWORD status = TdhGetEventInformation(per, 0, nullptr, nullptr, &cbEventInfo);
		if (ERROR_INSUFFICIENT_BUFFER == status)
		{
			PTRACE_EVENT_INFO ptei = (TRACE_EVENT_INFO*)malloc(cbEventInfo);
			if (ptei != nullptr)
			{
				status = TdhGetEventInformation(per, 0, nullptr, ptei, &cbEventInfo);

				if (status == ERROR_SUCCESS)
				{
					// Timestamp
					{
						FILETIME ft;
						ft.dwHighDateTime = per->EventHeader.TimeStamp.HighPart;
						ft.dwLowDateTime = per->EventHeader.TimeStamp.LowPart;
						SYSTEMTIME st;
						FileTimeToSystemTime(&ft, &st);
						wchar_t wszDate[100] = { 0 };
						GetDateFormatEx(LOCALE_NAME_INVARIANT, NULL, &st, L"yyyyy-MM-dd", wszDate, ARRAYSIZE(wszDate), nullptr);
						wchar_t wszTime[100] = { 0 };
						GetTimeFormatEx(LOCALE_NAME_INVARIANT, NULL, &st, L"HH:mm:ss", wszTime, ARRAYSIZE(wszTime));

						// yyyy-MM-dd HH:mm:ss:fff
						// Windows refuses to give us milliseconds for free, let alone fractions of milliseconds
						wprintf(L"%s ", wszDate);
						wprintf(L"%s", wszTime);
						wprintf(L".%03hu, ", st.wMilliseconds);
					}

					// Provider name or GUID
					if (ptei->ProviderNameOffset != 0)
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

					// Task name or id
					if (ptei->TaskNameOffset != 0)
					{
						wprintf(L"%s, ", (BYTE*)ptei + ptei->TaskNameOffset);
					}
					else
					{
						// printf converts 8-bit chars to 16-bit ints, in case you don't know
						wprintf(L"%hu, ", per->EventHeader.EventDescriptor.Task);
					}

					// Event ID
					wprintf(L"%hu, ", per->EventHeader.EventDescriptor.Id);

					// Opcode name or ID
					if (ptei->OpcodeNameOffset != 0)
					{
						wprintf(L"%s", (BYTE*)ptei + ptei->OpcodeNameOffset);
					}
					else
					{
						wprintf(L"%hu", per->EventHeader.EventDescriptor.Opcode);
					}

					// endl
					wprintf(L"\n");
				}

				free(ptei);
			}
			else
			{
				status = ERROR_OUTOFMEMORY;
			}
		}

		if (ERROR_SUCCESS != status)
		{
			wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
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
