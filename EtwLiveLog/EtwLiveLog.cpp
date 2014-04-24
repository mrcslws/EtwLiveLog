#include "stdafx.h"

#define SESSION_NAME L"MarcusRealtime";

static bool _s_fIsEnding = false;
static bool _s_fIsClosed = false;

int _tmain(int argc, _TCHAR* argv[])
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
	etlTrace.LoggerName = SESSION_NAME;
	etlTrace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	etlTrace.EventRecordCallback = [](_In_ PEVENT_RECORD per) {
		if (!_s_fIsEnding)
		{
			BSTR bstrGuid;
			if (SUCCEEDED(StringFromCLSID(per->EventHeader.ProviderId, &bstrGuid)))
			{
				wprintf(L"%llu, %hu, %hu, %s, %hhu\r\n",
					per->EventHeader.TimeStamp,
					per->EventHeader.EventDescriptor.Id,
					per->EventHeader.EventDescriptor.Task,
					bstrGuid,
					per->EventHeader.EventDescriptor.Opcode);

				::CoTaskMemFree(bstrGuid);
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
	};
	etlTrace.Context = &hTrace;

	hTrace = OpenTrace(&etlTrace);
	TRACEHANDLE rghTrace[] = { hTrace };
	if (hTrace != INVALID_PROCESSTRACE_HANDLE)
	{
		TRACEHANDLE rghTrace[] = { hTrace };
		ULONG ulProcessTrace = ProcessTrace(rghTrace, ARRAYSIZE(rghTrace), nullptr, nullptr);
		if (ulProcessTrace != ERROR_SUCCESS)
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
