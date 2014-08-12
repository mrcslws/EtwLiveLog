#include "stdafx.h"
#include "EventPayload.h"
#include <in6addr.h>

bool Is32BitEvent(const PEVENT_RECORD pEvent)
{
    return EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER);
}

int GetPointerSize(const PEVENT_RECORD pEvent)
{
    return Is32BitEvent(pEvent) ? 4 : 8;
}

// Everything below is taken from http://msdn.microsoft.com/en-us/library/windows/desktop/ee441329(v=vs.85).aspx
// I'm changing it as needed, but I'm not trying to make it my own.



#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")  // For ntohs function

#define MAX_NAME 256

typedef LPTSTR(NTAPI *PIPV6ADDRTOSTRING)(
    const IN6_ADDR *Addr,
    LPTSTR S
    );

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo);
void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);


DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex)
{
    DWORD status = ERROR_SUCCESS;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
    PBYTE pData = NULL;

    // Get the size of the array if the property is an array.

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; k++)
    {
        wprintf(L"%*s%s: ", (pStructureName) ? 4 : 0, L"", (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));

        // If the property is a structure, print the members of the structure.

        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
            {
                status = PrintProperties(pEvent, pInfo, j, (LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset), k);
                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"Printing the members of the structure failed.");
                    goto cleanup;
                }
            }
        }
        else
        {
            ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));

            // To retrieve a member of a structure, you need to specify an array of descriptors. 
            // The first descriptor in the array identifies the name of the structure and the second 
            // descriptor defines the member of the structure whose data you want to retrieve. 

            if (pStructureName)
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
                DataDescriptors[0].ArrayIndex = StructIndex;
                DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[1].ArrayIndex = k;
                DescriptorsCount = 2;
            }
            else
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[0].ArrayIndex = k;
                DescriptorsCount = 1;
            }

            // The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
            // you will not be able to consume the rest of the event. If you try to consume the
            // remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                wprintf(L"The event contains an IPv6 address. Skipping event.");
                status = ERROR_EVT_INVALID_EVENT_DATA;
                break;
            }
            else
            {
                status = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);

                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"TdhGetPropertySize failed with %lu", status);
                    goto cleanup;
                }

                pData = (PBYTE)malloc(PropertySize);

                if (NULL == pData)
                {
                    wprintf(L"Failed to allocate memory for property data");
                    status = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }

                status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

                // Get the name/value mapping if the property specifies a value map.

                status = GetMapInfo(pEvent,
                    (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                    pInfo->DecodingSource,
                    pMapInfo);

                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"GetMapInfo failed");
                    goto cleanup;
                }

                status = FormatAndPrintData(pEvent,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    pData,
                    PropertySize,
                    pMapInfo
                    );

                if (ERROR_SUCCESS != status)
                {
                    wprintf(L"GetMapInfo failed");
                    goto cleanup;
                }

                if (pData)
                {
                    free(pData);
                    pData = NULL;
                }

                if (pMapInfo)
                {
                    free(pMapInfo);
                    pMapInfo = NULL;
                }
            }
        }
    }

cleanup:

    if (pData)
    {
        free(pData);
        pData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return status;
}


DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo)
{
    UNREFERENCED_PARAMETER(pEvent);

    DWORD status = ERROR_SUCCESS;

    switch (InType)
    {
    case TDH_INTYPE_UNICODESTRING:
    case TDH_INTYPE_COUNTEDSTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
    case TDH_INTYPE_NONNULLTERMINATEDSTRING:
    {
        size_t StringLength = 0;

        if (TDH_INTYPE_COUNTEDSTRING == InType)
        {
            StringLength = *(PUSHORT)pData;
        }
        else if (TDH_INTYPE_REVERSEDCOUNTEDSTRING == InType)
        {
            StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
        }
        else if (TDH_INTYPE_NONNULLTERMINATEDSTRING == InType)
        {
            StringLength = DataSize;
        }
        else
        {
            StringLength = wcslen((LPWSTR)pData);
        }

        wprintf(L"%.*s", StringLength, (LPWSTR)pData);
        break;
    }

    case TDH_INTYPE_ANSISTRING:
    case TDH_INTYPE_COUNTEDANSISTRING:
    case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
    {
        size_t StringLength = 0;

        if (TDH_INTYPE_COUNTEDANSISTRING == InType)
        {
            StringLength = *(PUSHORT)pData;
        }
        else if (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING == InType)
        {
            StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
        }
        else if (TDH_INTYPE_NONNULLTERMINATEDANSISTRING == InType)
        {
            StringLength = DataSize;
        }
        else
        {
            StringLength = strlen((LPSTR)pData);
        }

        wprintf(L"%.*S", StringLength, (LPSTR)pData);
        break;
    }

    case TDH_INTYPE_INT8:
    {
        wprintf(L"%hd", *(PCHAR)pData);
        break;
    }

    case TDH_INTYPE_UINT8:
    {
        if (TDH_OUTTYPE_HEXINT8 == OutType)
        {
            wprintf(L"0x%x", *(PBYTE)pData);
        }
        else
        {
            wprintf(L"%hu", *(PBYTE)pData);
        }

        break;
    }

    case TDH_INTYPE_INT16:
    {
        wprintf(L"%hd", *(PSHORT)pData);
        break;
    }

    case TDH_INTYPE_UINT16:
    {
        if (TDH_OUTTYPE_HEXINT16 == OutType)
        {
            wprintf(L"0x%x", *(PUSHORT)pData);
        }
        else if (TDH_OUTTYPE_PORT == OutType)
        {
            wprintf(L"%hu", ntohs(*(PUSHORT)pData));
        }
        else
        {
            wprintf(L"%hu", *(PUSHORT)pData);
        }

        break;
    }

    case TDH_INTYPE_INT32:
    {
        if (TDH_OUTTYPE_HRESULT == OutType)
        {
            wprintf(L"0x%x", *(PLONG)pData);
        }
        else
        {
            wprintf(L"%d", *(PLONG)pData);
        }

        break;
    }

    case TDH_INTYPE_UINT32:
    {
        if (TDH_OUTTYPE_HRESULT == OutType ||
            TDH_OUTTYPE_WIN32ERROR == OutType ||
            TDH_OUTTYPE_NTSTATUS == OutType ||
            TDH_OUTTYPE_HEXINT32 == OutType)
        {
            wprintf(L"0x%x", *(PULONG)pData);
        }
        else if (TDH_OUTTYPE_IPV4 == OutType)
        {
            wprintf(L"%d.%d.%d.%d", (*(PLONG)pData >> 0) & 0xff,
                (*(PLONG)pData >> 8) & 0xff,
                (*(PLONG)pData >> 16) & 0xff,
                (*(PLONG)pData >> 24) & 0xff);
        }
        else
        {
            if (pMapInfo)
            {
                PrintMapString(pMapInfo, pData);
            }
            else
            {
                wprintf(L"%lu", *(PULONG)pData);
            }
        }

        break;
    }

    case TDH_INTYPE_INT64:
    {
        wprintf(L"%I64d", *(PLONGLONG)pData);

        break;
    }

    case TDH_INTYPE_UINT64:
    {
        if (TDH_OUTTYPE_HEXINT64 == OutType)
        {
            wprintf(L"0x%x", *(PULONGLONG)pData);
        }
        else
        {
            wprintf(L"%I64u", *(PULONGLONG)pData);
        }

        break;
    }

    case TDH_INTYPE_FLOAT:
    {
        wprintf(L"%f", *(PFLOAT)pData);

        break;
    }

    case TDH_INTYPE_DOUBLE:
    {
        wprintf(L"%I64f", *(DOUBLE*)pData);

        break;
    }

    case TDH_INTYPE_BOOLEAN:
    {
        wprintf(L"%s", (0 == (PBOOL)pData) ? L"false" : L"true");

        break;
    }

    case TDH_INTYPE_BINARY:
    {
        if (TDH_OUTTYPE_IPV6 == OutType)
        {
            WCHAR IPv6AddressAsString[46];
            PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

            fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
                GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

            if (NULL == fnRtlIpv6AddressToString)
            {
                wprintf(L"GetProcAddress failed with %lu.", status = GetLastError());
                goto cleanup;
            }

            fnRtlIpv6AddressToString((IN6_ADDR*)pData, IPv6AddressAsString);

            wprintf(L"%s", IPv6AddressAsString);
        }
        else
        {
            for (DWORD i = 0; i < DataSize; i++)
            {
                wprintf(L"%.2x", pData[i]);
            }

            wprintf(L"");
        }

        break;
    }

    case TDH_INTYPE_GUID:
    {
        WCHAR szGuid[50];

        StringFromGUID2(*(GUID*)pData, szGuid, sizeof(szGuid) - 1);
        wprintf(L"%s", szGuid);

        break;
    }

    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
    {
        if (Is32BitEvent(pEvent))
        {
            wprintf(L"0x%x", *(PULONG)pData);
        }
        else
        {
            wprintf(L"0x%x", *(PULONGLONG)pData);
        }

        break;
    }

    case TDH_INTYPE_FILETIME:
    {
        break;
    }

    case TDH_INTYPE_SYSTEMTIME:
    {
        break;
    }

    case TDH_INTYPE_SID:
    {
        WCHAR UserName[MAX_NAME];
        WCHAR DomainName[MAX_NAME];
        DWORD cchUserSize = MAX_NAME;
        DWORD cchDomainSize = MAX_NAME;
        SID_NAME_USE eNameUse;

        if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
        {
            if (ERROR_NONE_MAPPED == status)
            {
                wprintf(L"Unable to locate account for the specified SID");
                status = ERROR_SUCCESS;
            }
            else
            {
                wprintf(L"LookupAccountSid failed with %lu", status = GetLastError());
            }

            goto cleanup;
        }
        else
        {
            wprintf(L"%s\\%s", DomainName, UserName);
        }

        break;
    }

    case TDH_INTYPE_HEXINT32:
    {
        wprintf(L"0x%x", (PULONG)pData);
        break;
    }

    case TDH_INTYPE_HEXINT64:
    {
        wprintf(L"0x%x", (PULONGLONG)pData);
        break;
    }

    case TDH_INTYPE_UNICODECHAR:
    {
        wprintf(L"%c", *(PWCHAR)pData);
        break;
    }

    case TDH_INTYPE_ANSICHAR:
    {
        wprintf(L"%C", *(PCHAR)pData);
        break;
    }

    case TDH_INTYPE_WBEMSID:
    {
        WCHAR UserName[MAX_NAME];
        WCHAR DomainName[MAX_NAME];
        DWORD cchUserSize = MAX_NAME;
        DWORD cchDomainSize = MAX_NAME;
        SID_NAME_USE eNameUse;

        if ((PULONG)pData > 0)
        {
            // A WBEM SID is actually a TOKEN_USER structure followed 
            // by the SID. The size of the TOKEN_USER structure differs 
            // depending on whether the events were generated on a 32-bit 
            // or 64-bit architecture. Also the structure is aligned
            // on an 8-byte boundary, so its size is 8 bytes on a
            // 32-bit computer and 16 bytes on a 64-bit computer.
            // Doubling the pointer size handles both cases.

            pData += GetPointerSize(pEvent) * 2;

            if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
            {
                if (ERROR_NONE_MAPPED == status)
                {
                    wprintf(L"Unable to locate account for the specified SID");
                    status = ERROR_SUCCESS;
                }
                else
                {
                    wprintf(L"LookupAccountSid failed with %lu", status = GetLastError());
                }

                goto cleanup;
            }
            else
            {
                wprintf(L"%s\\%s", DomainName, UserName);
            }
        }

        break;
    }

    default:
        status = ERROR_NOT_FOUND;
    }

cleanup:

    return status;
}


void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData)
{
    BOOL MatchFound = FALSE;

    if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            wprintf(L"%s", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset));
        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
                {
                    wprintf(L"%s", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
                    MatchFound = TRUE;
                    break;
                }
            }

            if (FALSE == MatchFound)
            {
                wprintf(L"%lu", *(PULONG)pData);
            }
        }
    }
    else if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP ||
        (pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP) == EVENTMAP_INFO_FLAG_WBEM_BITMAP ||
        ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
        (pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
    {
        if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
        {
            DWORD BitPosition = 0;

            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((*(PULONG)pData & (BitPosition = (1 << i))) == BitPosition)
                {
                    wprintf(L"%s%s",
                        (MatchFound) ? L" | " : L"",
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }

        }
        else
        {
            for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
            {
                if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
                {
                    wprintf(L"%s%s",
                        (MatchFound) ? L" | " : L"",
                        (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

                    MatchFound = TRUE;
                }
            }
        }

        if (MatchFound)
        {
            wprintf(L"");
        }
        else
        {
            wprintf(L"%lu", *(PULONG)pData);
        }
    }
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}


// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
        if (pMapInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for map info (size=%lu).", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the map info.

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else
    {
        if (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            wprintf(L"TdhGetEventMapInformation failed with 0x%x.", status);
        }
    }

cleanup:

    return status;
}


// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    SIZE_T ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}

