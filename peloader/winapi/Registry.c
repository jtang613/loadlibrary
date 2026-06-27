#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_MORE_DATA 234


typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataLength;
  UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

STATIC LONG WINAPI RegOpenKeyExW(HANDLE hKey, PVOID lpSubKey, DWORD ulOptions, DWORD samDesired, PHANDLE phkResult)
{
    LONG Result = -1;
    char *ansikey = CreateAnsiFromWide(lpSubKey);

    DebugLog("%p, %p [%s], %#x, %#x, %p", hKey, lpSubKey, ansikey, ulOptions, samDesired, phkResult);

    if (strstr(ansikey, "Explorer\\Shell Folders")) {
        *phkResult = (HANDLE) 'REG0';
        Result = 0;
    } else if (strstr(ansikey, "Explorer\\User Shell Folders")) {
        *phkResult = (HANDLE) 'REG1';
        Result = 0;
    } else if (strstr(ansikey, "ProfileList")) {
        *phkResult = (HANDLE) 'REG2';
        Result = 0;
    } else if (strstr(ansikey, "DataCollection")) {
        *phkResult = (HANDLE) 'REG3';
        Result = 0;
    } else if (strstr(ansikey, "Windows Defender")
            || strstr(ansikey, "Microsoft Antimalware")
            || strstr(ansikey, "Defender")) {
        *phkResult = (HANDLE) 'REG4';
        Result = 0;
    }
    free(ansikey);
    return Result;
}

STATIC LONG WINAPI RegCloseKey(HANDLE hKey)
{
    DebugLog("%p");
    return 0;
}

STATIC LONG WINAPI RegQueryInfoKeyW(
  HANDLE   hKey,
  PWCHAR   lpClass,
  PDWORD   lpcClass,
  PDWORD   lpReserved,
  PDWORD   lpcSubKeys,
  PDWORD   lpcMaxSubKeyLen,
  PDWORD   lpcMaxClassLen,
  PDWORD   lpcValues,
  PDWORD   lpcMaxValueNameLen,
  PDWORD   lpcMaxValueLen,
  PDWORD   lpcbSecurityDescriptor,
  PVOID    lpftLastWriteTime)
{
    DebugLog("");

    if (lpClass || lpcClass || lpReserved || lpcSubKeys || lpcMaxSubKeyLen || lpcMaxClassLen || lpcMaxValueLen || lpcbSecurityDescriptor || lpftLastWriteTime) {
        DebugLog("NOT SUPPORTED");
        return -1;
    }

    switch ((DWORD) hKey) {
        case 'REG0':
        case 'REG1':
        case 'REG2':
            *lpcValues = 1;
            *lpcMaxValueNameLen = 1024;
            break;
        default:
            DebugLog("NOT SUPPROTED KEY");
            return -1;
    }

    return 0;
}

STATIC NTSTATUS WINAPI NtEnumerateValueKey(
  HANDLE                      KeyHandle,
  ULONG                       Index,
  DWORD                       KeyValueInformationClass,
  PKEY_VALUE_BASIC_INFORMATION KeyValueInformation,
  ULONG                       Length,
  PULONG                      ResultLength
) {
    DebugLog("%p, %u, %u, %p, %u, %p", KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    if (KeyValueInformationClass != 0) {
        DebugLog("NOT SUPPORTED");
        return -1;
    }

    switch ((DWORD) KeyHandle) {
        case 'REG1':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        case 'REG0':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        case 'REG2':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        default:
            DebugLog("NOT SUPPROTED KEY");
            return -1;
    }

    return 0;
}

STATIC NTSTATUS WINAPI NtQueryValueKey(
 HANDLE                      KeyHandle,
 PVOID                       ValueName,
 DWORD                       KeyValueInformationClass,
 PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation,
 ULONG                       Length,
 PULONG                      ResultLength
)
{
    DebugLog("%p, %p, %u, %u, %u, %p", KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    if (KeyValueInformationClass != 2) {
        DebugLog("NOT SUPPROTED");
        return -1;
    }

    switch ((DWORD) KeyHandle) {
        case 'REG1':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        case 'REG0':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        case 'REG2':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        default:
            DebugLog("NOT SUPPORTED KEY");
            return -1;
    }

    return 0;
}

STATIC LONG WINAPI RegCreateKeyExW(HANDLE hKey, PVOID lpSubKey, DWORD Reserved, PVOID lpClass, DWORD dwOptions, PVOID samDesired, PVOID lpSecurityAttributes, PVOID phkResult, PDWORD lpdwDisposition)
{
    DebugLog("%p, %p, %#x, %p, %#x, %p, %p, %p, %p",
             hKey,
             lpSubKey,
             Reserved,
             lpClass,
             dwOptions,
             samDesired,
             lpSecurityAttributes,
             phkResult,
             lpdwDisposition);
    return 0;
}

STATIC NTSTATUS WINAPI RegQueryValueExW(HANDLE hKey,
                                        PVOID lpValueName,
                                        PDWORD lpReserved,
                                        PDWORD lpType,
                                        PBYTE lpData,
                                        PDWORD lpcbData)
{
    DebugLog("%p, %p, %p, %p, %p, %p", hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    const char *Name = lpValueName ? CreateAnsiFromWide(lpValueName) : NULL;
    DWORD Value = 0;
    bool Found = false;

    if (Name) {
        Found = strcmp(Name, "MpDisableValidateTrustAllowBadCertDirectory") == 0
             || strcmp(Name, "MpDisableValidateTrustUseInternalCertFormat") == 0
             || strcmp(Name, "MpDisableValidateTrustUseSSTCertFormat") == 0
             || strcmp(Name, "MpDisableTrustAnchors") == 0
             || strcmp(Name, "MpDisableTrustAnchorsSkipRootInstalled") == 0
             || strcmp(Name, "MpDisableTrustAnchorsCheckAllRoots") == 0
             || strcmp(Name, "MpDisableFastpathCertCheck") == 0
             || strcmp(Name, "MpFastpathEnableTestCert") == 0;

        if (Found) {
            Value = 1;
        } else if (strcmp(Name, "MpValidateTrustDistrustSigWithTrailingData") == 0) {
            Found = true;
            Value = 0;
        }
    }

    if (!Found) {
        free((void *)Name);
        return ERROR_FILE_NOT_FOUND;
    }

    if (lpType) {
        *lpType = REG_DWORD;
    }

    if (lpcbData) {
        if (!lpData || *lpcbData < sizeof(Value)) {
            *lpcbData = sizeof(Value);
            free((void *)Name);
            return ERROR_MORE_DATA;
        }
        *lpcbData = sizeof(Value);
    }

    if (lpData) {
        memcpy(lpData, &Value, sizeof(Value));
    }

    DebugLog("returning DWORD %#x for %s", Value, Name);
    free((void *)Name);
    return ERROR_SUCCESS;
}


DECLARE_CRT_EXPORT("RegOpenKeyExW", RegOpenKeyExW);
DECLARE_CRT_EXPORT("RegCloseKey", RegCloseKey);
DECLARE_CRT_EXPORT("RegQueryInfoKeyW", RegQueryInfoKeyW);
DECLARE_CRT_EXPORT("NtEnumerateValueKey", NtEnumerateValueKey);
DECLARE_CRT_EXPORT("NtQueryValueKey", NtQueryValueKey);
DECLARE_CRT_EXPORT("RegCreateKeyExW", RegCreateKeyExW);
DECLARE_CRT_EXPORT("RegQueryValueExW", RegQueryValueExW);
