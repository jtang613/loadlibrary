#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <search.h>
#include <string.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define ERROR_SUCCESS 0

typedef enum _APPPOLICY_PROCESS_TERMINATION_METHOD {
    AppPolicyProcessTerminationMethod_ExitProcess = 0,
    AppPolicyProcessTerminationMethod_TerminateProcess = 1,
} APPPOLICY_PROCESS_TERMINATION_METHOD;

STATIC NTSTATUS WINAPI NtSetInformationProcess(HANDLE ProcessHandle,
                                               PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength)
{
    DebugLog("%p", ProcessHandle);
    return 0;
}

STATIC HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    DebugLog("%#x, %u, %u", dwDesiredAccess, bInheritHandle, dwProcessId);
    return (HANDLE) -1;
}

STATIC DWORD WINAPI GetProcessId(HANDLE Process)
{
    DebugLog("%p", Process);
    return getpid();
}

STATIC BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess,
                                              DWORD dwFlags,
                                              PWCHAR lpExeName,
                                              PDWORD lpdwSize)
{
    static const WCHAR ImageName[] = L"C:\\dummy\\fakename.exe";
    DWORD Length = sizeof(ImageName) / sizeof(ImageName[0]) - 1;

    DebugLog("%p, %#x, %p, %p", hProcess, dwFlags, lpExeName, lpdwSize);

    if (!lpdwSize || !lpExeName || *lpdwSize <= Length) {
        return FALSE;
    }

    memcpy(lpExeName, ImageName, sizeof(ImageName));
    *lpdwSize = Length;
    return TRUE;
}

STATIC BOOL WINAPI GetExitCodeProcess(HANDLE hProcess, PDWORD lpExitCode)
{
    DebugLog("%p, %p", hProcess, lpExitCode);
    if (lpExitCode) {
        *lpExitCode = 0;
    }
    return TRUE;
}

STATIC BOOL WINAPI IsWow64Process(HANDLE hProcess, BOOL *Wow64Process)
{
    DebugLog("%p, %p", hProcess, Wow64Process);
    if (Wow64Process) {
        *Wow64Process = FALSE;
    }
    return TRUE;
}

STATIC VOID WINAPI ExitProcess(UINT uExitCode)
{
    LogMessage("ExitProcess(%u)", uExitCode);
    exit(uExitCode);
}

STATIC LONG WINAPI AppPolicyGetProcessTerminationMethod(HANDLE ProcessToken,
                                                        APPPOLICY_PROCESS_TERMINATION_METHOD *Policy)
{
    DebugLog("%p, %p", ProcessToken, Policy);

    if (Policy) {
        *Policy = AppPolicyProcessTerminationMethod_ExitProcess;
    }

    return ERROR_SUCCESS;
}

DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);
DECLARE_CRT_EXPORT("OpenProcess", OpenProcess);
DECLARE_CRT_EXPORT("GetProcessId", GetProcessId);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);
DECLARE_CRT_EXPORT("GetExitCodeProcess", GetExitCodeProcess);
DECLARE_CRT_EXPORT("IsWow64Process", IsWow64Process);
DECLARE_CRT_EXPORT("ExitProcess", ExitProcess);
DECLARE_CRT_EXPORT("AppPolicyGetProcessTerminationMethod", AppPolicyGetProcessTerminationMethod);
