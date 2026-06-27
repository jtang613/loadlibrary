#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

extern void WINAPI SetLastError(DWORD dwErrCode);

typedef struct _CATALOG_INFO {
    DWORD cbStruct;
    WCHAR wszCatalogFile[260];
} CATALOG_INFO;

static DWORD FakeCatAdmin;
static DWORD FakeCatInfo;
static DWORD FakeCatHandle;
static DWORD FakeCatMember[16];
static DWORD FakeCatAttribute[16];

STATIC WINAPI BOOL CryptCATAdminAcquireContext(PVOID phCatAdmin, PVOID pgSubsystem, DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", phCatAdmin, pgSubsystem, dwFlags);
    if (phCatAdmin) {
        *(HANDLE *) phCatAdmin = &FakeCatAdmin;
    }
    return TRUE;
}

STATIC WINAPI BOOL CryptCATAdminAcquireContext2(PVOID phCatAdmin, PVOID pgSubsystem, PVOID pwszHashAlgorithm, PVOID pStrongHashPolicy, DWORD dwFlags)
{
    DebugLog("%p, %p, %p, %p, %#x", phCatAdmin,
                                      pgSubsystem,
                                      pwszHashAlgorithm,
                                      pStrongHashPolicy,
                                      dwFlags);
    if (phCatAdmin) {
        *(HANDLE *) phCatAdmin = &FakeCatAdmin;
    }
    return TRUE;
}

STATIC WINAPI HANDLE CryptCATAdminEnumCatalogFromHash(HANDLE hCatAdmin, BYTE *pbHash, DWORD cbHash, DWORD dwFlags, PVOID phPrevCatInfo)
{
    DebugLog("%p, %p, %u, %#x, %p", hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo);
    if (phPrevCatInfo && *(HANDLE *) phPrevCatInfo) {
        SetLastError(0x103);
        return NULL;
    }
    return &FakeCatInfo;
}

STATIC WINAPI BOOL CryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD *pcbHash, BYTE *pbHash, DWORD dwFlags)
{
    DebugLog("%p, %p, %p, %#x", hFile, pcbHash, pbHash, dwFlags);

    if (pcbHash) {
        if (pbHash && *pcbHash) {
            memset(pbHash, 0, *pcbHash);
        } else {
            *pcbHash = 20;
        }
    }

    return TRUE;
}

STATIC WINAPI BOOL CryptCATAdminReleaseCatalogContext(HANDLE hCatAdmin, HANDLE hCatInfo, DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", hCatAdmin, hCatInfo, dwFlags);
    return TRUE;
}

STATIC WINAPI BOOL CryptCATAdminReleaseContext(HANDLE hCatAdmin, DWORD dwFlags)
{
    DebugLog("%p, %#x", hCatAdmin, dwFlags);
    return TRUE;
}

STATIC WINAPI BOOL CryptCATCatalogInfoFromContext(HANDLE hCatInfo, CATALOG_INFO *psCatInfo, DWORD dwFlags)
{
    static const WCHAR CatalogPath[] = L"C:\\dummy\\fake.cat";

    DebugLog("%p, %p, %#x", hCatInfo, psCatInfo, dwFlags);

    if (psCatInfo) {
        psCatInfo->cbStruct = sizeof(*psCatInfo);
        memcpy(psCatInfo->wszCatalogFile, CatalogPath, sizeof(CatalogPath));
    }

    return TRUE;
}

STATIC WINAPI HANDLE CryptCATOpen(PWSTR pwszFileName, DWORD fdwOpenFlags, HANDLE hProv, DWORD dwPublicVersion, DWORD dwEncodingType)
{
    DebugLog("%p, %#x, %p, %#x, %#x", pwszFileName,
                                     fdwOpenFlags,
                                     hProv,
                                     dwPublicVersion,
                                     dwEncodingType);
    return &FakeCatHandle;
}

STATIC WINAPI BOOL CryptCATClose(HANDLE hCatalog)
{
    DebugLog("%p", hCatalog);
    return TRUE;
}

STATIC WINAPI PVOID CryptCATGetMemberInfo(HANDLE hCatalog, PWSTR pwszReferenceTag)
{
    DebugLog("%p, %p", hCatalog, pwszReferenceTag);
    FakeCatMember[0] = sizeof(FakeCatMember);
    return FakeCatMember;
}

STATIC WINAPI PVOID CryptCATGetAttrInfo(HANDLE hCatalog, PVOID pCatMember, PWSTR pwszReferenceTag)
{
    DebugLog("%p, %p, %p", hCatalog, pCatMember, pwszReferenceTag);
    FakeCatAttribute[0] = sizeof(FakeCatAttribute);
    return FakeCatAttribute;
}

STATIC BOOL WTHelperGetProvCertFromChain(VOID) { DebugLog("FIXME"); return 0; }
STATIC BOOL WTHelperGetProvSignerFromChain(VOID) { DebugLog("FIXME"); return 0; }
STATIC BOOL WTHelperProvDataFromStateData(VOID) { DebugLog("FIXME"); return 0; }
STATIC WINAPI LONG WinVerifyTrust(PVOID hwnd, PVOID pgActionID, PVOID pWVTData)
{
    DebugLog("%p, %p, %p", hwnd, pgActionID, pWVTData);
    return 0;
}

DECLARE_CRT_EXPORT("CryptCATAdminAcquireContext", CryptCATAdminAcquireContext);
DECLARE_CRT_EXPORT("CryptCATAdminAcquireContext2", CryptCATAdminAcquireContext2);
DECLARE_CRT_EXPORT("CryptCATAdminCalcHashFromFileHandle", CryptCATAdminCalcHashFromFileHandle);
DECLARE_CRT_EXPORT("CryptCATAdminEnumCatalogFromHash", CryptCATAdminEnumCatalogFromHash);
DECLARE_CRT_EXPORT("CryptCATAdminReleaseCatalogContext", CryptCATAdminReleaseCatalogContext);
DECLARE_CRT_EXPORT("CryptCATAdminReleaseContext", CryptCATAdminReleaseContext);
DECLARE_CRT_EXPORT("CryptCATCatalogInfoFromContext", CryptCATCatalogInfoFromContext);
DECLARE_CRT_EXPORT("CryptCATClose", CryptCATClose);
DECLARE_CRT_EXPORT("CryptCATGetAttrInfo", CryptCATGetAttrInfo);
DECLARE_CRT_EXPORT("CryptCATGetMemberInfo", CryptCATGetMemberInfo);
DECLARE_CRT_EXPORT("CryptCATOpen", CryptCATOpen);
DECLARE_CRT_EXPORT("WTHelperGetProvCertFromChain", WTHelperGetProvCertFromChain);
DECLARE_CRT_EXPORT("WTHelperGetProvSignerFromChain", WTHelperGetProvSignerFromChain);
DECLARE_CRT_EXPORT("WTHelperProvDataFromStateData", WTHelperProvDataFromStateData);
DECLARE_CRT_EXPORT("WinVerifyTrust", WinVerifyTrust);
