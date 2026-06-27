#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

#define MB_ERR_INVALID_CHARS 8
#define MB_PRECOMPOSED 1

#define CT_CTYPE1 1
#define C1_UPPER  0x0001
#define C1_LOWER  0x0002
#define C1_DIGIT  0x0004
#define C1_SPACE  0x0008
#define C1_PUNCT  0x0010
#define C1_CNTRL  0x0020
#define C1_BLANK  0x0040
#define C1_XDIGIT 0x0080
#define C1_ALPHA  0x0100

static USHORT GetCType1ForChar(int Character)
{
    USHORT Type = 0;
    unsigned char Ch = Character;

    if (isupper(Ch)) Type |= C1_UPPER | C1_ALPHA;
    if (islower(Ch)) Type |= C1_LOWER | C1_ALPHA;
    if (isdigit(Ch)) Type |= C1_DIGIT;
    if (isspace(Ch)) Type |= C1_SPACE;
    if (ispunct(Ch)) Type |= C1_PUNCT;
    if (iscntrl(Ch)) Type |= C1_CNTRL;
    if (isblank(Ch)) Type |= C1_BLANK;
    if (isxdigit(Ch)) Type |= C1_XDIGIT;

    return Type;
}

STATIC int WINAPI MultiByteToWideChar(UINT CodePage,
                                      DWORD dwFlags,
                                      PCHAR lpMultiByteStr,
                                      int cbMultiByte,
                                      PUSHORT lpWideCharStr,
                                      int cchWideChar)
{
    size_t i;

    DebugLog("%u, %#x, %p, %u, %p, %u", CodePage,
                                        dwFlags,
                                        lpMultiByteStr,
                                        cbMultiByte,
                                        lpWideCharStr,
                                        cchWideChar);

    if ((dwFlags & ~(MB_ERR_INVALID_CHARS | MB_PRECOMPOSED)) != 0) {
        LogMessage("Unsupported Conversion Flags %#x", dwFlags);
    }

    if (CodePage != 0 && CodePage != 65001) {
        DebugLog("Unsupported CodePage %u", CodePage);
    }

    if (cbMultiByte == 0)
        return 0;

    if (cbMultiByte == -1)
        cbMultiByte = strlen(lpMultiByteStr) + 1;

    if (cchWideChar == 0)
        return cbMultiByte;

    // cbMultibyte is the number of *bytes* to process.
    // cchWideChar is the number of output *chars* expected.
    if (cbMultiByte > cchWideChar) {
        return 0;
    }

    for (i = 0; i < cbMultiByte; i++) {
        lpWideCharStr[i] = (uint8_t) lpMultiByteStr[i];
        if (dwFlags & MB_ERR_INVALID_CHARS) {
            if (!isascii(lpMultiByteStr[i]) || iscntrl(lpMultiByteStr[i])) {
                lpWideCharStr[i] = '?';
            }
        }
    }

    return i;
}

STATIC int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, PVOID lpWideCharStr, int cchWideChar, PVOID lpMultiByteStr, int cbMultiByte, PVOID lpDefaultChar, PVOID lpUsedDefaultChar)
{
    char *ansi = NULL;

    DebugLog("%u, %#x, %p, %d, %p, %d, %p, %p", CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    if (cchWideChar != -1) {
        // Add a nul terminator.
        PVOID tmpStr = calloc(cchWideChar + 1, sizeof(USHORT));
        memcpy(tmpStr, lpWideCharStr, cchWideChar);
        ansi = CreateAnsiFromWide(tmpStr);
        free(tmpStr);
    } else {
        ansi = CreateAnsiFromWide(lpWideCharStr);
    }

    // This really can happen
    if (ansi == NULL) {
        return 0;
    }

    DebugLog("cchWideChar == %d, Ansi: [%s]", cchWideChar, ansi);

    if (lpMultiByteStr && strlen(ansi) < cbMultiByte) {
        strcpy(lpMultiByteStr, ansi);
        free(ansi);
        return strlen(lpMultiByteStr) + 1;
    } else if (!lpMultiByteStr && cbMultiByte == 0) {
        int len = strlen(ansi) + 1;
        free(ansi);
        return len;
    }

    free(ansi);
    return 0;
}

STATIC BOOL WINAPI GetStringTypeA(DWORD locale, DWORD dwInfoType, PUSHORT lpSrcStr, int cchSrc, PUSHORT lpCharType)
{
    DebugLog("%u, %u, %p, %d, %p", locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (dwInfoType != CT_CTYPE1) {
        return FALSE;
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = GetCType1ForChar(((PBYTE) lpSrcStr)[i]);
    }

    return TRUE;
}

STATIC BOOL WINAPI GetStringTypeExA(DWORD Locale, DWORD dwInfoType, PCHAR lpSrcStr, int cchSrc, PUSHORT lpCharType)
{
    DebugLog("%u, %u, %p, %d, %p", Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (dwInfoType != CT_CTYPE1) {
        return FALSE;
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = GetCType1ForChar(lpSrcStr[i]);
    }

    return TRUE;
}

STATIC BOOL WINAPI GetStringTypeExW(DWORD Locale, DWORD dwInfoType, PUSHORT lpSrcStr, int cchSrc, PUSHORT lpCharType)
{
    DebugLog("%u, %u, %p, %d, %p", Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (dwInfoType != CT_CTYPE1) {
        return FALSE;
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = GetCType1ForChar(lpSrcStr[i] & 0xff);
    }

    return TRUE;
}

STATIC BOOL WINAPI GetStringTypeW(DWORD dwInfoType, PUSHORT lpSrcStr, int cchSrc, PUSHORT lpCharType)
{
    DebugLog("%u, %p, %d, %p", dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (dwInfoType != CT_CTYPE1) {
        return FALSE;
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = GetCType1ForChar(lpSrcStr[i] & 0xff);
    }

    return TRUE;
}

STATIC VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWCHAR SourceString)
{
    DestinationString->Length = CountWideChars(SourceString) * 2;
    DestinationString->MaximumLength = DestinationString->Length;
    DestinationString->Buffer = SourceString;
}

STATIC PVOID WINAPI UuidFromStringW(PUSHORT StringUuid, PBYTE Uuid)
{
    int i;

    DebugLog("%S, %p", StringUuid, Uuid);

    for (i = 0; i < 16; i++) {
        Uuid[i] = 0x41;
    }

    return 0;
}

STATIC INT WINAPI UuidCreate(PBYTE Uuid)
{
    int i;

    DebugLog("%p", Uuid);

    for (i = 0; i < 16; i++) {
        Uuid[i] = 0x41;
    }

    return 0;
}

#define CSTR_LESS_THAN    1
#define CSTR_EQUAL        2
#define CSTR_GREATER_THAN 3

STATIC INT WINAPI CompareStringOrdinal(PVOID lpString1,
                                       INT cchCount1,
                                       PVOID lpString2,
                                       INT cchCount2,
                                       BOOL bIgnoreCase)
{
    int Result;
    int Length;
    PVOID lpt1;
    PVOID lpt2;

    DebugLog("%p, %d, %p, %d, %d", lpString1,
                                   cchCount1,
                                   lpString2,
                                   cchCount2,
                                   bIgnoreCase);

    if (cchCount1 == -1)
        cchCount1 = CountWideChars(lpString1);

    if (cchCount2 == -1)
        cchCount2 = CountWideChars(lpString2);

    lpt1 = calloc(cchCount1 + 1, 2);
    lpt2 = calloc(cchCount2 + 1, 2);

    if (!lpt1 || !lpt2) {
        // "The function returns 0 if it does not succeed."
        free(lpt1);
        free(lpt2);
        return 0;
    }

    memcpy(lpt1, lpString1, cchCount1 * 2);
    memcpy(lpt2, lpString2, cchCount2 * 2);

    Result = bIgnoreCase
        ? wcsicmp(lpt1, lpt2)
        : wcscmp(lpt1, lpt2);

    free(lpt1);
    free(lpt2);

    // I am not sure if this logic is correct, I just read the msdn page and
    // wrote it blindly.

    if (Result < 0)
        return CSTR_LESS_THAN;
    if (Result == 0)
        return CSTR_EQUAL;

    return CSTR_GREATER_THAN;
}

DECLARE_CRT_EXPORT("MultiByteToWideChar", MultiByteToWideChar);
DECLARE_CRT_EXPORT("WideCharToMultiByte", WideCharToMultiByte);
DECLARE_CRT_EXPORT("GetStringTypeA", GetStringTypeA);
DECLARE_CRT_EXPORT("GetStringTypeExA", GetStringTypeExA);
DECLARE_CRT_EXPORT("GetStringTypeExW", GetStringTypeExW);
DECLARE_CRT_EXPORT("GetStringTypeW", GetStringTypeW);
DECLARE_CRT_EXPORT("RtlInitUnicodeString", RtlInitUnicodeString);
DECLARE_CRT_EXPORT("UuidFromStringW", UuidFromStringW);
DECLARE_CRT_EXPORT("UuidCreate", UuidCreate);
DECLARE_CRT_EXPORT("CompareStringOrdinal", CompareStringOrdinal);
