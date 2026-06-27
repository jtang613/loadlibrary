#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

BOOL WINAPI LookupPrivilegeValueW(PVOID lpSystemName, PVOID lpName, PVOID lpLuid)
{
    DebugLog("%p, %p, %p", lpSystemName, lpName, lpLuid);

    return FALSE;
}

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    BYTE Revision;
    BYTE Sbz1;
    WORD Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
} SECURITY_DESCRIPTOR_RELATIVE, *PISECURITY_DESCRIPTOR_RELATIVE;

#define SECURITY_DESCRIPTOR_REVISION 1
#define SE_SELF_RELATIVE             0x8000

BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(PVOID StringSecurityDescriptor,
                                                                DWORD StringSDRevision,
                                                                PVOID *SecurityDescriptor,
                                                                PULONG SecurityDescriptorSize)
{
    PISECURITY_DESCRIPTOR_RELATIVE Descriptor;

    DebugLog("%p, %u, %p, %p", StringSecurityDescriptor,
                              StringSDRevision,
                              SecurityDescriptor,
                              SecurityDescriptorSize);

    Descriptor = calloc(1, sizeof *Descriptor);
    if (Descriptor == NULL) {
        return FALSE;
    }

    Descriptor->Revision = SECURITY_DESCRIPTOR_REVISION;
    Descriptor->Control  = SE_SELF_RELATIVE;

    *SecurityDescriptor = Descriptor;
    if (SecurityDescriptorSize != NULL) {
        *SecurityDescriptorSize = sizeof *Descriptor;
    }

    return TRUE;
}

DECLARE_CRT_EXPORT("LookupPrivilegeValueW", LookupPrivilegeValueW);
DECLARE_CRT_EXPORT("ConvertStringSecurityDescriptorToSecurityDescriptorW", ConvertStringSecurityDescriptorToSecurityDescriptorW);
