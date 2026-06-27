#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"
#include "rootcert.h"

typedef struct _CRYPT_BIT_BLOB {
  DWORD cbData;
  BYTE  *pbData;
  DWORD cUnusedBits;
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE  *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,
  CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,
  CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,
  CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB,
  *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB,
  CERT_BLOB, *PCERT_BLOB,
  CRL_BLOB, *PCRL_BLOB,
  DATA_BLOB, *PDATA_BLOB,
  CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
  CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,
  CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,
  CRYPT_DER_BLOB, PCRYPT_DER_BLOB,
  CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
  PVOID            pszObjId;
  CRYPT_OBJID_BLOB Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CERT_PUBLIC_KEY_INFO {
  CRYPT_ALGORITHM_IDENTIFIER Algorithm;
  CRYPT_BIT_BLOB             PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_EXTENSION {
  PVOID            pszObjId;
  BOOL             fCritical;
  CRYPT_OBJID_BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_INFO {
  DWORD                      dwVersion;
  CRYPT_INTEGER_BLOB         SerialNumber;
  CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
  CERT_NAME_BLOB             Issuer;
  FILETIME                   NotBefore;
  FILETIME                   NotAfter;
  CERT_NAME_BLOB             Subject;
  CERT_PUBLIC_KEY_INFO       SubjectPublicKeyInfo;
  CRYPT_BIT_BLOB             IssuerUniqueId;
  CRYPT_BIT_BLOB             SubjectUniqueId;
  DWORD                      cExtension;
  PCERT_EXTENSION            rgExtension;
} CERT_INFO, *PCERT_INFO;

typedef struct _CERT_CONTEXT {
  DWORD      dwCertEncodingType;
  BYTE       *pbCertEncoded;
  DWORD      cbCertEncoded;
  PCERT_INFO pCertInfo;
  HANDLE     hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;

typedef const CERT_CONTEXT *PCCERT_CONTEXT;

static PCERT_CONTEXT GetFakeCertContext(void)
{
    static CERT_INFO FakeInfo = {0};
    static CERT_CONTEXT FakeCert = {0};

    FakeCert.dwCertEncodingType = 1;
    FakeCert.pbCertEncoded = RootCertificate;
    FakeCert.cbCertEncoded = sizeof(RootCertificate);
    FakeCert.pCertInfo = &FakeInfo;
    FakeCert.pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId = "1.2.840.113549.1.1.1";

    return &FakeCert;
}

static NTSTATUS WINAPI BCryptOpenAlgorithmProvider(PVOID phAlgorithm, PWCHAR pszAlgId, PWCHAR pszImplementation, DWORD dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptCloseAlgorithmProvider(HANDLE hAlgorithm, ULONG dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptGenRandom(PVOID phAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)
{
    static int randomfd = -1;

    void __constructor init()
    {
        randomfd = open("/dev/urandom", O_RDONLY);
    }

    void __destructor fini()
    {
        close(randomfd);
    }

    DebugLog("%p, %p, %lu, %#x [fd=%d]", phAlgorithm, pbBuffer, cbBuffer, dwFlags, randomfd);

    if (read(randomfd, pbBuffer, cbBuffer) != cbBuffer) {
        DebugLog("failed to generate random data, %m");
    }

    return STATUS_SUCCESS;
}

static BOOL WINAPI CertStrToNameW(DWORD dwCertEncodingType,
                                  PVOID pszX500,
                                  DWORD dwStrType,
                                  void *pvReserved,
                                  BYTE *pbEncoded,
                                  DWORD *pcbEncoded,
                                  PVOID ppszError)
{
    uint16_t CertName[] = L"Totally Legitimate Certificate Name";
    char *name = CreateAnsiFromWide(pszX500);

    DebugLog("%u, %p [%s], %u, %p, %p, %p, %p", dwCertEncodingType,
                                                pszX500,
                                                name,
                                                dwStrType,
                                                pvReserved,
                                                pbEncoded,
                                                pcbEncoded,
                                                ppszError);
    free(name);

    *pcbEncoded = sizeof(CertName);

    if (pbEncoded) {
        memcpy(pbEncoded, CertName, sizeof(CertName));
    }

    return TRUE;
}

static HANDLE WINAPI CertOpenStore(PCHAR lpszStoreProvider,
                                   DWORD dwMsgAndCertEncodingType,
                                   PVOID hCryptProv,
                                   DWORD dwFlags,
                                   PVOID pvPara)
{
    return (HANDLE) 'STOR';
}

enum {
    CERT_FIND_SUBJECT_NAME = 131079,
};

static PVOID WINAPI CertFindCertificateInStore(HANDLE hCertStore,
                                               DWORD dwCertEncodingType,
                                               DWORD dwFindFlags,
                                               DWORD dwFindType,
                                               PVOID pvFindPara,
                                               PVOID pPrevCertContext)
{
    DebugLog("%p, %u, %#x, %#x, %p, %p", hCertStore,
                                         dwCertEncodingType,
                                         dwFindFlags,
                                         dwFindType,
                                         pvFindPara,
                                         pPrevCertContext);

    switch  (dwFindType) {
        case CERT_FIND_SUBJECT_NAME: {
            DebugLog("\tCERT_FIND_SUBJECT_NAME");
            break;
        }
    }

    DebugLog("FakeCert: %p", GetFakeCertContext());

    return GetFakeCertContext();
}

static PVOID WINAPI CertCreateCertificateContext(DWORD dwCertEncodingType,
                                                 const BYTE *pbCertEncoded,
                                                 DWORD cbCertEncoded)
{
    DebugLog("%#x, %p, %u", dwCertEncodingType, pbCertEncoded, cbCertEncoded);
    return GetFakeCertContext();
}

static BOOL WINAPI CertAddEncodedCertificateToStore(HANDLE hCertStore,
                                                    DWORD dwCertEncodingType,
                                                    const BYTE *pbCertEncoded,
                                                    DWORD cbCertEncoded,
                                                    DWORD dwAddDisposition,
                                                    PCCERT_CONTEXT *ppCertContext)
{
    DebugLog("%p, %#x, %p, %u, %#x, %p", hCertStore,
                                             dwCertEncodingType,
                                             pbCertEncoded,
                                             cbCertEncoded,
                                             dwAddDisposition,
                                             ppCertContext);
    if (ppCertContext) {
        *ppCertContext = GetFakeCertContext();
    }
    return TRUE;
}

static PVOID WINAPI CertEnumCertificatesInStore(HANDLE hCertStore, PVOID pPrevCertContext)
{
    DebugLog("%p, %p", hCertStore, pPrevCertContext);
    return pPrevCertContext ? NULL : GetFakeCertContext();
}

static BOOL WINAPI CertDeleteCertificateFromStore(PVOID pCertContext)
{
    DebugLog("%p", pCertContext);
    return TRUE;
}

static PVOID WINAPI CertGetSubjectCertificateFromStore(HANDLE hCertStore,
                                                       DWORD dwCertEncodingType,
                                                       PCERT_INFO pCertId)
{
    DebugLog("%p, %#x, %p", hCertStore, dwCertEncodingType, pCertId);
    return GetFakeCertContext();
}

static BOOL WINAPI CertCloseStore(HANDLE hCertStore, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CryptAcquireContextW(PVOID phProv, PWCHAR pszContainer, PWCHAR pszProvider, DWORD dwProvType, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CertFreeCertificateContext(PVOID pCertContext)
{
    return TRUE;
}

static BOOL WINAPI CertGetCertificateContextProperty(PVOID pCertContext,
                                                     DWORD dwPropId,
                                                     PVOID pvData,
                                                     DWORD *pcbData)
{
    DebugLog("%p, %#x, %p, %p", pCertContext, dwPropId, pvData, pcbData);

    if (pcbData) {
        if (pvData && *pcbData) {
            memset(pvData, 0, *pcbData);
        } else {
            *pcbData = 0;
        }
    }

    return TRUE;
}

static DWORD WINAPI CertNameToStrW(DWORD dwCertEncodingType,
                                   PCERT_NAME_BLOB pName,
                                   DWORD dwStrType,
                                   LPWSTR psz,
                                   DWORD csz)
{
    static const WCHAR Name[] = L"Microsoft Root Authority";
    DWORD Required = sizeof(Name) / sizeof(Name[0]);

    DebugLog("%#x, %p, %#x, %p, %u", dwCertEncodingType, pName, dwStrType, psz, csz);

    if (psz && csz) {
        DWORD Count = Required < csz ? Required : csz;
        memcpy(psz, Name, Count * sizeof(WCHAR));
        psz[csz - 1] = 0;
    }

    return Required;
}

static DWORD WINAPI CertGetNameStringW(PVOID pCertContext,
                                       DWORD dwType,
                                       DWORD dwFlags,
                                       PVOID pvTypePara,
                                       LPWSTR pszNameString,
                                       DWORD cchNameString)
{
    DebugLog("%p, %#x, %#x, %p, %p, %u", pCertContext,
                                             dwType,
                                             dwFlags,
                                             pvTypePara,
                                             pszNameString,
                                             cchNameString);
    return CertNameToStrW(1, NULL, 0, pszNameString, cchNameString);
}

enum {
    CALG_SHA_256 = 0x800c,
    CALG_SHA1 = 0x8004,
};

static BOOL WINAPI CryptCreateHash(PVOID hProv, DWORD Algid, HANDLE hKey, DWORD dwFlags, PDWORD phHash)
{
    DebugLog("%p, %#x, %p, %#x, %p", hProv, Algid, hKey, dwFlags, phHash);

    switch (Algid) {
        case CALG_SHA_256:
            *phHash = 'SHA2';
            break;
        case CALG_SHA1:
            *phHash = 'SHA1';
            break;
        default:
            DebugLog("unexpected Algid value, code update might be required.");
    }

    return TRUE;
}

enum HashParameters
{
    HP_ALGID = 0x0001,   // Hash algorithm
    HP_HASHVAL = 0x0002, // Hash value
    HP_HASHSIZE = 0x0004 // Hash value size
};

static BOOL WINAPI CryptGetHashParam(DWORD hHash, DWORD dwParam, PDWORD pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    DebugLog("%#x, %u, %p, %p, %#x", hHash, dwParam, pbData, pdwDataLen, dwFlags);

    switch (dwParam) {
        case HP_HASHSIZE:
            *pdwDataLen = sizeof(DWORD);

            switch (hHash) {
                case 'SHA2': *pbData = 32; break;
                case 'SHA1': *pbData = 20; break;
                default:
                    DebugLog("unknown hHash, this might fail.");
            }
            break;
    }

    return TRUE;
}

static BOOL WINAPI CryptSetHashParam(PVOID hHash, DWORD dwParam, PVOID pbData, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CryptImportPublicKeyInfo(HANDLE hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HANDLE *phKey)
{
    return TRUE;
}

static BOOL WINAPI CryptVerifySignatureW(DWORD hHash, PVOID pbSignature, DWORD dwSigLen, HANDLE hPubKey, PVOID sDescription, DWORD dwFlags)
{
    switch (hHash) {
        case 'SHA2': {
            if (dwSigLen != 256) {
                DebugLog("unexpected Signature Size");
            }
            break;
        }
        case 'SHA1': {
            if (dwSigLen != 160) {
                DebugLog("unexpected Signature Size");
            }
            break;
        }
        default: DebugLog("unrecognized hHash %#x, something went wrong", hHash);
    }
    DebugLog("Signature verification is not implemented #YOLO");
    return TRUE;
}

static BOOL WINAPI CertVerifyCertificateChainPolicy(PVOID pszPolicyOID, PVOID pChainContext, PVOID pPolicyPara, PVOID pPolicyStatus)
{
    DebugLog("Certificate policy verification is not implemented #YOLO");
    return TRUE;
}

static BOOL WINAPI CertGetCertificateChain(HANDLE hChainEngine,
                                           PVOID pCertContext,
                                           PFILETIME pTime,
                                           HANDLE hAdditionalStore,
                                           PVOID pChainPara,
                                           DWORD dwFlags,
                                           PVOID pvReserved,
                                           PVOID *ppChainContext)
{
    static DWORD FakeChainContext[16] = {0};

    DebugLog("%p, %p, %p, %p, %p, %#x, %p, %p", hChainEngine,
                                                     pCertContext,
                                                     pTime,
                                                     hAdditionalStore,
                                                     pChainPara,
                                                     dwFlags,
                                                     pvReserved,
                                                     ppChainContext);
    if (ppChainContext) {
        *ppChainContext = FakeChainContext;
    }

    return TRUE;
}

static VOID WINAPI CertFreeCertificateChain(PVOID pChainContext)
{
    DebugLog("%p", pChainContext);
}

static PVOID WINAPI CryptMsgOpenToDecode(DWORD dwMsgEncodingType,
                                         DWORD dwFlags,
                                         DWORD dwMsgType,
                                         HANDLE hCryptProv,
                                         PCERT_INFO pRecipientInfo,
                                         PVOID pStreamInfo)
{
    DebugLog("%#x, %#x, %#x, %p, %p, %p", dwMsgEncodingType,
                                             dwFlags,
                                             dwMsgType,
                                             hCryptProv,
                                             pRecipientInfo,
                                             pStreamInfo);
    return (PVOID) 'CMSG';
}

static BOOL WINAPI CryptMsgUpdate(PVOID hCryptMsg, const BYTE *pbData, DWORD cbData, BOOL fFinal)
{
    DebugLog("%p, %p, %u, %u", hCryptMsg, pbData, cbData, fFinal);
    return TRUE;
}

static BOOL WINAPI CryptMsgGetParam(PVOID hCryptMsg,
                                    DWORD dwParamType,
                                    DWORD dwIndex,
                                    PVOID pvData,
                                    DWORD *pcbData)
{
    DebugLog("%p, %#x, %u, %p, %p", hCryptMsg, dwParamType, dwIndex, pvData, pcbData);

    if (pcbData) {
        if (pvData && *pcbData) {
            memset(pvData, 0, *pcbData);
        } else {
            *pcbData = 0;
        }
    }

    return TRUE;
}

static BOOL WINAPI CryptMsgControl(PVOID hCryptMsg, DWORD dwFlags, DWORD dwCtrlType, const PVOID pvCtrlPara)
{
    DebugLog("%p, %#x, %#x, %p", hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara);
    return TRUE;
}

static BOOL WINAPI CryptMsgClose(PVOID hCryptMsg)
{
    DebugLog("%p", hCryptMsg);
    return TRUE;
}

static BOOL WINAPI CryptDecodeObject(DWORD dwCertEncodingType,
                                     LPCSTR lpszStructType,
                                     const BYTE *pbEncoded,
                                     DWORD cbEncoded,
                                     DWORD dwFlags,
                                     PVOID pvStructInfo,
                                     DWORD *pcbStructInfo)
{
    DebugLog("%#x, %p, %p, %u, %#x, %p, %p", dwCertEncodingType,
                                                     lpszStructType,
                                                     pbEncoded,
                                                     cbEncoded,
                                                     dwFlags,
                                                     pvStructInfo,
                                                     pcbStructInfo);
    if (pcbStructInfo) {
        if (pvStructInfo && *pcbStructInfo) {
            memset(pvStructInfo, 0, *pcbStructInfo);
        } else {
            *pcbStructInfo = 0;
        }
    }
    return TRUE;
}

static HANDLE WINAPI CryptGetMessageCertificates(DWORD dwMsgAndCertEncodingType,
                                                 HANDLE hCryptProv,
                                                 DWORD dwFlags,
                                                 const BYTE *pbSignedBlob,
                                                 DWORD cbSignedBlob)
{
    DebugLog("%#x, %p, %#x, %p, %u", dwMsgAndCertEncodingType,
                                             hCryptProv,
                                             dwFlags,
                                             pbSignedBlob,
                                             cbSignedBlob);
    return (HANDLE) 'STOR';
}

static BOOL WINAPI CryptQueryObject(DWORD dwObjectType,
                                    const PVOID pvObject,
                                    DWORD dwExpectedContentTypeFlags,
                                    DWORD dwExpectedFormatTypeFlags,
                                    DWORD dwFlags,
                                    DWORD *pdwMsgAndCertEncodingType,
                                    DWORD *pdwContentType,
                                    DWORD *pdwFormatType,
                                    HANDLE *phCertStore,
                                    PVOID *phMsg,
                                    PVOID *ppvContext)
{
    DebugLog("%#x, %p, %#x, %#x, %#x, %p, %p, %p, %p, %p, %p",
             dwObjectType,
             pvObject,
             dwExpectedContentTypeFlags,
             dwExpectedFormatTypeFlags,
             dwFlags,
             pdwMsgAndCertEncodingType,
             pdwContentType,
             pdwFormatType,
             phCertStore,
             phMsg,
             ppvContext);

    if (pdwMsgAndCertEncodingType) *pdwMsgAndCertEncodingType = 0x10001;
    if (pdwContentType) *pdwContentType = 2;
    if (pdwFormatType) *pdwFormatType = 1;
    if (phCertStore) *phCertStore = (HANDLE) 'STOR';
    if (phMsg) *phMsg = (PVOID) 'CMSG';
    if (ppvContext) *ppvContext = GetFakeCertContext();

    return TRUE;
}

static BOOL WINAPI CryptStringToBinaryW(LPCWSTR pszString,
                                        DWORD cchString,
                                        DWORD dwFlags,
                                        BYTE *pbBinary,
                                        DWORD *pcbBinary,
                                        DWORD *pdwSkip,
                                        DWORD *pdwFlags)
{
    DebugLog("%p, %u, %#x, %p, %p, %p, %p", pszString,
                                             cchString,
                                             dwFlags,
                                             pbBinary,
                                             pcbBinary,
                                             pdwSkip,
                                             pdwFlags);
    if (pcbBinary) {
        if (pbBinary && *pcbBinary) {
            memset(pbBinary, 0, *pcbBinary);
        } else {
            *pcbBinary = 0;
        }
    }
    if (pdwSkip) *pdwSkip = 0;
    if (pdwFlags) *pdwFlags = dwFlags;
    return TRUE;
}

static BOOL WINAPI CryptDestroyHash(DWORD hHash)
{
    DebugLog("%p", hHash);

    assert(hHash == 'SHA2' || hHash == 'SHA1');

    return TRUE;
}

DECLARE_CRT_EXPORT("CertCloseStore", CertCloseStore);
DECLARE_CRT_EXPORT("CertAddEncodedCertificateToStore", CertAddEncodedCertificateToStore);
DECLARE_CRT_EXPORT("CertCreateCertificateContext", CertCreateCertificateContext);
DECLARE_CRT_EXPORT("CertDeleteCertificateFromStore", CertDeleteCertificateFromStore);
DECLARE_CRT_EXPORT("CertEnumCertificatesInStore", CertEnumCertificatesInStore);
DECLARE_CRT_EXPORT("CertFindCertificateInStore", CertFindCertificateInStore);
DECLARE_CRT_EXPORT("CertFreeCertificateContext", CertFreeCertificateContext);
DECLARE_CRT_EXPORT("CertFreeCertificateChain", CertFreeCertificateChain);
DECLARE_CRT_EXPORT("CertGetCertificateChain", CertGetCertificateChain);
DECLARE_CRT_EXPORT("CertGetCertificateContextProperty", CertGetCertificateContextProperty);
DECLARE_CRT_EXPORT("CertGetNameStringW", CertGetNameStringW);
DECLARE_CRT_EXPORT("CertGetSubjectCertificateFromStore", CertGetSubjectCertificateFromStore);
DECLARE_CRT_EXPORT("CertNameToStrW", CertNameToStrW);
DECLARE_CRT_EXPORT("CertOpenStore", CertOpenStore);
DECLARE_CRT_EXPORT("CertStrToNameW", CertStrToNameW);
DECLARE_CRT_EXPORT("CertVerifyCertificateChainPolicy", CertVerifyCertificateChainPolicy);
DECLARE_CRT_EXPORT("CryptDecodeObject", CryptDecodeObject);
DECLARE_CRT_EXPORT("CryptGetMessageCertificates", CryptGetMessageCertificates);
DECLARE_CRT_EXPORT("CryptImportPublicKeyInfo", CryptImportPublicKeyInfo);
DECLARE_CRT_EXPORT("CryptCreateHash", CryptCreateHash);
DECLARE_CRT_EXPORT("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptGenRandom", BCryptGenRandom);
DECLARE_CRT_EXPORT("CryptAcquireContextW", CryptAcquireContextW);
DECLARE_CRT_EXPORT("CryptGetHashParam", CryptGetHashParam);
DECLARE_CRT_EXPORT("CryptMsgClose", CryptMsgClose);
DECLARE_CRT_EXPORT("CryptMsgControl", CryptMsgControl);
DECLARE_CRT_EXPORT("CryptMsgGetParam", CryptMsgGetParam);
DECLARE_CRT_EXPORT("CryptMsgOpenToDecode", CryptMsgOpenToDecode);
DECLARE_CRT_EXPORT("CryptMsgUpdate", CryptMsgUpdate);
DECLARE_CRT_EXPORT("CryptQueryObject", CryptQueryObject);
DECLARE_CRT_EXPORT("CryptSetHashParam", CryptSetHashParam);
DECLARE_CRT_EXPORT("CryptStringToBinaryW", CryptStringToBinaryW);
DECLARE_CRT_EXPORT("CryptVerifySignatureW", CryptVerifySignatureW);
DECLARE_CRT_EXPORT("CryptDestroyHash", CryptDestroyHash);
