/* crypto/cryptlib.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_CRYPTLIB_H
# define HEADER_CRYPTLIB_H

# include <stdlib.h>
# include <string.h>

# include "e_os.h"

# ifdef OPENSSL_USE_APPLINK
#  define BIO_FLAGS_UPLINK 0x8000
#  include "ms/uplink.h"
# endif

# include <openssl/crypto.h>
# include <openssl/buffer.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/opensslconf.h>

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENSSL_SYS_VMS
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
#  define X509_CERT_FILE          OPENSSLDIR "/cert.pem"
#  define X509_PRIVATE_DIR        OPENSSLDIR "/private"
# else
#  define X509_CERT_AREA          "SSLROOT:[000000]"
#  define X509_CERT_DIR           "SSLCERTS:"
#  define X509_CERT_FILE          "SSLCERTS:cert.pem"
#  define X509_PRIVATE_DIR        "SSLPRIVATE:"
# endif

# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

/* size of string representations */
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEX_SIZE(type)          (sizeof(type)*2)

void OPENSSL_cpuid_setup(void);
extern unsigned int OPENSSL_ia32cap_P[];
void OPENSSL_showfatal(const char *fmta, ...);
extern int OPENSSL_NONPIC_relocated;

# define SGXAPI __cdecl
#define SGX_MK_ERROR(x)              (0x00000000|(x))

typedef enum _status_t
{
    SGX_SUCCESS                  = SGX_MK_ERROR(0x0000),

    SGX_ERROR_UNEXPECTED            = SGX_MK_ERROR(0x0001),      /* Unexpected error */
    SGX_ERROR_INVALID_PARAMETER     = SGX_MK_ERROR(0x0002),      /* The parameter is incorrect */
    SGX_ERROR_OUT_OF_MEMORY         = SGX_MK_ERROR(0x0003),      /* Not enough memory is available to complete this operation */
    SGX_ERROR_ENCLAVE_LOST          = SGX_MK_ERROR(0x0004),      /* Enclave lost after power transition or used in child process created by linux:fork() */
    SGX_ERROR_INVALID_STATE         = SGX_MK_ERROR(0x0005),      /* SGX API is invoked in incorrect order or state */
    SGX_ERROR_VMM_INCOMPATIBLE      = SGX_MK_ERROR(0x0006),      /* Virtual Machine Monitor is not compatible */
    SGX_ERROR_HYPERV_ENABLED        = SGX_MK_ERROR(0x0007),      /* Win10 platform with Hyper-V enabled */
    SGX_ERROR_FEATURE_NOT_SUPPORTED = SGX_MK_ERROR(0x0008),      /* Feature is not supported on this platform */

    SGX_ERROR_INVALID_FUNCTION   = SGX_MK_ERROR(0x1001),      /* The ecall/ocall index is invalid */
    SGX_ERROR_OUT_OF_TCS         = SGX_MK_ERROR(0x1003),      /* The enclave is out of TCS */
    SGX_ERROR_ENCLAVE_CRASHED    = SGX_MK_ERROR(0x1006),      /* The enclave is crashed */
    SGX_ERROR_ECALL_NOT_ALLOWED  = SGX_MK_ERROR(0x1007),      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
    SGX_ERROR_OCALL_NOT_ALLOWED  = SGX_MK_ERROR(0x1008),      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */

    SGX_ERROR_UNDEFINED_SYMBOL   = SGX_MK_ERROR(0x2000),      /* The enclave image has undefined symbol. */
    SGX_ERROR_INVALID_ENCLAVE    = SGX_MK_ERROR(0x2001),      /* The enclave image is not correct. */
    SGX_ERROR_INVALID_ENCLAVE_ID = SGX_MK_ERROR(0x2002),      /* The enclave id is invalid */
    SGX_ERROR_INVALID_SIGNATURE  = SGX_MK_ERROR(0x2003),      /* The signature is invalid */
    SGX_ERROR_NDEBUG_ENCLAVE     = SGX_MK_ERROR(0x2004),      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
    SGX_ERROR_OUT_OF_EPC         = SGX_MK_ERROR(0x2005),      /* Not enough EPC is available to load the enclave */
    SGX_ERROR_NO_DEVICE          = SGX_MK_ERROR(0x2006),      /* Can't open SGX device */
    SGX_ERROR_MEMORY_MAP_CONFLICT= SGX_MK_ERROR(0x2007),      /* Page mapping failed in driver */
    SGX_ERROR_INVALID_METADATA   = SGX_MK_ERROR(0x2009),      /* The metadata is incorrect. */
    SGX_ERROR_DEVICE_BUSY        = SGX_MK_ERROR(0x200c),      /* Device is busy, mostly EINIT failed. */
    SGX_ERROR_INVALID_VERSION    = SGX_MK_ERROR(0x200d),      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
    SGX_ERROR_MODE_INCOMPATIBLE  = SGX_MK_ERROR(0x200e),      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
    SGX_ERROR_ENCLAVE_FILE_ACCESS = SGX_MK_ERROR(0x200f),     /* Can't open enclave file. */
    SGX_ERROR_INVALID_MISC        = SGX_MK_ERROR(0x2010),     /* The MiscSelct/MiscMask settings are not correct.*/

    SGX_ERROR_MAC_MISMATCH       = SGX_MK_ERROR(0x3001),      /* Indicates verification error for reports, sealed datas, etc */
    SGX_ERROR_INVALID_ATTRIBUTE  = SGX_MK_ERROR(0x3002),      /* The enclave is not authorized */
    SGX_ERROR_INVALID_CPUSVN     = SGX_MK_ERROR(0x3003),      /* The cpu svn is beyond platform's cpu svn value */
    SGX_ERROR_INVALID_ISVSVN     = SGX_MK_ERROR(0x3004),      /* The isv svn is greater than the enclave's isv svn */
    SGX_ERROR_INVALID_KEYNAME    = SGX_MK_ERROR(0x3005),      /* The key name is an unsupported value */

    SGX_ERROR_SERVICE_UNAVAILABLE       = SGX_MK_ERROR(0x4001),   /* Indicates aesm not response or the requested service is not supported */
    SGX_ERROR_SERVICE_TIMEOUT           = SGX_MK_ERROR(0x4002),   /* Request to aesm time out */
    SGX_ERROR_AE_INVALID_EPIDBLOB       = SGX_MK_ERROR(0x4003),   /* Indicates epid blob verification error */
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE = SGX_MK_ERROR(0x4004),   /* Get launch token error */
    SGX_ERROR_EPID_MEMBER_REVOKED       = SGX_MK_ERROR(0x4005),   /* The EPID group membership revoked. */
    SGX_ERROR_UPDATE_NEEDED             = SGX_MK_ERROR(0x4006),   /* SGX needs to be updated */
    SGX_ERROR_NETWORK_FAILURE           = SGX_MK_ERROR(0x4007),   /* Network connecting or proxy setting issue is encountered */
    SGX_ERROR_AE_SESSION_INVALID        = SGX_MK_ERROR(0x4008),   /* Session is invalid or ended by server */
    SGX_ERROR_BUSY                      = SGX_MK_ERROR(0x400a),   /* The requested service is temporarily not availabe */
    SGX_ERROR_MC_NOT_FOUND              = SGX_MK_ERROR(0x400c),   /* The Monotonic Counter doesn't exist or has been invalided */
    SGX_ERROR_MC_NO_ACCESS_RIGHT        = SGX_MK_ERROR(0x400d),   /* Caller doesn't have the access right to specified VMC */
    SGX_ERROR_MC_USED_UP                = SGX_MK_ERROR(0x400e),   /* Monotonic counters are used out */
    SGX_ERROR_MC_OVER_QUOTA             = SGX_MK_ERROR(0x400f),   /* Monotonic counters exceeds quota limitation */

    SGX_ERROR_EFI_NOT_SUPPORTED         = SGX_MK_ERROR(0x5001),   /* The OS doesn't support EFI */
    SGX_ERROR_NO_PRIVILEGE              = SGX_MK_ERROR(0x5002),   /* Not enough privelige to perform the operation */

} sgx_status_t;

extern sgx_status_t SGXAPI sgx_read_rand(unsigned char *rand, size_t length_in_bytes);
extern int sgx_recv(int fd, char *out, int out_len, int flags);
extern int sgx_send(int fd, char *in, int in_len, int flags);
extern int sgx_close(int fd);
extern int sgx_shutdown(int fd);
extern char *sgx_getenv(const char *env);
extern void sgx_WSASetLastError(int e);

#ifdef  __cplusplus
}
#endif
#endif
