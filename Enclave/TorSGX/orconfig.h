/* orconfig.h.  Generated from orconfig.h.in by configure.  */
/* orconfig.h.in.  Generated from configure.ac by autoheader.  */

#ifndef TOR_ORCONFIG_H
#define TOR_ORCONFIG_H

// Sgx
//#include <BaseTsd.h>
#include "time.h"
//#include "print.h"

#include <sys/types.h>

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* tor's build directory */
#define BUILDDIR "C:/Users/INA-SGX-USER/Desktop/TorVS2012/TorVS2012"

/* tor's configuration directory */
#define CONFDIR "C:/Users/INA-SGX-USER/Desktop/TorVS2012/tor_conf"

/* Defined if we're not going to look for a torrc in SYSCONF */
/* #undef DISABLE_SYSTEM_TORRC */

/* Define to 1 iff memset(0) sets doubles to 0.0 */
#define DOUBLE_0_REP_IS_ZERO_BYTES 1

/* Defined if we default to host local appdata paths on Windows */
/* #undef ENABLE_LOCAL_APPDATA */

/* Define if enum is always signed */
#define ENUM_VALS_ARE_SIGNED

/* Define to nothing if C supports flexible array members, and to 1 if it does
   not. That way, with a declaration like `struct s { int n; double
   d[FLEXIBLE_ARRAY_MEMBER]; };', the struct hack can be used with pre-C99
   compilers. When computing the size of such an object, don't use 'sizeof
   (struct s)' as it overestimates the size. Use 'offsetof (struct s, d)'
   instead. Don't use 'offsetof (struct s, d[0])', as this doesn't work with
   MSVC and with C++ compilers. */
#define FLEXIBLE_ARRAY_MEMBER /**/

/* Define to 1 if you have the `accept4' function. */
/* #undef HAVE_ACCEPT4 */

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `backtrace' function. */
/* #undef HAVE_BACKTRACE */

/* Define to 1 if you have the `backtrace_symbols_fd' function. */
/* #undef HAVE_BACKTRACE_SYMBOLS_FD */

/* Define to 1 if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */

/* Define to 1 if you have the <crt_externs.h> header file. */
/* #undef HAVE_CRT_EXTERNS_H */

/* Define to 1 if you have the <crypto_scalarmult_curve25519.h> header file.
   */
/* #undef HAVE_CRYPTO_SCALARMULT_CURVE25519_H */

/* Define to 1 if you have the <cygwin/signal.h> header file. */
/* #undef HAVE_CYGWIN_SIGNAL_H */

/* Define to 1 if you have the declaration of `mlockall', and to 0 if you
   don't. */
#define HAVE_DECL_MLOCKALL 0

/* Define to 1 if you have the declaration of `SecureZeroMemory', and to 0 if
   you don't. */
#define HAVE_DECL_SECUREZEROMEMORY 1

/* Define to 1 if you have the declaration of `_getwch', and to 0 if you
   don't. */
#define HAVE_DECL__GETWCH 0

/* Define to 1 if you have the <dmalloc.h> header file. */
/* #undef HAVE_DMALLOC_H */

/* Define to 1 if you have the `dmalloc_strdup' function. */
/* #undef HAVE_DMALLOC_STRDUP */

/* Define to 1 if you have the `dmalloc_strndup' function. */
/* #undef HAVE_DMALLOC_STRNDUP */

#define HAVE_ERRNO_H 1
/* Define to 1 if you have the <errno.h> header file. */
/* #define HAVE_ERRNO_H 1 */

/* Define to 1 if you have the <event2/bufferevent_ssl.h> header file. */
#define HAVE_EVENT2_BUFFEREVENT_SSL_H 1

/* Define to 1 if you have the <event2/dns.h> header file. */
#define HAVE_EVENT2_DNS_H 1

/* Define to 1 if you have the <event2/event.h> header file. */
#define HAVE_EVENT2_EVENT_H 1

/* Define to 1 if you have the `eventfd' function. */
/* #undef HAVE_EVENTFD */

/* Define to 1 if you have the `event_get_version_number' function. */
#define HAVE_EVENT_GET_VERSION_NUMBER 1

/* Define to 1 if you have the `EVP_PBE_scrypt' function. */
/* #undef HAVE_EVP_PBE_SCRYPT */

/* Define to 1 if you have the `evutil_secure_rng_init' function. */
#define HAVE_EVUTIL_SECURE_RNG_INIT 1

/* Define to 1 if you have the `evutil_secure_rng_set_urandom_device_file'
   function. */
#define HAVE_EVUTIL_SECURE_RNG_SET_URANDOM_DEVICE_FILE 1

/* Define to 1 if you have the <execinfo.h> header file. */
/* #undef HAVE_EXECINFO_H */

/* Defined if we have extern char **environ already declared */
#define HAVE_EXTERN_ENVIRON_DECLARED 1

/* Define to 1 if you have the <fcntl.h> header file. */
/* #define HAVE_FCNTL_H 1 */

/* Define to 1 if you have the `flock' function. */
/* #undef HAVE_FLOCK */

/* Define to 1 if you have the `ftime' function. */
/* #define HAVE_FTIME 1 */

/* Define to 1 if you have the `getaddrinfo' function. */
/* #undef HAVE_GETADDRINFO */

/* Define this if you have any gethostbyname_r() */
/* #undef HAVE_GETHOSTBYNAME_R */

/* Define this if gethostbyname_r takes 3 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_3_ARG */

/* Define this if gethostbyname_r takes 5 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_5_ARG */

/* Define this if gethostbyname_r takes 6 arguments */
/* #undef HAVE_GETHOSTBYNAME_R_6_ARG */

/* Define to 1 if you have the `getifaddrs' function. */
/* #undef HAVE_GETIFADDRS */

/* Define to 1 if you have the `getpass' function. */
/* #undef HAVE_GETPASS */

/* Define to 1 if you have the `getresgid' function. */
/* #undef HAVE_GETRESGID */

/* Define to 1 if you have the `getresuid' function. */
/* #undef HAVE_GETRESUID */

/* Define to 1 if you have the `getrlimit' function. */
/* #undef HAVE_GETRLIMIT */

/* Define to 1 if you have the `gettimeofday' function. */
/* #define HAVE_GETTIMEOFDAY 1 */

/* Define to 1 if you have the `gmtime_r' function. */
/* #undef HAVE_GMTIME_R */

/* Define to 1 if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* Define to 1 if you have the <ifaddrs.h> header file. */
/* #undef HAVE_IFADDRS_H */

/* Define to 1 if you have the `inet_aton' function. */
/* #undef HAVE_INET_ATON */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */

/* Define to 1 if you have the `ioctl' function. */
/* #undef HAVE_IOCTL */

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to 1 if you have the <libscrypt.h> header file. */
/* #undef HAVE_LIBSCRYPT_H */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/if.h> header file. */
/* #undef HAVE_LINUX_IF_H */

/* Define to 1 if you have the <linux/netfilter_ipv4.h> header file. */
/* #undef HAVE_LINUX_NETFILTER_IPV4_H */

/* Define to 1 if you have the <linux/netfilter_ipv6/ip6_tables.h> header
   file. */
/* #undef HAVE_LINUX_NETFILTER_IPV6_IP6_TABLES_H */

/* Define to 1 if you have the <linux/types.h> header file. */
/* #undef HAVE_LINUX_TYPES_H */

/* Define to 1 if you have the `llround' function. */
/*#define HAVE_LLROUND */

/* Define to 1 if you have the `localtime_r' function. */
/* #undef HAVE_LOCALTIME_R */

/* Define to 1 if you have the `lround' function. */
/*#define HAVE_LROUND 1*/

/* Define to 1 if you have the <machine/limits.h> header file. */
/* #undef HAVE_MACHINE_LIMITS_H */

/* Defined if the compiler supports __FUNCTION__ */
#define HAVE_MACRO__FUNCTION__ 1

/* Defined if the compiler supports __FUNC__ */
/* #undef HAVE_MACRO__FUNC__ */

/* Defined if the compiler supports __func__ */
#define HAVE_MACRO__func__ 1

/* Define to 1 if you have the `mallinfo' function. */
/* #undef HAVE_MALLINFO */

/* Define to 1 if you have the <malloc.h> header file. */
/* #define HAVE_MALLOC_H 1 */

/* Define to 1 if you have the <malloc/malloc.h> header file. */
/* #undef HAVE_MALLOC_MALLOC_H */

/* Define to 1 if you have the <malloc_np.h> header file. */
/* #undef HAVE_MALLOC_NP_H */

/* Define to 1 if you have the `memmem' function. */
/* #undef HAVE_MEMMEM */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mlockall' function. */
/* #undef HAVE_MLOCKALL */

/* Define to 1 if you have the <nacl/crypto_scalarmult_curve25519.h> header
   file. */
/* #undef HAVE_NACL_CRYPTO_SCALARMULT_CURVE25519_H */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in6.h> header file. */
/* #undef HAVE_NETINET_IN6_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if you have the <net/if.h> header file. */
/* #undef HAVE_NET_IF_H */

/* Define to 1 if you have the <net/pfvar.h> header file. */
/* #undef HAVE_NET_PFVAR_H */

/* Define to 1 if you have the `pipe' function. */
/* #undef HAVE_PIPE */

/* Define to 1 if you have the `pipe2' function. */
/* #undef HAVE_PIPE2 */

/* Define to 1 if you have the `prctl' function. */
/* #undef HAVE_PRCTL */

/* Define to 1 if you have the `pthread_create' function. */
/* #undef HAVE_PTHREAD_CREATE */
/* Define to 1 if you have the <pthread.h> header file. */
/* #undef HAVE_PTHREAD_H */

/* Define to 1 if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define to 1 if you have the `readpassphrase' function. */
/* #undef HAVE_READPASSPHRASE */

/* Define to 1 if you have the <readpassphrase.h> header file. */
/* #undef HAVE_READPASSPHRASE_H */

/* Define to 1 if you have the `rint' function. */
/*#define HAVE_RINT 1 */

/* Define to 1 if the system has the type `rlim_t'. */
/* #undef HAVE_RLIM_T */

/* Define to 1 if the system has the type `sa_family_t'. */
/* #undef HAVE_SA_FAMILY_T */

/* Define to 1 if you have the <seccomp.h> header file. */
/* #undef HAVE_SECCOMP_H */

/* Define to 1 if you have the `sigaction' function. */
/* #undef HAVE_SIGACTION */

/* Define to 1 if you have the <signal.h> header file. */
/* #define HAVE_SIGNAL_H 1 */

/* Define to 1 if you have the `socketpair' function. */
/* #undef HAVE_SOCKETPAIR */

/* Define to 1 if the system has the type `ssize_t'. */
/*#define HAVE_SSIZE_T 1*/

#define HAVE_SSIZE_T 1

/* Define to 1 if you have the `SSL_CIPHER_find' function. */
#define HAVE_SSL_CIPHER_FIND 1

/* Define to 1 if you have the `SSL_get_client_ciphers' function. */
#define HAVE_SSL_GET_CLIENT_CIPHERS 1

/* Define to 1 if you have the `SSL_get_client_random' function. */
#define HAVE_SSL_GET_CLIENT_RANDOM 1

/* Define to 1 if you have the `SSL_get_server_random' function. */
#define HAVE_SSL_GET_SERVER_RANDOM 1

/* Define to 1 if you have the `SSL_SESSION_get_master_key' function. */
#define HAVE_SSL_SESSION_GET_MASTER_KEY 1

/* Define to 1 if you have the `statvfs' function. */
/* #undef HAVE_STATVFS */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strnlen' function. */
/* #undef HAVE_STRNLEN */

/* Define to 1 if you have the `strptime' function. */
/* #undef HAVE_STRPTIME */

/* Define to 1 if you have the `strtok_r' function. */
/* #undef HAVE_STRTOK_R */

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if `min_heap_idx' is a member of `struct event'. */
/* #undef HAVE_STRUCT_EVENT_MIN_HEAP_IDX */

/* Define to 1 if the system has the type `struct in6_addr'. */
/* #define HAVE_STRUCT_IN6_ADDR 1 */

/* Define to 1 if `s6_addr16' is a member of `struct in6_addr'. */
/* #undef HAVE_STRUCT_IN6_ADDR_S6_ADDR16 */

/* Define to 1 if `s6_addr32' is a member of `struct in6_addr'. */
/* #undef HAVE_STRUCT_IN6_ADDR_S6_ADDR32 */

/* Define to 1 if the system has the type `struct sockaddr_in6'. */
/* #define HAVE_STRUCT_SOCKADDR_IN6 1 */

/* Define to 1 if `sin6_len' is a member of `struct sockaddr_in6'. */
/* #undef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN */

/* Define to 1 if `sin_len' is a member of `struct sockaddr_in'. */
/* #undef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

/* Define to 1 if `get_cipher_by_char' is a member of `struct ssl_method_st'.
   */
/*#define HAVE_STRUCT_SSL_METHOD_ST_GET_CIPHER_BY_CHAR 1*/

/* Define to 1 if `tv_sec' is a member of `struct timeval'. */
/* #define HAVE_STRUCT_TIMEVAL_TV_SEC 1 */

/* Define to 1 if you have the `sysconf' function. */
/* #undef HAVE_SYSCONF */

/* Define to 1 if you have the `sysctl' function. */
/* #undef HAVE_SYSCTL */

/* Define to 1 if you have the <syslog.h> header file. */
/* #undef HAVE_SYSLOG_H */

/* Have systemd */
/* #undef HAVE_SYSTEMD */

/* Have systemd v209 or more */
/* #undef HAVE_SYSTEMD_209 */

/* Define to 1 if you have the <sys/eventfd.h> header file. */
/* #undef HAVE_SYS_EVENTFD_H */

/* Define to 1 if you have the <sys/fcntl.h> header file. */
/*#define HAVE_SYS_FCNTL_H 1*/

/* Define to 1 if you have the <sys/file.h> header file. */
/*#define HAVE_SYS_FILE_H 1 */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
/* #undef HAVE_SYS_IOCTL_H */

/* Define to 1 if you have the <sys/limits.h> header file. */
/* #undef HAVE_SYS_LIMITS_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/param.h> header file. */
/*#define HAVE_SYS_PARAM_H 1*/

/* Define to 1 if you have the <sys/prctl.h> header file. */
/* #undef HAVE_SYS_PRCTL_H */

/* Define to 1 if you have the <sys/resource.h> header file. */
/* #undef HAVE_SYS_RESOURCE_H */

/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/statvfs.h> header file. */
/* #undef HAVE_SYS_STATVFS_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
/* #define HAVE_SYS_STAT_H 1 */

/* Define to 1 if you have the <sys/sysctl.h> header file. */
/* #undef HAVE_SYS_SYSCTL_H */

/* Define to 1 if you have the <sys/syslimits.h> header file. */
/* #undef HAVE_SYS_SYSLIMITS_H */

/* Define to 1 if you have the <sys/time.h> header file. */
/*#define HAVE_SYS_TIME_H 1 */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/ucontext.h> header file. */
/* #undef HAVE_SYS_UCONTEXT_H */

/* Define to 1 if you have the <sys/un.h> header file. */
/* #undef HAVE_SYS_UN_H */

/* Define to 1 if you have the <sys/utime.h> header file. */
/* #define HAVE_SYS_UTIME_H 1 */

/* Define to 1 if you have the <sys/wait.h> header file. */
/* #undef HAVE_SYS_WAIT_H */

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `TLS_method' function. */
/* #undef HAVE_TLS_METHOD */

/* Define to 1 if you have the <ucontext.h> header file. */
/* #undef HAVE_UCONTEXT_H */

/* Define to 1 if the system has the type `uint'. */
/* #undef HAVE_UINT */

/* Define to 1 if you have the `uname' function. */
/* #undef HAVE_UNAME */

/* Define to 1 if you have the <unistd.h> header file. */
/*#define HAVE_UNISTD_H 1*/

/* Define to 1 if you have the `usleep' function. */
#define HAVE_USLEEP 1

/* Define to 1 if you have the <utime.h> header file. */
/*#define HAVE_UTIME_H 1 */

/* Define to 1 if the system has the type `u_char'. */
/* #undef HAVE_U_CHAR */

/* Define to 1 if you have the `vasprintf' function. */
/* #undef HAVE_VASPRINTF */

/* Define to 1 if you have the `_NSGetEnviron' function. */
/* #undef HAVE__NSGETENVIRON */

/* Define to 1 if you have the `_vscprintf' function. */
/* #define HAVE__VSCPRINTF 1 */

/* Defined if we want to keep track of how much of each kind of resource we
   download. */
/* #undef INSTRUMENT_DOWNLOADS */

/* name of the syslog facility */
#define LOGFACILITY LOG_DAEMON

/* Define to 1 iff malloc(0) returns a pointer */
#define MALLOC_ZERO_WORKS 1

/* Define to 1 iff memset(0) sets pointers to NULL */
#define NULL_REP_IS_ZERO_BYTES 1

/* "Define to handle pf on OpenBSD properly" */
/* #undef OPENBSD */

/* Name of package */
#define PACKAGE "tor"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "tor"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "tor 0.2.7.6"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "tor"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.2.7.6"

/* How to access the PC from a struct ucontext */
/* #undef PC_FROM_UCONTEXT */

/* Define to 1 iff right-shifting a negative value performs sign-extension */
#define RSHIFT_DOES_SIGN_EXTEND 1

/* The size of `cell_t', as computed by sizeof. */
#define SIZEOF_CELL_T 0

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `int16_t', as computed by sizeof. */
#define SIZEOF_INT16_T 2

/* The size of `int32_t', as computed by sizeof. */
#define SIZEOF_INT32_T 4

/* The size of `int64_t', as computed by sizeof. */
#define SIZEOF_INT64_T 8

/* The size of `int8_t', as computed by sizeof. */
#define SIZEOF_INT8_T 1

/* The size of `intptr_t', as computed by sizeof. */
#define SIZEOF_INTPTR_T 8

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `pid_t', as computed by sizeof. */
#define SIZEOF_PID_T 4

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 8

/* The size of `socklen_t', as computed by sizeof. */
#define SIZEOF_SOCKLEN_T 0

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of `uint16_t', as computed by sizeof. */
#define SIZEOF_UINT16_T 2

/* The size of `uint32_t', as computed by sizeof. */
#define SIZEOF_UINT32_T 4

/* The size of `uint64_t', as computed by sizeof. */
#define SIZEOF_UINT64_T 8

/* The size of `uint8_t', as computed by sizeof. */
#define SIZEOF_UINT8_T 1

/* The size of `uintptr_t', as computed by sizeof. */
#define SIZEOF_UINTPTR_T 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* The size of `__int64', as computed by sizeof. */
#define SIZEOF___INT64 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define if time_t is signed */
#define TIME_T_IS_SIGNED 1

/* Defined if we're going to use Libevent's buffered IO API */
/* #undef USE_BUFFEREVENTS */

/* Defined if we should use an internal curve25519_donna{,_c64} implementation
   */
#define USE_CURVE25519_DONNA 1

/* Defined if we should use a curve25519 from nacl */
/* #undef USE_CURVE25519_NACL */

/* Debug memory allocation library */
/* #undef USE_DMALLOC */

/* "Define to enable transparent proxy support" */
/* #undef USE_TRANSPARENT */

/* Define to 1 iff we represent negative integers with two's complement */
#define USING_TWOS_COMPLEMENT 1

/* Version number of package */
#define VERSION "0.2.7.6"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define on some platforms to activate x_r() functions in time.h */
/* #undef _REENTRANT */


#ifdef _WIN32
/* Defined to access windows functions and definitions for >=WinXP */
# ifndef WINVER
#  define WINVER 0x0501
# endif

/* Defined to access _other_ windows functions and definitions for >=WinXP */
# ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0501
# endif

/* Defined to avoid including some windows headers as part of Windows.h */
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN 1
# endif
#endif

#define SHARE_DATADIR ""
#define HAVE_EVENT_BASE_LOOPEXIT

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#define DISABLE_ENGINES 1

#pragma comment(lib, "ws2_32.lib")

#define inline __inline

// This is a top header;
#define TOR_SGX 1 // SGX

/* For Linux types */
typedef unsigned int uid_t;
typedef unsigned int pid_t;
typedef unsigned int gid_t;
typedef long off_t;

typedef uid_t __uid_t;
typedef pid_t __pid_t;
typedef gid_t __gid_t;

/* Type for data associated with a signal.  */
typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;

# define __SI_MAX_SIZE     128
# define __SI_PAD_SIZE     ((__SI_MAX_SIZE / sizeof (int)) - 4)

/* The passwd structure.  */
struct passwd
{
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  uid_t pw_uid;		/* User ID.  */
  gid_t pw_gid;		/* Group ID.  */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* Shell program.  */
};

struct group {
	char	*gr_name;		/* [XBD] group name */
	char	*gr_passwd;		/* [???] group password */
	gid_t	gr_gid;			/* [XBD] group id */
	char	**gr_mem;		/* [XBD] group members */
};

#define WNOHANG		1
#define WUNTRACED	2

/* Type of a signal handler.  */
typedef void (*__sighandler_t)(int);

#define SIG_DFL ((__sighandler_t)0)     /* default signal handling */
#define SIG_IGN ((__sighandler_t)1)     /* ignore signal */
#define SIG_ERR ((__sighandler_t)-1)    /* error return from signal */


typedef struct siginfo
  {
    int si_signo;		/* Signal number.  */
    int si_errno;		/* If non-zero, an errno value associated with
				   this signal, as defined in <errno.h>.  */
    int si_code;		/* Signal code.  */
    int __pad0;			/* Explicit padding.  */

    union
      {
	int _pad[__SI_PAD_SIZE];

	 /* kill().  */
	struct
	  {
	    __pid_t si_pid;	/* Sending process ID.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	  } _kill;

	/* POSIX.1b timers.  */
	struct
	  {
	    int si_tid;		/* Timer ID.  */
	    int si_overrun;	/* Overrun count.  */
	    sigval_t si_sigval;	/* Signal value.  */
	  } _timer;

	/* POSIX.1b signals.  */
	struct
	  {
	    __pid_t si_pid;	/* Sending process ID.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	    sigval_t si_sigval;	/* Signal value.  */
	  } _rt;

	/* SIGCHLD.  */
	struct
	  {
	    __pid_t si_pid;	/* Which child.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	    int si_status;	/* Exit value or signal.  */
	    __clock_t si_utime;
	    __clock_t si_stime;
	  } _sigchld;

	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
	struct
	  {
	    void *si_addr;	/* Faulting insn/memory ref.  */
	    int _si_imm;
	    unsigned int _si_flags;
	    unsigned long int _si_isr;
	  } _sigfault;

	/* SIGPOLL.  */
	struct
	  {
	    long int si_band;	/* Band event for SIGPOLL.  */
	    int si_fd;
	  } _sigpoll;
      } _sifields;
  } siginfo_t;

#ifdef __KERNEL__
/* Most things should be clean enough to redefine this at will, if care
   is taken to make libc match.  */
#include <asm/sigcontext.h>
#define _NSIG           _SIGCONTEXT_NSIG
#define _NSIG_BPW       _SIGCONTEXT_NSIG_BPW
#define _NSIG_WORDS     _SIGCONTEXT_NSIG_WORDS

typedef unsigned long old_sigset_t;             /* at least 32 bits */

typedef struct {
        unsigned long sig[_NSIG_WORDS];
} sigset_t;

#else
/* Here we must cater to libcs that poke about in kernel headers.  */

#define NSIG            32
typedef unsigned long sigset_t;

#endif /* __KERNEL__ */

#ifdef __KERNEL__
struct old_sigaction {
        __sighandler_t sa_handler;
        old_sigset_t sa_mask;
        unsigned long sa_flags;
        void (*sa_restorer)(void);
};

struct sigaction {
        __sighandler_t sa_handler;
        unsigned long sa_flags;
        void (*sa_restorer)(void);
        sigset_t sa_mask;               /* mask last for extensibility */
};

struct k_sigaction {
        struct sigaction sa;
};
#else
/* Here we must cater to libcs that poke about in kernel headers.  */

struct sigaction {
        union {
          __sighandler_t _sa_handler;
          void (*_sa_sigaction)(int, struct siginfo *, void *);
        } _u;
        sigset_t sa_mask;
        unsigned long sa_flags;
        void (*sa_restorer)(void);
};

#define sa_handler      _u._sa_handler
#define sa_sigaction    _u._sa_sigaction

#endif /* __KERNEL__ */

#ifndef HAVE_ARCH_STRUCT_FLOCK
#ifndef __ARCH_FLOCK_PAD
#define __ARCH_FLOCK_PAD
#endif

typedef long            __kernel_long_t;
typedef __kernel_long_t __kernel_off_t;
typedef int             __kernel_pid_t;

struct flock {
        short   l_type;
        short   l_whence;
        __kernel_off_t  l_start;
        __kernel_off_t  l_len;
        __kernel_pid_t  l_pid;
        __ARCH_FLOCK_PAD
};
#endif

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;    /* Epoll events */
    epoll_data_t data;      /* User data variable */
};

#define	NGROUPS_MAX	16	/* max number of supplemental group id's */

#define SIG_SETMASK 3

#define PTHREAD_MUTEX_NORMAL     0
#define PTHREAD_MUTEX_RECURSIVE  1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT    PTHREAD_MUTEX_NORMAL

typedef uint64_t pthread_t;

typedef int pthread_key_t;
typedef int pthread_attr_t;
typedef int pthread_mutexattr_t;
typedef int pthread_condattr_t;

/* for posix fcntl() and lockf() */
#ifndef F_RDLCK
#define F_RDLCK         0
#define F_WRLCK         1
#define F_UNLCK         2
#endif

#define F_DUPFD         0       /* dup */
#define F_GETFD         1       /* get close_on_exec */
#define F_SETFD         2       /* set/clear close_on_exec */
#define F_GETFL         3       /* get file->f_flags */
#define F_SETFL         4       /* set file->f_flags */
#ifndef F_GETLK
#define F_GETLK         5
#define F_SETLK         6
#define F_SETLKW        7
#endif
#ifndef F_SETOWN
#define F_SETOWN        8       /* for sockets. */
#define F_GETOWN        9       /* for sockets. */
#endif
#ifndef F_SETSIG
#define F_SETSIG        10      /* for sockets. */
#define F_GETSIG        11      /* for sockets. */
#endif

#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPOLL		SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR		30
#define SIGSYS		31
#define	SIGUNUSED	31

/* These should not be considered constants from userland.  */
#define SIGRTMIN	32
#define SIGRTMAX	_NSIG

//#define INADDR_ANY              (ULONG)0x00000000
#define INADDR_ANY              (unsigned long)0x00000000
#define INADDR_LOOPBACK         0x7f000001

/*
 * Option flags per-socket.
 */
#define SO_DEBUG       0x0001  /* turn on debugging info recording */
#define SO_ACCEPTCONN  0x0002  /* socket has had listen() */
#define SO_REUSEADDR   0x0004  /* allow local address reuse */
#define SO_KEEPALIVE   0x0008  /* keep connections alive */
#define SO_DONTROUTE   0x0010  /* just use interface addresses */
#define SO_BROADCAST   0x0020  /* permit sending of broadcast msgs */
#define SO_USELOOPBACK 0x0040  /* bypass hardware when possible */
#define SO_LINGER      0x0080  /* linger on close if data present */
#define SO_OOBINLINE   0x0100  /* leave received OOB data in line */
#define SO_REUSEPORT   0x0200  /* allow local address & port reuse */

/*
 * Additional options, not kept in so_options.
 */
#define SO_SNDBUF	0x1001		/* send buffer size */
#define SO_RCVBUF	0x1002		/* receive buffer size */
#define SO_SNDLOWAT	0x1003		/* send low-water mark */
#define SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define SO_SNDTIMEO	0x1005		/* send timeout */
#define SO_RCVTIMEO	0x1006		/* receive timeout */
#define	SO_ERROR	0x1007		/* get error status and clear */
#define	SO_TYPE		0x1008		/* get socket type */

/*
 * Maximum queue length specifiable by listen.
 */
#define	SOMAXCONN	5

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	SOL_SOCKET	0xffff		/* options for socket level */

#if 0
#define EPERM           1
#define ENOENT          2
#define ESRCH           3
#define EINTR           4
#define EIO             5
#define ENXIO           6
#define E2BIG           7
#define ENOEXEC         8
#define EBADF           9
#define ECHILD          10
#define EAGAIN          11
#define ENOMEM          12
#define EACCES          13
#define EFAULT          14
#define EBUSY           16
#define EEXIST          17
#define EXDEV           18
#define ENODEV          19
#define ENOTDIR         20
#define EISDIR          21
#define ENFILE          23
#define EMFILE          24
#define ENOTTY          25
#define EFBIG           27
#define ENOSPC          28
#define ESPIPE          29
#define EROFS           30
#define EMLINK          31
#define EPIPE           32
#define EDOM            33
#define EDEADLK         36
#define ENAMETOOLONG    38
#define ENOLCK          39
#define ENOSYS          40
#define ENOTEMPTY       41

/* Error codes used in the Secure CRT functions */

#ifndef RC_INVOKED
#if !defined (_SECURECRT_ERRCODE_VALUES_DEFINED)
#define _SECURECRT_ERRCODE_VALUES_DEFINED
#define EINVAL          22
#define ERANGE          34
#define EILSEQ          42
#define STRUNCATE       80
#endif  /* !defined (_SECURECRT_ERRCODE_VALUES_DEFINED) */
#endif  /* RC_INVOKED */

/* Support EDEADLOCK for compatibility with older MS-C versions */
#define EDEADLOCK       EDEADLK

/* POSIX SUPPLEMENT */
#define EADDRINUSE      100
#define EADDRNOTAVAIL   101
#define EAFNOSUPPORT    102
#define EALREADY        103
#define EBADMSG         104
#define ECANCELED       105
#define ECONNABORTED    106
#define ECONNREFUSED    107
#define ECONNRESET      108
#define EDESTADDRREQ    109
#define EHOSTUNREACH    110
#define EIDRM           111
#define EINPROGRESS     112
#define EISCONN         113
#define ELOOP           114
#define EMSGSIZE        115
#define ENETDOWN        116
#define ENETRESET       117
#define ENETUNREACH     118
#define ENOBUFS         119
#define ENODATA         120
#define ENOLINK         121
#define ENOMSG          122
#define ENOPROTOOPT     123
#define ENOSR           124
#define ENOSTR          125
#define ENOTCONN        126
#define ENOTRECOVERABLE 127
#define ENOTSOCK        128
#define ENOTSUP         129
#define EOPNOTSUPP      130
#define EOTHER          131
#define EOVERFLOW       132
#define EOWNERDEAD      133
#define EPROTO          134
#define EPROTONOSUPPORT 135
#define EPROTOTYPE      136
#define ETIME           137
#define ETIMEDOUT       138
#define ETXTBSY         139
#define EWOULDBLOCK     140
#endif

#define _O_RDONLY       0x0000  /* open for reading only */
#define _O_WRONLY       0x0001  /* open for writing only */
#define _O_RDWR         0x0002  /* open for reading and writing */
#define _O_NONBLOCK     0x4000
#define _O_APPEND       0x0008  /* writes done at eof */

#define _O_CREAT        0x0100  /* create and open file */
#define _O_TRUNC        0x0200  /* open and truncate */
#define _O_EXCL         0x0400  /* open only if file doesn't already exist */

/* O_TEXT files have <cr><lf> sequences translated to <lf> on read()'s,
** and <lf> sequences translated to <cr><lf> on write()'s
*/

#define _O_TEXT         0x4000  /* file mode is text (translated) */
#define _O_BINARY       0x8000  /* file mode is binary (untranslated) */
#define _O_WTEXT        0x10000 /* file mode is UTF16 (translated) */
#define _O_U16TEXT      0x20000 /* file mode is UTF16 no BOM (translated) */
#define _O_U8TEXT       0x40000 /* file mode is UTF8  no BOM (translated) */

/* macro to translate the C 2.0 name used to force binary mode for files */

#define _O_RAW  _O_BINARY

/* Open handle inherit bit */

#define _O_NOINHERIT    0x0080  /* child process doesn't inherit file */

/* Temporary file bit - file is deleted when last handle is closed */

#define _O_TEMPORARY    0x0040  /* temporary file bit */

/* temporary access hint */

#define _O_SHORT_LIVED  0x1000  /* temporary storage file, try not to flush */

/* directory access hint */

#define _O_OBTAIN_DIR   0x2000  /* get information about a directory */

/* sequential/random access hints */

#define _O_SEQUENTIAL   0x0020  /* file access is primarily sequential */
#define _O_RANDOM       0x0010  /* file access is primarily random */

#define O_RDONLY        _O_RDONLY
#define O_WRONLY        _O_WRONLY
#define O_RDWR          _O_RDWR
#define O_NONBLOCK	_O_NONBLOCK
#define O_APPEND        _O_APPEND
#define O_CREAT         _O_CREAT
#define O_TRUNC         _O_TRUNC
#define O_EXCL          _O_EXCL
#define O_TEXT          _O_TEXT
#define O_BINARY        _O_BINARY
#define O_RAW           _O_BINARY
#define O_TEMPORARY     _O_TEMPORARY
#define O_NOINHERIT     _O_NOINHERIT
#define O_SEQUENTIAL    _O_SEQUENTIAL
#define O_RANDOM        _O_RANDOM

#ifndef SEEK_SET
#define SEEK_SET                0       // Seek relative to begining of file
#define SEEK_CUR                1       // Seek relative to current file position
#define SEEK_END                2       // Seek relative to end of file
#endif

#define	_LK_UNLOCK	0	/* Unlock */
#define	_LK_LOCK	1	/* Lock */
#define	_LK_NBLCK	2	/* Non-blocking lock */
#define	_LK_RLCK	3	/* Lock for read only */
#define	_LK_NBRLCK	4	/* Non-blocking lock for read only */

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004  
#define FILE_ATTRIBUTE_READONLY             0x00000001  
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  
#define FILE_ATTRIBUTE_DEVICE               0x00000040  
#define FILE_ATTRIBUTE_NORMAL               0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  
#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  
#define FILE_ATTRIBUTE_INTEGRITY_STREAM     0x00008000  
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000  
#define FILE_ATTRIBUTE_NO_SCRUB_DATA        0x00020000  
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001   
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002   
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004   
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008   
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010   
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020   
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040   
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100   
#define FILE_ACTION_ADDED                   0x00000001   
#define FILE_ACTION_REMOVED                 0x00000002   
#define FILE_ACTION_MODIFIED                0x00000003   
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004   
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005   
#define MAILSLOT_NO_MESSAGE             ((DWORD)-1) 
#define MAILSLOT_WAIT_FOREVER           ((DWORD)-1) 
#define FILE_CASE_SENSITIVE_SEARCH          0x00000001  
#define FILE_CASE_PRESERVED_NAMES           0x00000002  
#define FILE_UNICODE_ON_DISK                0x00000004  
#define FILE_PERSISTENT_ACLS                0x00000008  
#define FILE_FILE_COMPRESSION               0x00000010  
#define FILE_VOLUME_QUOTAS                  0x00000020  
#define FILE_SUPPORTS_SPARSE_FILES          0x00000040  
#define FILE_SUPPORTS_REPARSE_POINTS        0x00000080  
#define FILE_SUPPORTS_REMOTE_STORAGE        0x00000100  
#define FILE_VOLUME_IS_COMPRESSED           0x00008000  
#define FILE_SUPPORTS_OBJECT_IDS            0x00010000  
#define FILE_SUPPORTS_ENCRYPTION            0x00020000  
#define FILE_NAMED_STREAMS                  0x00040000  
#define FILE_READ_ONLY_VOLUME               0x00080000  
#define FILE_SEQUENTIAL_WRITE_ONCE          0x00100000  
#define FILE_SUPPORTS_TRANSACTIONS          0x00200000  
#define FILE_SUPPORTS_HARD_LINKS            0x00400000  
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES   0x00800000  
#define FILE_SUPPORTS_OPEN_BY_FILE_ID       0x01000000  
#define FILE_SUPPORTS_USN_JOURNAL           0x02000000  
#define FILE_SUPPORTS_INTEGRITY_STREAMS     0x04000000  
#define FILE_INVALID_FILE_ID               ((LONGLONG)-1LL) 

#define CREATE_NEW          1
#define CREATE_ALWAYS       2
#define OPEN_EXISTING       3
#define OPEN_ALWAYS         4
#define TRUNCATE_EXISTING   5

/* For windows related type */
/*
typedef unsigned long long HANDLE;			// HANDLE as unsigned long long
typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef ULONG *PULONG;
typedef void *PVOID;
typedef char TCHAR;
typedef char CHAR;
typedef unsigned short WCHAR;
typedef CHAR *LPSTR;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef BYTE *LPBYTE;
typedef void *LPVOID;
typedef ULONGLONG  DWORDLONG;
typedef unsigned short USHORT;

typedef WCHAR *LPWSTR;
#ifdef UNICODE
typedef LPWSTR LPTSTR;
#else
typedef LPSTR LPTSTR;
#endif
#define WINAPI __stdcall

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CHAR *PCHAR, *LPCH, *PCH;
typedef ULONG_PTR HCRYPTPROV;
*/

/* Window Error code and flags*/
/*
#define NO_ERROR 0L
#define ERROR_BUFFER_OVERFLOW 111L

#define GAA_FLAG_SKIP_ANYCAST	0x0002
#define GAA_FLAG_SKIP_MULTICAST	0x0004
#define GAA_FLAG_SKIP_DNS_SERVER	0x0008

#ifndef WSABASEERR
#define WSABASEERR 10000
#define WSAEINTR 10004L
#define WSAEBADF 10009L
#define WSAEACCES 10013L
#define WSAEFAULT 10014L
#define WSAEINVAL 10022L
#define WSAEMFILE 10024L
#define WSAEWOULDBLOCK 10035L
#define WSAEINPROGRESS 10036L
#define WSAEALREADY 10037L
#define WSAENOTSOCK 10038L
#define WSAEDESTADDRREQ 10039L
#define WSAEMSGSIZE 10040L
#define WSAEPROTOTYPE 10041L
#define WSAENOPROTOOPT 10042L
#define WSAEPROTONOSUPPORT 10043L
#define WSAESOCKTNOSUPPORT 10044L
#define WSAEOPNOTSUPP 10045L
#define WSAEPFNOSUPPORT 10046L
#define WSAEAFNOSUPPORT 10047L
#define WSAEADDRINUSE 10048L
#define WSAEADDRNOTAVAIL 10049L
#define WSAENETDOWN 10050L
#define WSAENETUNREACH 10051L
#define WSAENETRESET 10052L
#define WSAECONNABORTED 10053L
#define WSAECONNRESET 10054L
#define WSAENOBUFS 10055L
#define WSAEISCONN 10056L
#define WSAENOTCONN 10057L
#define WSAESHUTDOWN 10058L
#define WSAETOOMANYREFS 10059L
#define WSAETIMEDOUT 10060L
#define WSAECONNREFUSED 10061L
#define WSAELOOP 10062L
#define WSAENAMETOOLONG 10063L
#define WSAEHOSTDOWN 10064L
#define WSAEHOSTUNREACH 10065L
#define WSAENOTEMPTY 10066L
#define WSAEPROCLIM 10067L
#define WSAEUSERS 10068L
#define WSAEDQUOT 10069L
#define WSAESTALE 10070L
#define WSAEREMOTE 10071L
#define WSASYSNOTREADY 10091L
#define WSAVERNOTSUPPORTED 10092L
#define WSANOTINITIALISED 10093L
#define WSAEDISCON 10101L
#define WSAENOMORE 10102L
#define WSAECANCELLED 10103L
#define WSAEINVALIDPROCTABLE 10104L
#define WSAEINVALIDPROVIDER 10105L
#define WSAEPROVIDERFAILEDINIT 10106L
#define WSASYSCALLFAILURE 10107L
#define WSASERVICE_NOT_FOUND 10108L
#define WSATYPE_NOT_FOUND 10109L
#define WSA_E_NO_MORE 10110L
#define WSA_E_CANCELLED 10111L
#define WSAEREFUSED 10112L
#define WSAHOST_NOT_FOUND 11001L
#define WSATRY_AGAIN 11002L
#define WSANO_RECOVERY 11003L
#define WSANO_DATA 11004L
#define WSA_QOS_RECEIVERS 11005L
#define WSA_QOS_SENDERS 11006L
#define WSA_QOS_NO_SENDERS 11007L
#define WSA_QOS_NO_RECEIVERS 11008L
#define WSA_QOS_REQUEST_CONFIRMED 11009L
#define WSA_QOS_ADMISSION_FAILURE 11010L
#define WSA_QOS_POLICY_FAILURE 11011L
#define WSA_QOS_BAD_STYLE 11012L
#define WSA_QOS_BAD_OBJECT 11013L
#define WSA_QOS_TRAFFIC_CTRL_ERROR 11014L
#define WSA_QOS_GENERIC_ERROR 11015L
#define WSA_QOS_ESERVICETYPE 11016L
#define WSA_QOS_EFLOWSPEC 11017L
#define WSA_QOS_EPROVSPECBUF 11018L
#define WSA_QOS_EFILTERSTYLE 11019L
#define WSA_QOS_EFILTERTYPE 11020L
#define WSA_QOS_EFILTERCOUNT 11021L
#define WSA_QOS_EOBJLENGTH 11022L
#define WSA_QOS_EFLOWCOUNT 11023L
#define WSA_QOS_EUNKOWNPSOBJ 11024L
#define WSA_QOS_EPOLICYOBJ 11025L
#define WSA_QOS_EFLOWDESC 11026L
#define WSA_QOS_EPSFLOWSPEC 11027L
#define WSA_QOS_EPSFILTERSPEC 11028L
#define WSA_QOS_ESDMODEOBJ 11029L
#define WSA_QOS_ESHAPERATEOBJ 11030L
#define WSA_QOS_RESERVED_PETYPE 11031L
#endif // !WSABASEERR
*/

#if 0
typedef UINT_PTR        SOCKET;
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)

#ifdef  UNICODE                     
#define __TEXT(quote) L##quote      
#else   /* UNICODE */               
#define __TEXT(quote) quote         
#endif /* UNICODE */                
#define TEXT(quote) __TEXT(quote)   
#endif

// Sgx
/* For networking */
/*--------------------------------------------------------*/
typedef __uint32_t in_addr_t;
struct in_addr {
      in_addr_t s_addr;
};

 /* Socket types. */
#define SOCK_STREAM	1		/* stream (connection) socket	*/
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* linux specific way of	*/
					/* getting packets at the dev	*/
					/* level.  For writing rarp and	*/
					/* other similar things on the	*/
					/* user level.			*/

#define AF_UNSPEC       0               // unspecified
#define AF_UNIX         1               // local to host (pipes, portals)
#define AF_INET         2               // internetwork: UDP, TCP, etc.
#define AF_IMPLINK      3               // arpanet imp addresses
#define AF_PUP          4               // pup protocols: e.g. BSP
#define AF_CHAOS        5               // mit CHAOS protocols
#define AF_NS           6               // XEROX NS protocols
#define AF_IPX          AF_NS           // IPX protocols: IPX, SPX, etc.
#define AF_ISO          7               // ISO protocols
#define AF_OSI          AF_ISO          // OSI is ISO
#define AF_ECMA         8               // european computer manufacturers
#define AF_DATAKIT      9               // datakit protocols
#define AF_CCITT        10              // CCITT protocols, X.25 etc
#define AF_SNA          11              // IBM SNA
#define AF_DECnet       12              // DECnet
#define AF_DLI          13              // Direct data link interface
#define AF_LAT          14              // LAT
#define AF_HYLINK       15              // NSC Hyperchannel
#define AF_APPLETALK    16              // AppleTalk
#define AF_NETBIOS      17              // NetBios-style addresses
#define AF_VOICEVIEW    18              // VoiceView
#define AF_FIREFOX      19              // Protocols from Firefox
#define AF_UNKNOWN1     20              // Somebody is using this!
#define AF_BAN          21              // Banyan
#define AF_ATM          22              // Native ATM Services
#define AF_INET6        23              // Internetwork Version 6
#define AF_CLUSTER      24              // Microsoft Wolfpack
#define AF_12844        25              // IEEE 1284.4 WG AF
#define AF_IRDA         26              // IrDA
#define AF_NETDES       28              // Network Designers OSI & gateway

#define PF_UNSPEC       AF_UNSPEC
#define PF_UNIX         AF_UNIX
#define PF_INET         AF_INET
#define PF_IMPLINK      AF_IMPLINK
#define PF_PUP          AF_PUP
#define PF_CHAOS        AF_CHAOS
#define PF_NS           AF_NS
#define PF_IPX          AF_IPX
#define PF_ISO          AF_ISO
#define PF_OSI          AF_OSI
#define PF_ECMA         AF_ECMA
#define PF_DATAKIT      AF_DATAKIT
#define PF_CCITT        AF_CCITT
#define PF_SNA          AF_SNA
#define PF_DECnet       AF_DECnet
#define PF_DLI          AF_DLI
#define PF_LAT          AF_LAT
#define PF_HYLINK       AF_HYLINK
#define PF_APPLETALK    AF_APPLETALK
#define PF_VOICEVIEW    AF_VOICEVIEW
#define PF_FIREFOX      AF_FIREFOX
#define PF_UNKNOWN1     AF_UNKNOWN1
#define PF_BAN          AF_BAN
#define PF_ATM          AF_ATM
#define PF_INET6        AF_INET6

typedef enum {
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_HOPOPTS       = 0,  // IPv6 Hop-by-Hop options
#endif//(_WIN32_WINNT >= 0x0501)
    IPPROTO_ICMP          = 1,
    IPPROTO_IGMP          = 2,
    IPPROTO_GGP           = 3,
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_IPV4          = 4,
#endif//(_WIN32_WINNT >= 0x0501)
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_ST            = 5,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_TCP           = 6,
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_CBT           = 7,
    IPPROTO_EGP           = 8,
    IPPROTO_IGP           = 9,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_PUP           = 12,
    IPPROTO_UDP           = 17,
    IPPROTO_IDP           = 22,
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_RDP           = 27,
#endif//(_WIN32_WINNT >= 0x0600)

#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_IPV6          = 41, // IPv6 header
    IPPROTO_ROUTING       = 43, // IPv6 Routing header
    IPPROTO_FRAGMENT      = 44, // IPv6 fragmentation header
    IPPROTO_ESP           = 50, // encapsulating security payload
    IPPROTO_AH            = 51, // authentication header
    IPPROTO_ICMPV6        = 58, // ICMPv6
    IPPROTO_NONE          = 59, // IPv6 no next header
    IPPROTO_DSTOPTS       = 60, // IPv6 Destination options
#endif//(_WIN32_WINNT >= 0x0501)

    IPPROTO_ND            = 77,
#if(_WIN32_WINNT >= 0x0501)
    IPPROTO_ICLFXBM       = 78,
#endif//(_WIN32_WINNT >= 0x0501)
#if(_WIN32_WINNT >= 0x0600)
    IPPROTO_PIM           = 103,
    IPPROTO_PGM           = 113,
    IPPROTO_L2TP          = 115,
    IPPROTO_SCTP          = 132,
#endif//(_WIN32_WINNT >= 0x0600)
    IPPROTO_RAW           = 255,

    IPPROTO_MAX           = 256,
//
//  These are reserved for internal use by Windows.
//
    IPPROTO_RESERVED_RAW  = 257,
    IPPROTO_RESERVED_IPSEC  = 258,
    IPPROTO_RESERVED_IPSECOFFLOAD  = 259,
    IPPROTO_RESERVED_WNV = 260,
    IPPROTO_RESERVED_MAX  = 261
} IPPROTO, *PIPROTO;

/* POSIX.1g specifies this type name for the `sa_family' member.  */
//typedef unsigned short int sa_family_t;
//typedef USHORT ADDRESS_FAMILY;

typedef unsigned short sa_family_t;

/* This macro is used to declare the initial common members
   of the data types used for socket addresses, `struct sockaddr',
   `struct sockaddr_in', `struct sockaddr_un', etc.  */
#define __SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

#define __SOCKADDR_COMMON_SIZE  (sizeof (unsigned short int))

typedef __uint16_t in_port_t;

/* Structure describing a generic socket address.  */
typedef struct sockaddr
{
  __SOCKADDR_COMMON (sa_);    /* Common data: address family and length.  */
  char sa_data[14];           /* Address data.  */
} SOCKADDR, *PSOCKADDR, *LPSOCKADDR;

/* Structure describing an Internet socket address.  */
struct sockaddr_in {
	__SOCKADDR_COMMON (sin_);
	in_port_t sin_port;                 /* Port number.  */
	struct in_addr sin_addr;            /* Internet address.  */

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sin_zero[sizeof(struct sockaddr) -__SOCKADDR_COMMON_SIZE - sizeof (in_port_t) - sizeof (struct in_addr)];
};

#define IOCPARM_MASK    0x7f            /* parameters must be < 128 bytes */
#define IOC_VOID        0x20000000      /* no parameters */
#define IOC_OUT         0x40000000      /* copy out parameters */
#define IOC_IN          0x80000000      /* copy in parameters */
#define IOC_INOUT       (IOC_IN|IOC_OUT)
                                        /* 0x20000000 distinguishes new &
                                           old ioctl's */
#define _IO(x,y)        (IOC_VOID|((x)<<8)|(y))

#define _IOR(x,y,t)     (IOC_OUT|(((long)sizeof(t)&IOCPARM_MASK)<<16)|((x)<<8)|(y))

#define _IOW(x,y,t)     (IOC_IN|(((long)sizeof(t)&IOCPARM_MASK)<<16)|((x)<<8)|(y))

#define FIONREAD    _IOR('f', 127, u_long) /* get # bytes to read */
#define FIONBIO     _IOW('f', 126, u_long) /* set/clear non-blocking i/o */
#define FIOASYNC    _IOW('f', 125, u_long) /* set/clear async i/o */

/** Implementation of struct in6_addr for platforms that do not have it.
 * Generally, these platforms are ones without IPv6 support, but we want to
 * have a working in6_addr there anyway, so we can use it to parse IPv6
 * addresses. */
#if !defined(HAVE_STRUCT_IN6_ADDR)
struct in6_addr
{
  union {
    __uint8_t u6_addr8[16];
    __uint16_t u6_addr16[8];
    __uint32_t u6_addr32[4];
  } in6_u;
#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};
#endif

/* Ditto, for IPv6.  */
struct sockaddr_in6 {
     __SOCKADDR_COMMON (sin6_);
     in_port_t sin6_port;        /* Transport layer port # */
     __uint32_t sin6_flowinfo;     /* IPv6 flow information */
     struct in6_addr sin6_addr;  /* IPv6 address */
     __uint32_t sin6_scope_id;     /* IPv6 scope-id */
};

#define _SS_MAXSIZE 128                 // Maximum size
//#define _SS_ALIGNSIZE (sizeof(__int64)) // Desired alignment
#define _SS_ALIGNSIZE (sizeof(int64_t)) // Desired alignment

//#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof(USHORT))
//#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof(USHORT) + _SS_PAD1SIZE + _SS_ALIGNSIZE))
#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof(unsigned short))
#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof(unsigned short) + _SS_PAD1SIZE + _SS_ALIGNSIZE))


struct sockaddr_storage {
    sa_family_t ss_family;      // address family

    char __ss_pad1[_SS_PAD1SIZE];  // 6 byte pad, this is to make
                                   //   implementation specific pad up to
                                   //   alignment field that follows explicit
                                   //   in the data structure
    int64_t __ss_align;            // Field to force desired structure
    char __ss_pad2[_SS_PAD2SIZE];  // 112 byte pad to achieve desired size;
                                   //   _SS_MAXSIZE value minus size of
                                   //   ss_family, __ss_pad1, and
                                   //   __ss_align fields is 112
};

/*
typedef struct sockaddr_storage {
    ADDRESS_FAMILY ss_family;      // address family

    CHAR __ss_pad1[_SS_PAD1SIZE];  // 6 byte pad, this is to make
                                   //   implementation specific pad up to
                                   //   alignment field that follows explicit
                                   //   in the data structure
    __int64 __ss_align;            // Field to force desired structure
    CHAR __ss_pad2[_SS_PAD2SIZE];  // 112 byte pad to achieve desired size;
                                   //   _SS_MAXSIZE value minus size of
                                   //   ss_family, __ss_pad1, and
                                   //   __ss_align fields is 112
} SOCKADDR_STORAGE_LH, *PSOCKADDR_STORAGE_LH, *LPSOCKADDR_STORAGE_LH;
*/ 

typedef int socklen_t;

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

struct hostent
{
  char *h_name;                 /* Official name of host.  */
  char **h_aliases;             /* Alias list.  */
  short h_addrtype;               /* Host address type.  */
  short h_length;                 /* Length of address.  */
  char **h_addr_list;           /* List of addresses from name server.  */
#define h_addr  h_addr_list[0]  /* Address, for backward compatibility.  */
};

#if !defined(HAVE_GETTIMEOFDAY) && !defined(HAVE_STRUCT_TIMEVAL_TV_SEC)
/** Implementation of timeval for platforms that don't have it. */
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};

struct timespec {
        long    tv_sec;         /* seconds */
        long		 tv_nsec;        /* and nanoseconds */
};

typedef int clockid_t;

#endif

struct timeb
{
	long	time;
	short 	millitm;
	short	timezone;
	short	dstflag;
};


#define DECLARE_HANDLE(name) struct name##__{int unused;}; typedef struct name##__ *name
DECLARE_HANDLE(HKEY);
DECLARE_HANDLE(HWND);
DECLARE_HANDLE(HMODULE);

#define MAX_PATH          260

typedef enum {
    //
    // These values are from iptypes.h.
    // They need to fit in a 4 bit field.
    //
    IpPrefixOriginOther = 0,
    IpPrefixOriginManual,
    IpPrefixOriginWellKnown,
    IpPrefixOriginDhcp,
    IpPrefixOriginRouterAdvertisement,
    IpPrefixOriginUnchanged = 1 << 4
} NL_PREFIX_ORIGIN;

typedef enum {
    //
    // TODO: Remove the Nlso* definitions.
    //
    NlsoOther = 0,
    NlsoManual,
    NlsoWellKnown,
    NlsoDhcp,
    NlsoLinkLayerAddress,
    NlsoRandom,

    //
    // These values are from in iptypes.h.
    // They need to fit in a 4 bit field.
    //
    IpSuffixOriginOther = 0,
    IpSuffixOriginManual,
    IpSuffixOriginWellKnown,
    IpSuffixOriginDhcp,
    IpSuffixOriginLinkLayerAddress,
    IpSuffixOriginRandom,
    IpSuffixOriginUnchanged = 1 << 4
} NL_SUFFIX_ORIGIN;

typedef enum {
    //
    // TODO: Remove the Nlds* definitions.
    //
    NldsInvalid,
    NldsTentative,
    NldsDuplicate,
    NldsDeprecated,
    NldsPreferred,

    //
    // These values are from in iptypes.h.
    //
    IpDadStateInvalid    = 0,
    IpDadStateTentative,
    IpDadStateDuplicate,
    IpDadStateDeprecated,
    IpDadStatePreferred,
} NL_DAD_STATE;

typedef NL_PREFIX_ORIGIN IP_PREFIX_ORIGIN;
typedef NL_SUFFIX_ORIGIN IP_SUFFIX_ORIGIN;
typedef NL_DAD_STATE IP_DAD_STATE;

typedef int INT;
typedef unsigned short u_short;

/*
 * SockAddr Information
 */
/*
typedef struct _SOCKET_ADDRESS {
   LPSOCKADDR lpSockaddr;
   INT iSockaddrLength;
} SOCKET_ADDRESS, *PSOCKET_ADDRESS, *LPSOCKET_ADDRESS;

typedef struct _IP_ADAPTER_UNICAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct { 
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_UNICAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;

    IP_PREFIX_ORIGIN PrefixOrigin;
    IP_SUFFIX_ORIGIN SuffixOrigin;
    IP_DAD_STATE DadState;

    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG LeaseLifetime;
} IP_ADAPTER_UNICAST_ADDRESS_XP, *PIP_ADAPTER_UNICAST_ADDRESS_XP;

typedef  IP_ADAPTER_UNICAST_ADDRESS_XP IP_ADAPTER_UNICAST_ADDRESS;
typedef  IP_ADAPTER_UNICAST_ADDRESS_XP *PIP_ADAPTER_UNICAST_ADDRESS;

typedef struct _IP_ADAPTER_ANYCAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct { 
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_ANYCAST_ADDRESS_XP, *PIP_ADAPTER_ANYCAST_ADDRESS_XP;
#if (NTDDI_VERSION >= NTDDI_WINXP)
typedef IP_ADAPTER_ANYCAST_ADDRESS_XP IP_ADAPTER_ANYCAST_ADDRESS;
typedef IP_ADAPTER_ANYCAST_ADDRESS_XP *PIP_ADAPTER_ANYCAST_ADDRESS;
#endif

typedef struct _IP_ADAPTER_MULTICAST_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_MULTICAST_ADDRESS_XP, *PIP_ADAPTER_MULTICAST_ADDRESS_XP;
#if (NTDDI_VERSION >= NTDDI_WINXP)
typedef IP_ADAPTER_MULTICAST_ADDRESS_XP IP_ADAPTER_MULTICAST_ADDRESS;
typedef IP_ADAPTER_MULTICAST_ADDRESS_XP *PIP_ADAPTER_MULTICAST_ADDRESS;
#endif

typedef struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Reserved;
        };
    };
    struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next;
    SOCKET_ADDRESS Address;
} IP_ADAPTER_DNS_SERVER_ADDRESS_XP, *PIP_ADAPTER_DNS_SERVER_ADDRESS_XP;
#if (NTDDI_VERSION >= NTDDI_WINXP)
typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP IP_ADAPTER_DNS_SERVER_ADDRESS;
typedef IP_ADAPTER_DNS_SERVER_ADDRESS_XP *PIP_ADAPTER_DNS_SERVER_ADDRESS;
#endif

typedef struct _IP_ADAPTER_PREFIX_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD Flags;
        };
    };
    struct _IP_ADAPTER_PREFIX_XP *Next;
    SOCKET_ADDRESS Address;
    ULONG PrefixLength;
} IP_ADAPTER_PREFIX_XP, *PIP_ADAPTER_PREFIX_XP;
*/

typedef enum {
    IfOperStatusUp = 1,
    IfOperStatusDown,
    IfOperStatusTesting,
    IfOperStatusUnknown,
    IfOperStatusDormant,
    IfOperStatusNotPresent,
    IfOperStatusLowerLayerDown
} IF_OPER_STATUS;

#define MAX_ADAPTER_DESCRIPTION_LENGTH  128 // arb.
#define MAX_ADAPTER_NAME_LENGTH         256 // arb.
#define MAX_ADAPTER_ADDRESS_LENGTH      8   // arb.
#define DEFAULT_MINIMUM_ENTITIES        32  // arb.
#define MAX_HOSTNAME_LEN                128 // arb.
#define MAX_DOMAIN_NAME_LEN             128 // arb.
#define MAX_SCOPE_ID_LEN                256 // arb.
#define MAX_DHCPV6_DUID_LENGTH          130 // RFC 3315.
#define MAX_DNS_SUFFIX_STRING_LENGTH    256

/*
typedef struct _IP_ADAPTER_ADDRESSES_XP {
    union {
        ULONGLONG Alignment;
        struct {
            ULONG Length;
            DWORD IfIndex;
        };
    };
    struct _IP_ADAPTER_ADDRESSES_XP *Next;
    PCHAR AdapterName;
    PIP_ADAPTER_UNICAST_ADDRESS_XP FirstUnicastAddress;
    PIP_ADAPTER_ANYCAST_ADDRESS_XP FirstAnycastAddress;
    PIP_ADAPTER_MULTICAST_ADDRESS_XP FirstMulticastAddress;
    PIP_ADAPTER_DNS_SERVER_ADDRESS_XP FirstDnsServerAddress;
    PWCHAR DnsSuffix;
    PWCHAR Description;
    PWCHAR FriendlyName;
    BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD PhysicalAddressLength;
    DWORD Flags;
    DWORD Mtu;
    DWORD IfType;
    IF_OPER_STATUS OperStatus;
    DWORD Ipv6IfIndex;
    DWORD ZoneIndices[16];
    PIP_ADAPTER_PREFIX_XP FirstPrefix;
} IP_ADAPTER_ADDRESSES_XP,
 *PIP_ADAPTER_ADDRESSES_XP;
typedef  IP_ADAPTER_ADDRESSES_XP IP_ADAPTER_ADDRESSES;
typedef  IP_ADAPTER_ADDRESSES_XP *PIP_ADAPTER_ADDRESSES;

typedef struct _SYSTEM_INFO {
    union {
        DWORD dwOemId;          // Obsolete field...do not use
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

typedef struct _MEMORYSTATUSEX {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    DWORDLONG ullTotalPhys;
    DWORDLONG ullAvailPhys;
    DWORDLONG ullTotalPageFile;
    DWORDLONG ullAvailPageFile;
    DWORDLONG ullTotalVirtual;
    DWORDLONG ullAvailVirtual;
    DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
*/

struct _iobuf {
        char *_ptr;
        int   _cnt;
        char *_base;
        int   _flag;
        int   _file;
        int   _charbuf;
        int   _bufsiz;
        char *_tmpfname;
        };
typedef struct _iobuf FILE;

typedef unsigned int _dev_t;            /* device code */
typedef unsigned short _ino_t;          /* i-node number (not used on DOS) */
typedef long _off_t;                    /* file offset value */

struct stat {
        _dev_t     st_dev;
        _ino_t     st_ino;
        unsigned short st_mode;
        short      st_nlink;
        short      st_uid;
        short      st_gid;
        _dev_t     st_rdev;
        _off_t     st_size;
        time_t st_atime;
        time_t st_mtime;
        time_t st_ctime;
        };

#define PROV_RSA_FULL           1
#define CRYPT_VERIFYCONTEXT     0xF0000000

#define _S_IFMT         0xF000          /* file type mask */
#define _S_IFDIR        0x4000          /* directory */
#define _S_IFCHR        0x2000          /* character special */
#define _S_IFIFO        0x1000          /* pipe */
#define _S_IFREG        0x8000          /* regular */
#define _S_IREAD        0x0100          /* read permission, owner */
#define _S_IWRITE       0x0080          /* write permission, owner */
#define _S_IEXEC        0x0040          /* execute/search permission, owner */

#define S_IFMT   _S_IFMT
#define S_IFDIR  _S_IFDIR
#define S_IFCHR  _S_IFCHR
#define S_IFIFO  _S_IFIFO
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define INVALID_FILE_SIZE ((DWORD)0xFFFFFFFF)

typedef const char *LPCSTR, *PCSTR;

typedef int                 BOOL;

/*
typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
*/

struct utimbuf {
        time_t actime;          /* access time */
        time_t modtime;         /* modification time */
        };

#define PAGE_READONLY          0x02

#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define FILE_MAP_WRITE      SECTION_MAP_WRITE
#define FILE_MAP_READ       SECTION_MAP_READ
#define FILE_MAP_ALL_ACCESS SECTION_ALL_ACCESS

#define ERROR_FILE_NOT_FOUND             2L
#define ERROR_PATH_NOT_FOUND             3L
#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100

#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_STRING     0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE    0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY  0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK  0x000000FF

#define MAKELANGID(p, s)       ((((WORD  )(s)) << 10) | (WORD  )(p))

#define LANG_NEUTRAL                     0x00
#define LANG_INVARIANT                   0x7f

#define SUBLANG_DEFAULT                             0x01    // user default

/*
typedef struct _OSVERSIONINFOEXA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR   szCSDVersion[ 128 ];     // Maintenance string for PSS usage
    WORD   wServicePackMajor;
    WORD   wServicePackMinor;
    WORD   wSuiteMask;
    BYTE  wProductType;
    BYTE  wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;

typedef OSVERSIONINFOEXA OSVERSIONINFOEX;
typedef POSVERSIONINFOEXA POSVERSIONINFOEX;
typedef LPOSVERSIONINFOEXA LPOSVERSIONINFOEX;

typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR   szCSDVersion[ 128 ];     // Maintenance string for PSS usage
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

typedef OSVERSIONINFOA OSVERSIONINFO;
typedef POSVERSIONINFOA POSVERSIONINFO;
typedef LPOSVERSIONINFOA LPOSVERSIONINFO;

#define VER_PLATFORM_WIN32s             0
#define VER_PLATFORM_WIN32_WINDOWS      1
#define VER_PLATFORM_WIN32_NT           2

#define ERROR_SUCCESS                    0L

typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;

typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef unsigned int        UINT;
typedef UINT_PTR            WPARAM;
typedef LONG_PTR            LPARAM;

typedef struct {
    char HostName[MAX_HOSTNAME_LEN + 4] ;
    char DomainName[MAX_DOMAIN_NAME_LEN + 4];
    PIP_ADDR_STRING CurrentDnsServer;
    IP_ADDR_STRING DnsServerList;
    UINT NodeType;
    char ScopeId[MAX_SCOPE_ID_LEN + 4];
    UINT EnableRouting;
    UINT EnableProxy;
    UINT EnableDns;
} FIXED_INFO_W2KSP1, *PFIXED_INFO_W2KSP1;
typedef  FIXED_INFO_W2KSP1 FIXED_INFO;
typedef  FIXED_INFO_W2KSP1 *PFIXED_INFO;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;
*/

#define TLS_OUT_OF_INDEXES ((unsigned int)0xFFFFFFFF)

/*--------------------------------------------------------*/

typedef struct _sgx_file
{
	char *content;
	long content_len;
	long seek;
	unsigned long mtime;
	int is_private;
} sgx_file;

typedef unsigned char       __uint8_t;
typedef unsigned int        __uint32_t;
typedef __uint8_t       uint8_t;
typedef __uint32_t       uint32_t;
typedef unsigned char byte;

/*--------------------------------------------------------*/


#if defined(__cplusplus)
extern "C" {
#endif

/* Ocall start */
//void sgx_GetSystemTimeAsFileTime(FILETIME *ft);
//unsigned long sgx_GetAdaptersAddresses(unsigned long family, unsigned long flags, 
//			IP_ADAPTER_ADDRESSES * addresses, unsigned long *psize);
//unsigned long sgx_TlsAlloc(void);
//void *sgx_TlsGetValue(unsigned long index);
//int sgx_TlsSetValue(unsigned long index, void *val);

void *sgx_pthread_getspecific(pthread_key_t key);
int sgx_pthread_setspecific(pthread_key_t key, const void *value);
sgx_file *sgx_get_file(const char *pathname);
//int sgx_GetVersionEx(OSVERSIONINFOA* info);
int * _errno(void);
int sscanf(const char *str, const char *format, ...);
//int sgx_GlobalMemoryStatusEx(MEMORYSTATUSEX *mse);
//void sgx_GetSystemInfo(SYSTEM_INFO *info);
//void sgx_Sleep(unsigned long ms);
void sgx_sleep(unsigned int s);
int sgx_gettimeofday(struct timeval *tv);
int sgx_clock_gettime(clockid_t clk_id, struct timespec *tp);
int sgx_select(int nfds, void *rfd, void *wfd,  void *efd, int fd_size, struct timeval *timeout);
int sgx_poll(void *fds, int fd_size, int nfds, int timeout);
//unsigned sgx_GetSystemDirectory(char *lpBuffer, unsigned int uSize);
char *sgx_getenv(const char *env);
//int sgx_GetLastError(void);
int sgx_setsockopt(int s, int level, int optname, const char *optval, int optlen);
int sgx_socketpair(int domain, int type, int protocol, int *sv);
int sgx_accept(int s, struct sockaddr *addr, int *addrlen);
int sgx_bind(int s, const struct sockaddr *addr, int addrlen);
//int sgx_closesocket(int fd);
int sgx_listen(int s, int backlog);
int sgx_connect(int s, const struct sockaddr *addr, int addrlen);
int sgx_ioctlsocket(int s, long cmd, unsigned long *argp);
int sgx_getaddrinfo(const char *node, const char *service, const void *hints, void **res);
void sgx_freeaddrinfo(void *res);
int sgx_getsockname(int s,  struct sockaddr *name, int *namelen);
int sgx_getsockopt(int s, int level, int optname, char *optval, int* optlen);
int sgx_socket(int af, int type, int protocol);
void sgx_getservbyname(const char *name, int name_len, const char *proto, int proto_len, void *serv_ptr, int serv_len);
void sgx_getprotobynumber(int number, void *proto, int proto_len, char *proto_name, int proto_name_len);
int sgx_vsnprintf(char *s1, size_t n, const char *s2, __va_list v);
//int sgx_CloseHandle(int hObject);
void (*sgx_signal(int signum, void(*_Func)(int)))(int);
int sgx_eventfd(unsigned int initval, int flags);
//int sgx_atexit(void(*function)(void));
//int sgx_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sgx_sigfillset(void *set);
int sgx_sigemptyset(void *set);
int sgx_sigaction(int signum, const void *act, void *oldact);
int real_sgx_fcntl(int fd, int cmd, long arg);
int real_sgx_fcntl2(int fd, int cmd, void *lock);
int sgx_chmod(const char *pathname, int mode);
int sgx_chdir(const char *path);
int sgx_pipe(int pipefd[2]);
int sgx_sysctl(int *name, int nlen, void *oldval, int oldval_len, size_t *oldlenp, void *newval, size_t newlen);
unsigned int sgx_fork(void);
//int sgx_CreateIoCompletionPort(int FileHandle, int p, unsigned long k, unsigned long numthreads);
//int sgx_GetQueuedCompletionStatus(int p, unsigned long *numbytes, __int64 *k, void *lpOverlapped, int lpOverlapped_len, unsigned long dwMilliseconds);
/*
int sgx_WSAIoctl(int s, unsigned long dwIoControlCode,
	void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer,
	unsigned long cbOutBuffer, unsigned long *lpcbBytesReturned,
	void *lpOverlapped, void *LPWSAOVERLAPPED_COMPLETION_ROUTINE);
*/
//void sgx_ftime(struct _timeb *tb, int sizetb);
void sgx_ftime(struct timeb *tb, int sizetb);
int sgx_fstat(int fd, struct stat *_Stat);
int sgx_open(const char *pathname, int flags, unsigned mode);
struct hostent *sgx_gethostbyname(const char *name);
/*
int sgx_PostQueuedCompletionStatus(int port, unsigned int n, unsigned int key, void *o, int o_len);
int sgx_CryptAcquireContext(void *prov, void *container, void *provider, unsigned long provtype, unsigned long dwflags);
int sgx_CryptGenRandom(unsigned long long prov, int buf_len, unsigned char *buf);
int sgx_CryptReleaseContext(unsigned long long hProv, unsigned long dwFlags);
void sgx_EnterCriticalSection(void *lock, int lock_len);
void sgx_LeaveCriticalSection(void *lock, int lock_len);
void sgx_DeleteCriticalSection(void *lock, int lock_len);
void sgx_InitializeCriticalSectionAndSpinCount(void *lock, int lock_len, int count);
int sgx_CreateSemaphore(void *attr, int attr_len, long initcount, long maxcount, void *name, int name_len);
void sgx_WaitForSingleObject(int handle, unsigned long ms_);
int sgx_ReleaseSemaphore(int hSemaphore, long lReleaseCount, long* lpPreviousCount, int lp_len);
*/
char *_strdup(const char* s);
/*
unsigned long long sgx_beginthread(void (*fn)(void *), int num, void *port, int port_len);
void sgx_endthread(void);
*/
int sgx_pthread_create(void (*fn)(void *), int num, void *port, int port_len);
void sgx_pthread_exit(void *retval);
long sgx_rand(void);
int sgx_epoll_wait(int epfd, void *events, int maxevents, int timeout);
int sgx_epoll_ctl(int epfd, int op, int fd, void *event);
int sgx_epoll_create(int size);
//unsigned long sgx_GetNetworkParams(void *fixed, unsigned long *fixed_size);

void __attribute__((noreturn))
__chk_fail (void);

const unsigned short **__ctype_b_loc(void);
const int32_t **__ctype_tolower_loc(void);

#define FD_SETSIZE            65536
/* The fd_set member is required to be an array of longs.  */
typedef long int __fd_mask;

/* Some versions of <linux/posix_types.h> define this macros.  */
#undef  __NFDBITS
/* It's easier to assume 8-bit bytes than to get CHAR_BIT.  */
#define __NFDBITS   (8 * (int) sizeof (__fd_mask))

long int
__fdelt_chk (long int d);

void *
__memcpy_chk (void *__restrict__ dest, const void *__restrict__ src,
              size_t len, size_t slen);

void *
__memset_chk (void *dest, int val, size_t len, size_t slen);

unsigned short sgx_htons(unsigned short hostshort);
unsigned long sgx_htonl(unsigned long hostlong);
unsigned short sgx_ntohs(unsigned short netshort);
unsigned long sgx_ntohl(unsigned long netlong);
time_t sgx_time(time_t *timep);
int sgx_recv(int s, char *buf, int len, int flags);
int sgx_send(int s, const char *buf, int len, int flags);
/*
int sgx_WSAGetLastError(void);
void sgx_SetLastError(int e);
void sgx_WSASetLastError(int e);
*/
unsigned long sgx_GetVersion(void);
void sgx_get_current_time(struct timeval *t);
int sgx_rename(const char *from, const char *to);
int sgx_unlink(const char *to);
int sgx_close(int fd);
//int sgx_shutdown(int fd);
int sgx_shutdown(int fd, int how);
void sgx_exit(int exit_status);
int sgx_write(int fd, const void *buf, int n);
int sgx_read(int fd, void *buf, int n);
unsigned int sgx_waitpid(unsigned int pid, int *_status, int status_len, int options);
unsigned int sgx_getpid(void);
unsigned int sgx_setsid(void);
int sgx_getgroups(int size, unsigned int *list, int list_num);
int sgx_setgroups(size_t size, const unsigned int *list, int list_num);
int sgx_setuid(unsigned int uid);
int sgx_setgid(unsigned int gid);
int sgx_seteuid(unsigned int uid);
int sgx_setegid(unsigned int gid);
unsigned int sgx_getuid(void);
unsigned int sgx_getgid(void);
unsigned int sgx_geteuid(void);
unsigned int sgx_getegid(void);
int sgx_dup2(int oldfd, int newfd);
off_t sgx_lseek(int fildes, off_t offset, int whence);
int sgx_gethostname(char *name, size_t namelen);
struct tm *sgx_localtime(const time_t *timep);
struct tm *sgx_gmtime(const time_t *timep);
time_t sgx_mktime(struct tm *timeptr);
int sgx_sendto(int s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen);
int sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int *in_len);
//int sgx_SHGetSpecialFolderPathA(HWND hwnd, char *path, int csidl, int fCreate);
//char *sgx_get_windows_conf_root(void);
int sgx_stat(const char * _Filename, struct stat * _Stat);
sgx_file *sgx_fopen(const char *fname, const char *mode);
//int sgx_locking(int _FileHandle, int _LockMode, long _NumOfBytes);
sgx_file *sgx_fdopen(int fd, const char *format);
int sgx_fputs(const char *str, sgx_file *f);
int sgx_fclose(sgx_file *f);
char ***sgx_environ(void);
//char *sgx_strdup(const char *str);
char *sgx_get_torrc(void);
int sgx_remote_attestation_server(int fd);
int sgx_remote_attestation_client(int fd);
// For eval
long sgx_clock(void);

int real_sgx_fileno_stdout();
int real_sgx_open(const char *pathname, int flags, unsigned mode);
int real_sgx_write(int fd, const void *buf, int n);
int real_sgx_read(int fd, void *buf, int n);
off_t real_sgx_lseek(int fildes, off_t offset, int whence);
int real_sgx_close(int fd);
//int real_sgx_chsize(int fd, long val);
int real_sgx_ftruncate(int fd, off_t length);
int real_sgx_fclose(FILE * file);
int real_sgx_unlink(const char *filename);
/*
HANDLE real_sgx_CreateFile(
				const char *lpFileName,
				DWORD dwDesiredAccess,
				DWORD dwShareMode,
				void *_null,
				DWORD dwCreationDisposition,
				DWORD dwFlagsAndAttributes,
				HANDLE hTemplateFile);
unsigned long real_sgx_GetFileSize(int hFile, unsigned long *lpFileSizeHigh);
int real_sgx_CreateFileMapping(
    int hFile,
    void *_null,
    unsigned long flProtect,
    unsigned long dwMaximumSizeHigh,
    unsigned long dwMaximumSizeLow,
    const char* lpName);
void *real_sgx_MapViewOfFile(
    int hFileMappingObject,
    unsigned long dwDesiredAccess,
    unsigned long dwFileOffsetHigh,
    unsigned long dwFileOffsetLow,
    unsigned long long dwNumberOfBytesToMap
);
int real_sgx_UnmapViewOfFile(const void* lpBaseAddress);
*/
int real_sgx_rename(const char *from_str, const char *to_str);
int real_sgx_fstat(int fd, struct stat *buf);
int real_sgx_stat(const char *filename, struct stat *st) ;
//int real_sgx_mkdir(const char *path);
int real_sgx_mkdir(const char *path, int mode);
void *sgx_malloc(int m_size);
void *sgx_calloc(int m_cnt, int m_size);
void *sgx_realloc(void *old_mem, int m_size);
void sgx_free(void *ptr);
int real_sgx_locking(int fd, int mode, long num);

int sgx_check_remote_accept_list(unsigned long ip);

// For eval
//#define EVAL_OCALL_COUNT

#ifdef EVAL_OCALL_COUNT
extern int ocall_num;
#endif

	/* MACRO for ocall */
#define htons	sgx_htons
#define htonl	sgx_htonl
#define ntohs	sgx_ntohs
#define ntohl 	sgx_ntohl
#define time(timep)		sgx_time(timep)
#define recv sgx_recv
#define send sgx_send
#define WSAGetLastError		sgx_WSAGetLastError
#define close			sgx_close
#define exit				sgx_exit
#define _exit			sgx_exit			// For windows
#define write			sgx_write
#define read			sgx_read
//#define _getpid	sgx_getpid	// For windows
#define getuid	sgx_getuid
#define getpid	sgx_getpid
//#define _lseek		sgx_lseek		// For windows
#define lseek		sgx_lseek
#define _locking sgx_locking
#define rename(from, to) sgx_rename(from, to)
#define unlink(to) sgx_unlink(to)
#define gethostname sgx_gethostname
#define getsockname sgx_getsockname
#define localtime sgx_localtime
#define gmtime sgx_gmtime
#define mktime sgx_mktime
#define gettimeofday(a, b) sgx_gettimeofday(a)
#include <errno.h>
#define sgx_errno (*__errno()) // Enclave errno
//#define errno (*_errno()) // Outside errno
#define environ (*sgx_environ())

/* Other functions */
int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t n);
char *strdup(const char *str);
long long int strtoll(const char *nptr, char **endptr, int base);

#if defined(__cplusplus)
}
#endif

#endif
