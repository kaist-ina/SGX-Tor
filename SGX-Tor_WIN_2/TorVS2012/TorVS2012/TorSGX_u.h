#ifndef TORSGX_U_H__
#define TORSGX_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "time.h"
#include "orconfig.h"
#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_process_msg_all, (const void* p_req, int p_req_size, void** p_resp));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ra_free_network_response_buffer, (void** resp));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_malloc, (int m_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_calloc, (int m_cnt, int m_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_realloc, (unsigned long long old_mem, int m_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_free, (unsigned long long ptr));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetSystemTimeAsFileTime, (FILETIME* ft, int ft_size));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetAdaptersAddresses, (unsigned long int family, unsigned long int flags, void* addresses, unsigned long int addresses_size, unsigned long int* psize));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_TlsAlloc, ());
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_TlsGetValue, (unsigned long int index));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_TlsSetValue, (unsigned long int index, void* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_Sleep, (unsigned long int milli));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_select, (int nfds, void* rfd, void* wfd, void* efd, int fd_size, struct timeval* timeout, int tv_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const char* optval, int optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, struct sockaddr* addr, int addr_size, int* addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const struct sockaddr* addr, int addr_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fstat, (int fd, struct stat* buf, int buflen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const struct sockaddr* addr, int addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ioctlsocket, (int s, long int cmd, unsigned long int* argp, int argp_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_EnterCriticalSection, (void* lock, int lock_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_LeaveCriticalSection, (void* lock, int lock_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_DeleteCriticalSection, (void* lock, int lock_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_InitializeCriticalSectionAndSpinCount, (void* lock, int lock_len, int count));
struct hostent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gethostbyname, (const char* name));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_WaitForSingleObject, (int handle, unsigned long int ms_));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CryptGenRandom, (unsigned long long prov, int buf_len, unsigned char* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CryptReleaseContext, (unsigned long long hProv, unsigned long int dwFlags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CloseHandle, (int hObject));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetLastError, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CreateIoCompletionPort, (int FileHandle, int p, unsigned long int k, unsigned long int numthreads));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetQueuedCompletionStatus, (int p, unsigned long int* numbytes, int numbytes_len, __int64* k, int k_len, void* lpOverlapped, int lpOverlapped_len, unsigned long int dwMilliseconds));
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetSystemDirectory, (char* lpBuffer, unsigned int uSize));
unsigned long long SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_LoadLibrary, (char* lpFileName));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_open, (const char* pathname, int flags, unsigned int mode));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ftime, (struct _timeb* tb, int size_timeb));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CreateSemaphore, (void* attr, int attr_len, long int initcount, long int maxcount, void* name, int name_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ReleaseSemaphore, (int hSemaphore, long int lReleaseCount, long int* lpPreviousCount, int lp_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CryptAcquireContext, (void* prov, void* container, void* provider, unsigned long int provtype, unsigned long int dwflags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockname, (int s, struct sockaddr* name, int nlen, int* namelen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getservbyname, (const char* name, int name_len, const char* proto, int proto_len, void* serv_ptr, int serv_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getprotobynumber, (int number, void* proto, int proto_len, char* proto_name, int proto_name_len));
unsigned long long SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_beginthread, (void* port, int port_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_endthread, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_PostQueuedCompletionStatus, (int p, unsigned int n, unsigned int key, void* o, int o_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_signal, (int signum, int f_id));
unsigned short int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ntohs, (unsigned short int netshort));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ntohl, (unsigned long int netlong));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (time_t* timep, int t_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ucheck_recv, (int s, char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_recv, (int s, char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_recv, (int s, unsigned long long buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_send, (int s, const char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ucheck_send, (int s, const char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_send, (int s, unsigned long long buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_WSAGetLastError, ());
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_SetLastError, (int e));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_WSASetLastError, (int e));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_rename, (const char* from_str, const char* to_str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_unlink, (const char* filename));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_chsize, (int fd, long int val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_closesocket, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_exit, (int exit_status));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_write, (int fd, unsigned long long buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_read, (int fd, unsigned long long buf, int n));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getpid, ());
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_lseek, (int fildes, off_t offset, int whence));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_locking, (int fd, int mode, long int num));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gethostname, (char* name, size_t namelen));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime, (const time_t* timep, int t_len));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_mktime, (struct tm* timeptr, int tm_len));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetNetworkParams, (void* fixed, unsigned long int fixed_sz, unsigned long int* fixed_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sendto, (int s, const void* msg, int len, int flags, const struct sockaddr* to, int tolen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_recvfrom, (int s, void* msg, int len, int flags, struct sockaddr* fr, int frlen, int* in_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_SHGetSpecialFolderPathA, (HWND hwnd, char* path, int path_len, int csidl, int fCreate));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fputs, (const char* str, FILE* stream, int stream_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fclose, (FILE* file, int file_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_stat, (const char* filename, struct stat* st, int stat_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_mkdir, (const char* path));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_UnmapViewOfFile, (unsigned long long lpBaseAddress));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_MapViewOfFile, (int hFileMappingObject, unsigned long int dwDesiredAccess, unsigned long int dwFileOffsetHigh, unsigned long int dwFileOffsetLow, unsigned long long dwNumberOfBytesToMap));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CreateFileMapping, (int hFile, void* _null, unsigned long int flProtect, unsigned long int dwMaximumSizeHigh, unsigned long int dwMaximumSizeLow, const char* lpName));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_GetFileSize, (int hFile, unsigned long int* lpFileSizeHigh));
HANDLE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_CreateFile, (const char* lpFileName, unsigned long int dwDesiredAccess, unsigned long int dwShareMode, void* _null, unsigned long int dwCreationDisposition, unsigned long int dwFlagsAndAttributes, int hTemplateFile));
long long SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, ());
unsigned long long SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fdopen, (int fd, const char* format));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t sgx_start_tor(sgx_enclave_id_t eid, int argc, char** argv, int argv_len, void* version, int version_size, unsigned long long app_errno, unsigned long long app_environ, const char* app_conf_root, const char* app_torrc, const char* app_system_dir, MEMORYSTATUSEX* app_mse, SYSTEM_INFO* app_info);
sgx_status_t sgx_start_gencert(sgx_enclave_id_t eid, char* tor_cert, unsigned long long app_errno, const char* month, const char* address);
sgx_status_t sgx_start_fingerprint(sgx_enclave_id_t eid, char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno, MEMORYSTATUSEX* app_mse);
sgx_status_t sgx_start_remote_attestation_server(sgx_enclave_id_t eid, int remote_server_port, void* sgx_cert_cont, int sgx_cert_size, void* sgx_pkey_cont, int sgx_pkey_size, unsigned long int given_my_ip);
sgx_status_t sgx_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t sgx_close_ra(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t sgx_verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t enclave_func_caller(sgx_enclave_id_t eid, void* args, int args_len);
sgx_status_t test_sgx_put_gencert(sgx_enclave_id_t eid, char* fname, char* fcont, int fcont_len);
sgx_status_t sgx_seal_files(sgx_enclave_id_t eid, char* fname, void* fcont);
sgx_status_t sgx_unseal_files(sgx_enclave_id_t eid, char* fname, void* fcont);
sgx_status_t sgx_signal_handle_caller(sgx_enclave_id_t eid, int signum, int f_id);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
