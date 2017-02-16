#ifndef TORSGX_T_H__
#define TORSGX_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "time.h"
#include "orconfig.h"
#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void sgx_start_tor(int argc, char** argv, int argv_len, void* version, int version_size, unsigned long long app_errno, unsigned long long app_environ, const char* app_conf_root, const char* app_torrc, const char* app_system_dir, MEMORYSTATUSEX* app_mse, SYSTEM_INFO* app_info);
void sgx_start_gencert(char* tor_cert, unsigned long long app_errno, const char* month, const char* address);
void sgx_start_fingerprint(char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno, MEMORYSTATUSEX* app_mse);
void sgx_start_remote_attestation_server(int remote_server_port, void* sgx_cert_cont, int sgx_cert_size, void* sgx_pkey_cont, int sgx_pkey_size, unsigned long int given_my_ip);
sgx_status_t sgx_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t sgx_close_ra(sgx_ra_context_t context);
sgx_status_t sgx_verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
void enclave_func_caller(void* args, int args_len);
void test_sgx_put_gencert(char* fname, char* fcont, int fcont_len);
void sgx_seal_files(char* fname, void* fcont);
void sgx_unseal_files(char* fname, void* fcont);
void sgx_signal_handle_caller(int signum, int f_id);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_sgx_process_msg_all(int* retval, const void* p_req, int p_req_size, void** p_resp);
sgx_status_t SGX_CDECL ocall_sgx_ra_free_network_response_buffer(void** resp);
sgx_status_t SGX_CDECL ocall_sgx_malloc(void** retval, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_calloc(void** retval, int m_cnt, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_realloc(void** retval, unsigned long long old_mem, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_free(unsigned long long ptr);
sgx_status_t SGX_CDECL ocall_sgx_GetSystemTimeAsFileTime(FILETIME* ft, int ft_size);
sgx_status_t SGX_CDECL ocall_sgx_GetAdaptersAddresses(unsigned long int* retval, unsigned long int family, unsigned long int flags, void* addresses, unsigned long int addresses_size, unsigned long int* psize);
sgx_status_t SGX_CDECL ocall_sgx_TlsAlloc(unsigned long int* retval);
sgx_status_t SGX_CDECL ocall_sgx_TlsGetValue(void** retval, unsigned long int index);
sgx_status_t SGX_CDECL ocall_sgx_TlsSetValue(int* retval, unsigned long int index, void* val);
sgx_status_t SGX_CDECL ocall_sgx_Sleep(unsigned long int milli);
sgx_status_t SGX_CDECL ocall_sgx_select(int* retval, int nfds, void* rfd, void* wfd, void* efd, int fd_size, struct timeval* timeout, int tv_size);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int* retval, int s, int level, int optname, const char* optval, int optlen);
sgx_status_t SGX_CDECL ocall_sgx_accept(int* retval, int s, struct sockaddr* addr, int addr_size, int* addrlen);
sgx_status_t SGX_CDECL ocall_sgx_bind(int* retval, int s, const struct sockaddr* addr, int addr_size);
sgx_status_t SGX_CDECL ocall_sgx_fstat(int* retval, int fd, struct stat* buf, int buflen);
sgx_status_t SGX_CDECL ocall_sgx_socket(int* retval, int af, int type, int protocol);
sgx_status_t SGX_CDECL ocall_sgx_listen(int* retval, int s, int backlog);
sgx_status_t SGX_CDECL ocall_sgx_connect(int* retval, int s, const struct sockaddr* addr, int addrlen);
sgx_status_t SGX_CDECL ocall_sgx_ioctlsocket(int* retval, int s, long int cmd, unsigned long int* argp, int argp_len);
sgx_status_t SGX_CDECL ocall_sgx_EnterCriticalSection(void* lock, int lock_len);
sgx_status_t SGX_CDECL ocall_sgx_LeaveCriticalSection(void* lock, int lock_len);
sgx_status_t SGX_CDECL ocall_sgx_DeleteCriticalSection(void* lock, int lock_len);
sgx_status_t SGX_CDECL ocall_sgx_InitializeCriticalSectionAndSpinCount(void* lock, int lock_len, int count);
sgx_status_t SGX_CDECL ocall_sgx_gethostbyname(struct hostent** retval, const char* name);
sgx_status_t SGX_CDECL ocall_sgx_WaitForSingleObject(int handle, unsigned long int ms_);
sgx_status_t SGX_CDECL ocall_sgx_CryptGenRandom(int* retval, unsigned long long prov, int buf_len, unsigned char* buf);
sgx_status_t SGX_CDECL ocall_sgx_CryptReleaseContext(int* retval, unsigned long long hProv, unsigned long int dwFlags);
sgx_status_t SGX_CDECL ocall_sgx_CloseHandle(int* retval, int hObject);
sgx_status_t SGX_CDECL ocall_sgx_GetLastError(int* retval);
sgx_status_t SGX_CDECL ocall_sgx_CreateIoCompletionPort(int* retval, int FileHandle, int p, unsigned long int k, unsigned long int numthreads);
sgx_status_t SGX_CDECL ocall_sgx_GetQueuedCompletionStatus(int* retval, int p, unsigned long int* numbytes, int numbytes_len, __int64* k, int k_len, void* lpOverlapped, int lpOverlapped_len, unsigned long int dwMilliseconds);
sgx_status_t SGX_CDECL ocall_sgx_GetSystemDirectory(unsigned int* retval, char* lpBuffer, unsigned int uSize);
sgx_status_t SGX_CDECL ocall_sgx_LoadLibrary(unsigned long long* retval, char* lpFileName);
sgx_status_t SGX_CDECL ocall_sgx_open(int* retval, const char* pathname, int flags, unsigned int mode);
sgx_status_t SGX_CDECL ocall_sgx_ftime(struct _timeb* tb, int size_timeb);
sgx_status_t SGX_CDECL ocall_sgx_CreateSemaphore(int* retval, void* attr, int attr_len, long int initcount, long int maxcount, void* name, int name_len);
sgx_status_t SGX_CDECL ocall_sgx_ReleaseSemaphore(int* retval, int hSemaphore, long int lReleaseCount, long int* lpPreviousCount, int lp_len);
sgx_status_t SGX_CDECL ocall_sgx_CryptAcquireContext(int* retval, void* prov, void* container, void* provider, unsigned long int provtype, unsigned long int dwflags);
sgx_status_t SGX_CDECL ocall_sgx_getenv(int* retval, const char* env, int envlen, char* ret_str, int ret_len);
sgx_status_t SGX_CDECL ocall_sgx_getsockname(int* retval, int s, struct sockaddr* name, int nlen, int* namelen);
sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int* retval, int s, int level, int optname, char* optval, int optval_len, int* optlen);
sgx_status_t SGX_CDECL ocall_sgx_getservbyname(const char* name, int name_len, const char* proto, int proto_len, void* serv_ptr, int serv_len);
sgx_status_t SGX_CDECL ocall_sgx_getprotobynumber(int number, void* proto, int proto_len, char* proto_name, int proto_name_len);
sgx_status_t SGX_CDECL ocall_sgx_beginthread(unsigned long long* retval, void* port, int port_len);
sgx_status_t SGX_CDECL ocall_sgx_endthread();
sgx_status_t SGX_CDECL ocall_sgx_PostQueuedCompletionStatus(int* retval, int p, unsigned int n, unsigned int key, void* o, int o_len);
sgx_status_t SGX_CDECL ocall_sgx_signal(int signum, int f_id);
sgx_status_t SGX_CDECL ocall_sgx_ntohs(unsigned short int* retval, unsigned short int netshort);
sgx_status_t SGX_CDECL ocall_sgx_ntohl(unsigned long int* retval, unsigned long int netlong);
sgx_status_t SGX_CDECL ocall_get_time(time_t* retval, time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_ucheck_recv(int* retval, int s, char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_recv(int* retval, int s, char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_direct_recv(int* retval, int s, unsigned long long buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_send(int* retval, int s, const char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_ucheck_send(int* retval, int s, const char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_direct_send(int* retval, int s, unsigned long long buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_WSAGetLastError(int* retval);
sgx_status_t SGX_CDECL ocall_sgx_SetLastError(int e);
sgx_status_t SGX_CDECL ocall_sgx_WSASetLastError(int e);
sgx_status_t SGX_CDECL ocall_sgx_rename(int* retval, const char* from_str, const char* to_str);
sgx_status_t SGX_CDECL ocall_sgx_unlink(int* retval, const char* filename);
sgx_status_t SGX_CDECL ocall_sgx_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sgx_chsize(int* retval, int fd, long int val);
sgx_status_t SGX_CDECL ocall_sgx_closesocket(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sgx_exit(int exit_status);
sgx_status_t SGX_CDECL ocall_sgx_write(int* retval, int fd, const void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_direct_write(int* retval, int fd, unsigned long long buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_read(int* retval, int fd, void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_direct_read(int* retval, int fd, unsigned long long buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_getpid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_lseek(off_t* retval, int fildes, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_sgx_locking(int* retval, int fd, int mode, long int num);
sgx_status_t SGX_CDECL ocall_sgx_gethostname(int* retval, char* name, size_t namelen);
sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm** retval, const time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_gmtime(struct tm** retval, const time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_mktime(time_t* retval, struct tm* timeptr, int tm_len);
sgx_status_t SGX_CDECL ocall_sgx_GetNetworkParams(unsigned long int* retval, void* fixed, unsigned long int fixed_sz, unsigned long int* fixed_size);
sgx_status_t SGX_CDECL ocall_sgx_sendto(int* retval, int s, const void* msg, int len, int flags, const struct sockaddr* to, int tolen);
sgx_status_t SGX_CDECL ocall_sgx_recvfrom(int* retval, int s, void* msg, int len, int flags, struct sockaddr* fr, int frlen, int* in_len);
sgx_status_t SGX_CDECL ocall_sgx_SHGetSpecialFolderPathA(int* retval, HWND hwnd, char* path, int path_len, int csidl, int fCreate);
sgx_status_t SGX_CDECL ocall_sgx_fputs(int* retval, const char* str, FILE* stream, int stream_size);
sgx_status_t SGX_CDECL ocall_sgx_fclose(int* retval, FILE* file, int file_size);
sgx_status_t SGX_CDECL ocall_sgx_stat(int* retval, const char* filename, struct stat* st, int stat_size);
sgx_status_t SGX_CDECL ocall_sgx_mkdir(int* retval, const char* path);
sgx_status_t SGX_CDECL ocall_sgx_UnmapViewOfFile(int* retval, unsigned long long lpBaseAddress);
sgx_status_t SGX_CDECL ocall_sgx_MapViewOfFile(void** retval, int hFileMappingObject, unsigned long int dwDesiredAccess, unsigned long int dwFileOffsetHigh, unsigned long int dwFileOffsetLow, unsigned long long dwNumberOfBytesToMap);
sgx_status_t SGX_CDECL ocall_sgx_CreateFileMapping(int* retval, int hFile, void* _null, unsigned long int flProtect, unsigned long int dwMaximumSizeHigh, unsigned long int dwMaximumSizeLow, const char* lpName);
sgx_status_t SGX_CDECL ocall_sgx_GetFileSize(unsigned long int* retval, int hFile, unsigned long int* lpFileSizeHigh);
sgx_status_t SGX_CDECL ocall_sgx_CreateFile(HANDLE* retval, const char* lpFileName, unsigned long int dwDesiredAccess, unsigned long int dwShareMode, void* _null, unsigned long int dwCreationDisposition, unsigned long int dwFlagsAndAttributes, int hTemplateFile);
sgx_status_t SGX_CDECL ocall_sgx_clock(long long* retval);
sgx_status_t SGX_CDECL ocall_sgx_fdopen(unsigned long long* retval, int fd, const char* format);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
