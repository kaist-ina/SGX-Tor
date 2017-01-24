#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"
#include "time.h"
#include "orconfig.h"
#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct struct_foo_t {
	uint32_t struct_foo_0;
	uint64_t struct_foo_1;
} struct_foo_t;

typedef enum enum_foo_t {
	ENUM_FOO_0 = 0,
	ENUM_FOO_1 = 1,
} enum_foo_t;

typedef union union_foo_t {
	uint32_t union_foo_0;
	uint32_t union_foo_1;
	uint64_t union_foo_3;
} union_foo_t;

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_user_check, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_in, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_out, (int* val));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pointer_in_out, (int* val));
SGX_DLLIMPORT void* SGX_UBRIDGE(SGX_CDECL, memccpy, (void* dest, const void* src, int val, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_function_allow, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_process_msg_all, (const void* p_req, int p_req_size, void** p_resp));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ra_free_network_response_buffer, (void** resp));
unsigned long long SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_malloc, (int m_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_calloc, (int m_cnt, int m_size));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_realloc, (unsigned long long old_mem, int m_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_free, (unsigned long long ptr));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fileno_stdout, ());
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_pthread_getspecific, (int key));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_pthread_setspecific, (int key, const void* value));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sleep, (unsigned int seconds));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_poll, (void* fds, int fd_size, int nfds, int timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gettimeofday, (struct timeval* tv, int tv_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock_gettime, (clockid_t clk_id, struct timespec* tp, int tp_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_select, (int nfds, void* rfd, void* wfd, void* efd, int fd_size, struct timeval* timeout, int tv_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const char* optval, int optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socketpair, (int domain, int type, int protocol, int* sv));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, struct sockaddr* addr, int addr_size, int* addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const struct sockaddr* addr, int addr_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fstat, (int fd, struct stat* buf, int buflen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const struct sockaddr* addr, int addrlen));
struct hostent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gethostbyname, (const char* name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_open, (const char* pathname, int flags, unsigned int mode));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ftime, (struct timeb* tb, int size_timeb));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getaddrinfo, (const char* node, const char* service, const void* hints, int hints_len, void** res, int res_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_freeaddrinfo, (void* res, int res_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockname, (int s, struct sockaddr* name, int nlen, int* namelen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getservbyname, (const char* name, int name_len, const char* proto, int proto_len, void* serv_ptr, int serv_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getprotobynumber, (int number, void* proto, int proto_len, char* proto_name, int proto_name_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_pthread_create, (void* port, int port_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_epoll_wait, (int epfd, void* events, int events_len, int maxevents, int timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_epoll_ctl, (int epfd, int op, int fd, void* event, int event_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_epoll_create, (int size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_signal, (int signum, int f_id));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_eventfd, (unsigned int initval, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sigfillset, (void* set, int setlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sigemptyset, (void* set, int setlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sigaction, (int signum, const void* act, int act_len, void* oldact, int oldact_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fcntl, (int fd, int cmd, long int arg));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fcntl2, (int fd, int cmd, void* lock, int lock_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_chmod, (const char* pathname, int mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_chdir, (const char* path));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_pipe, (int* pipefd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sysctl, (int* name, int nlen, void* oldval, int oldval_len, size_t* oldlenp, void* newval, size_t newlen));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fork, ());
unsigned short int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ntohs, (unsigned short int netshort));
unsigned long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ntohl, (unsigned long int netlong));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time, (time_t* timep, int t_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_recv, (int s, char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_recv, (int s, unsigned long long buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_send, (int s, const char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_send, (int s, unsigned long long buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_rename, (const char* from_str, const char* to_str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_unlink, (const char* filename));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_ftruncate, (int fd, off_t length));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd, int how));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_exit, (int exit_status));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_write, (int fd, unsigned long long buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_direct_read, (int fd, unsigned long long buf, int n));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_waitpid, (unsigned int pid, int* _status, int status_len, int options));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getpid, ());
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsid, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getgroups, (int size, unsigned int* list, int list_num));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setgroups, (size_t size, const unsigned int* list, int list_num));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setuid, (unsigned int uid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setgid, (unsigned int gid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_seteuid, (unsigned int uid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setegid, (unsigned int gid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_dup2, (int oldfd, int newfd));
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getuid, ());
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getgid, ());
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_geteuid, ());
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getegid, ());
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_lseek, (int fildes, off_t offset, int whence));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gethostname, (char* name, size_t namelen));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime, (const time_t* timep, int t_len));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_mktime, (struct tm* timeptr, int tm_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_sendto, (int s, const void* msg, int len, int flags, const struct sockaddr* to, int tolen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_recvfrom, (int s, void* msg, int len, int flags, struct sockaddr* fr, int frlen, int* in_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_fclose, (FILE* file, int file_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_stat, (const char* filename, struct stat* st, int stat_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_mkdir, (const char* path, int mode));
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, ());
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val);
sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val);
sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val);
sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val);
sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val);
sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val);
sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val);
sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2);
sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz);
sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val);
sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str);
sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str);
sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len);
sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt);
sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len);
sgx_status_t ecall_pointer_sizefunc(sgx_enclave_id_t eid, char* buf);
sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid);
sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr);
sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid);
sgx_status_t ecall_function_public(sgx_enclave_id_t eid);
sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval);
sgx_status_t StartTorSGX(sgx_enclave_id_t eid, int argc, char** argv, int argv_len, unsigned long long app_errno, unsigned long long app_environ, const char* app_torrc);
sgx_status_t sgx_start_gencert(sgx_enclave_id_t eid, char* tor_cert, unsigned long long app_errno, const char* month, const char* address);
sgx_status_t sgx_start_fingerprint(sgx_enclave_id_t eid, char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno);
sgx_status_t sgx_seal_files(sgx_enclave_id_t eid, char* fname, void* fcont);
sgx_status_t sgx_unseal_files(sgx_enclave_id_t eid, char* fname, void* fcont);
sgx_status_t enclave_func_caller(sgx_enclave_id_t eid, void* args, int args_len);
sgx_status_t sgx_signal_handle_caller(sgx_enclave_id_t eid, int signum, int f_id);
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t sgx_start_remote_attestation_server(sgx_enclave_id_t eid, int remote_server_port, void* sgx_cert_cont, int sgx_cert_size, void* sgx_pkey_cont, int sgx_pkey_size, unsigned long int given_my_ip);
sgx_status_t test_sgx_put_gencert(sgx_enclave_id_t eid, char* fname, char* fcont, int fcont_len);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
