#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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

size_t get_buffer_len(const char* val);

void ecall_type_char(char val);
void ecall_type_int(int val);
void ecall_type_float(float val);
void ecall_type_double(double val);
void ecall_type_size_t(size_t val);
void ecall_type_wchar_t(wchar_t val);
void ecall_type_struct(struct struct_foo_t val);
void ecall_type_enum_union(enum enum_foo_t val1, union union_foo_t* val2);
size_t ecall_pointer_user_check(void* val, size_t sz);
void ecall_pointer_in(int* val);
void ecall_pointer_out(int* val);
void ecall_pointer_in_out(int* val);
void ecall_pointer_string(char* str);
void ecall_pointer_string_const(const char* str);
void ecall_pointer_size(void* ptr, size_t len);
void ecall_pointer_count(int* arr, int cnt);
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len);
void ecall_pointer_sizefunc(char* buf);
void ocall_pointer_attr();
void ecall_array_user_check(int arr[4]);
void ecall_array_in(int arr[4]);
void ecall_array_out(int arr[4]);
void ecall_array_in_out(int arr[4]);
void ecall_array_isary(array_t arr);
void ecall_function_calling_convs();
void ecall_function_public();
int ecall_function_private();
void StartTorSGX(int argc, char** argv, int argv_len, unsigned long long app_errno, unsigned long long app_environ, const char* app_torrc);
void sgx_start_gencert(char* tor_cert, unsigned long long app_errno, const char* month, const char* address);
void sgx_start_fingerprint(char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno);
void sgx_seal_files(char* fname, void* fcont);
void sgx_unseal_files(char* fname, void* fcont);
void enclave_func_caller(void* args, int args_len);
void sgx_signal_handle_caller(int signum, int f_id);
sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
void sgx_start_remote_attestation_server(int remote_server_port, void* sgx_cert_cont, int sgx_cert_size, void* sgx_pkey_cont, int sgx_pkey_size, unsigned long int given_my_ip);
void test_sgx_put_gencert(char* fname, char* fcont, int fcont_len);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in(int* val);
sgx_status_t SGX_CDECL ocall_pointer_out(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val);
sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len);
sgx_status_t SGX_CDECL ocall_function_allow();
sgx_status_t SGX_CDECL ocall_sgx_process_msg_all(int* retval, const void* p_req, int p_req_size, void** p_resp);
sgx_status_t SGX_CDECL ocall_sgx_ra_free_network_response_buffer(void** resp);
sgx_status_t SGX_CDECL ocall_sgx_malloc(unsigned long long* retval, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_calloc(void** retval, int m_cnt, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_realloc(void** retval, unsigned long long old_mem, int m_size);
sgx_status_t SGX_CDECL ocall_sgx_free(unsigned long long ptr);
sgx_status_t SGX_CDECL ocall_sgx_fileno_stdout(int* retval);
sgx_status_t SGX_CDECL ocall_sgx_pthread_getspecific(void** retval, int key);
sgx_status_t SGX_CDECL ocall_sgx_pthread_setspecific(int* retval, int key, const void* value);
sgx_status_t SGX_CDECL ocall_sgx_sleep(unsigned int seconds);
sgx_status_t SGX_CDECL ocall_sgx_poll(int* retval, void* fds, int fd_size, int nfds, int timeout);
sgx_status_t SGX_CDECL ocall_sgx_gettimeofday(int* retval, struct timeval* tv, int tv_size);
sgx_status_t SGX_CDECL ocall_sgx_clock_gettime(int* retval, clockid_t clk_id, struct timespec* tp, int tp_size);
sgx_status_t SGX_CDECL ocall_sgx_select(int* retval, int nfds, void* rfd, void* wfd, void* efd, int fd_size, struct timeval* timeout, int tv_size);
sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int* retval, int s, int level, int optname, const char* optval, int optlen);
sgx_status_t SGX_CDECL ocall_sgx_socketpair(int* retval, int domain, int type, int protocol, int* sv);
sgx_status_t SGX_CDECL ocall_sgx_accept(int* retval, int s, struct sockaddr* addr, int addr_size, int* addrlen);
sgx_status_t SGX_CDECL ocall_sgx_bind(int* retval, int s, const struct sockaddr* addr, int addr_size);
sgx_status_t SGX_CDECL ocall_sgx_fstat(int* retval, int fd, struct stat* buf, int buflen);
sgx_status_t SGX_CDECL ocall_sgx_socket(int* retval, int af, int type, int protocol);
sgx_status_t SGX_CDECL ocall_sgx_listen(int* retval, int s, int backlog);
sgx_status_t SGX_CDECL ocall_sgx_connect(int* retval, int s, const struct sockaddr* addr, int addrlen);
sgx_status_t SGX_CDECL ocall_sgx_gethostbyname(struct hostent** retval, const char* name);
sgx_status_t SGX_CDECL ocall_sgx_open(int* retval, const char* pathname, int flags, unsigned int mode);
sgx_status_t SGX_CDECL ocall_sgx_ftime(struct timeb* tb, int size_timeb);
sgx_status_t SGX_CDECL ocall_sgx_getenv(int* retval, const char* env, int envlen, char* ret_str, int ret_len);
sgx_status_t SGX_CDECL ocall_sgx_getaddrinfo(int* retval, const char* node, const char* service, const void* hints, int hints_len, void** res, int res_len);
sgx_status_t SGX_CDECL ocall_sgx_freeaddrinfo(void* res, int res_len);
sgx_status_t SGX_CDECL ocall_sgx_getsockname(int* retval, int s, struct sockaddr* name, int nlen, int* namelen);
sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int* retval, int s, int level, int optname, char* optval, int optval_len, int* optlen);
sgx_status_t SGX_CDECL ocall_sgx_getservbyname(const char* name, int name_len, const char* proto, int proto_len, void* serv_ptr, int serv_len);
sgx_status_t SGX_CDECL ocall_sgx_getprotobynumber(int number, void* proto, int proto_len, char* proto_name, int proto_name_len);
sgx_status_t SGX_CDECL ocall_sgx_pthread_create(int* retval, void* port, int port_len);
sgx_status_t SGX_CDECL ocall_sgx_epoll_wait(int* retval, int epfd, void* events, int events_len, int maxevents, int timeout);
sgx_status_t SGX_CDECL ocall_sgx_epoll_ctl(int* retval, int epfd, int op, int fd, void* event, int event_len);
sgx_status_t SGX_CDECL ocall_sgx_epoll_create(int* retval, int size);
sgx_status_t SGX_CDECL ocall_sgx_signal(int signum, int f_id);
sgx_status_t SGX_CDECL ocall_sgx_eventfd(int* retval, unsigned int initval, int flags);
sgx_status_t SGX_CDECL ocall_sgx_sigfillset(int* retval, void* set, int setlen);
sgx_status_t SGX_CDECL ocall_sgx_sigemptyset(int* retval, void* set, int setlen);
sgx_status_t SGX_CDECL ocall_sgx_sigaction(int* retval, int signum, const void* act, int act_len, void* oldact, int oldact_len);
sgx_status_t SGX_CDECL ocall_sgx_fcntl(int* retval, int fd, int cmd, long int arg);
sgx_status_t SGX_CDECL ocall_sgx_fcntl2(int* retval, int fd, int cmd, void* lock, int lock_len);
sgx_status_t SGX_CDECL ocall_sgx_chmod(int* retval, const char* pathname, int mode);
sgx_status_t SGX_CDECL ocall_sgx_chdir(int* retval, const char* path);
sgx_status_t SGX_CDECL ocall_sgx_pipe(int* retval, int* pipefd);
sgx_status_t SGX_CDECL ocall_sgx_sysctl(int* retval, int* name, int nlen, void* oldval, int oldval_len, size_t* oldlenp, void* newval, size_t newlen);
sgx_status_t SGX_CDECL ocall_sgx_fork(pid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_ntohs(unsigned short int* retval, unsigned short int netshort);
sgx_status_t SGX_CDECL ocall_sgx_ntohl(unsigned long int* retval, unsigned long int netlong);
sgx_status_t SGX_CDECL ocall_get_time(time_t* retval, time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_recv(int* retval, int s, char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_direct_recv(int* retval, int s, unsigned long long buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_send(int* retval, int s, const char* buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_direct_send(int* retval, int s, unsigned long long buf, int len, int flags);
sgx_status_t SGX_CDECL ocall_sgx_rename(int* retval, const char* from_str, const char* to_str);
sgx_status_t SGX_CDECL ocall_sgx_unlink(int* retval, const char* filename);
sgx_status_t SGX_CDECL ocall_sgx_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_sgx_ftruncate(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd, int how);
sgx_status_t SGX_CDECL ocall_sgx_exit(int exit_status);
sgx_status_t SGX_CDECL ocall_sgx_write(int* retval, int fd, const void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_direct_write(int* retval, int fd, unsigned long long buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_read(int* retval, int fd, void* buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_direct_read(int* retval, int fd, unsigned long long buf, int n);
sgx_status_t SGX_CDECL ocall_sgx_waitpid(pid_t* retval, unsigned int pid, int* _status, int status_len, int options);
sgx_status_t SGX_CDECL ocall_sgx_getpid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_setsid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_getgroups(int* retval, int size, unsigned int* list, int list_num);
sgx_status_t SGX_CDECL ocall_sgx_setgroups(int* retval, size_t size, const unsigned int* list, int list_num);
sgx_status_t SGX_CDECL ocall_sgx_setuid(int* retval, unsigned int uid);
sgx_status_t SGX_CDECL ocall_sgx_setgid(int* retval, unsigned int gid);
sgx_status_t SGX_CDECL ocall_sgx_seteuid(int* retval, unsigned int uid);
sgx_status_t SGX_CDECL ocall_sgx_setegid(int* retval, unsigned int gid);
sgx_status_t SGX_CDECL ocall_sgx_dup2(int* retval, int oldfd, int newfd);
sgx_status_t SGX_CDECL ocall_sgx_getuid(uid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_getgid(gid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_geteuid(uid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_getegid(gid_t* retval);
sgx_status_t SGX_CDECL ocall_sgx_lseek(off_t* retval, int fildes, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_sgx_gethostname(int* retval, char* name, size_t namelen);
sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm** retval, const time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_gmtime(struct tm** retval, const time_t* timep, int t_len);
sgx_status_t SGX_CDECL ocall_sgx_mktime(time_t* retval, struct tm* timeptr, int tm_len);
sgx_status_t SGX_CDECL ocall_sgx_sendto(int* retval, int s, const void* msg, int len, int flags, const struct sockaddr* to, int tolen);
sgx_status_t SGX_CDECL ocall_sgx_recvfrom(int* retval, int s, void* msg, int len, int flags, struct sockaddr* fr, int frlen, int* in_len);
sgx_status_t SGX_CDECL ocall_sgx_fclose(int* retval, FILE* file, int file_size);
sgx_status_t SGX_CDECL ocall_sgx_stat(int* retval, const char* filename, struct stat* st, int stat_size);
sgx_status_t SGX_CDECL ocall_sgx_mkdir(int* retval, const char* path, int mode);
sgx_status_t SGX_CDECL ocall_sgx_clock(long int* retval);
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
