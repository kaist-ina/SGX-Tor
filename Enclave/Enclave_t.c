#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	char* ms_str;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_pointer_sizefunc_t {
	char* ms_buf;
} ms_ecall_pointer_sizefunc_t;


typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;



typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_StartTorSGX_t {
	int ms_argc;
	char** ms_argv;
	int ms_argv_len;
	unsigned long long ms_app_errno;
	unsigned long long ms_app_environ;
	char* ms_app_torrc;
} ms_StartTorSGX_t;

typedef struct ms_sgx_start_gencert_t {
	char* ms_tor_cert;
	unsigned long long ms_app_errno;
	char* ms_month;
	char* ms_address;
} ms_sgx_start_gencert_t;

typedef struct ms_sgx_start_fingerprint_t {
	char* ms_fingerprint;
	char* ms_data_dir;
	char* ms_app_torrc;
	unsigned long long ms_app_errno;
} ms_sgx_start_fingerprint_t;

typedef struct ms_sgx_seal_files_t {
	char* ms_fname;
	void* ms_fcont;
} ms_sgx_seal_files_t;

typedef struct ms_sgx_unseal_files_t {
	char* ms_fname;
	void* ms_fcont;
} ms_sgx_unseal_files_t;

typedef struct ms_enclave_func_caller_t {
	void* ms_args;
	int ms_args_len;
} ms_enclave_func_caller_t;

typedef struct ms_sgx_signal_handle_caller_t {
	int ms_signum;
	int ms_f_id;
} ms_sgx_signal_handle_caller_t;

typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_sgx_start_remote_attestation_server_t {
	int ms_remote_server_port;
	void* ms_sgx_cert_cont;
	int ms_sgx_cert_size;
	void* ms_sgx_pkey_cont;
	int ms_sgx_pkey_size;
	unsigned long int ms_given_my_ip;
} ms_sgx_start_remote_attestation_server_t;

typedef struct ms_test_sgx_put_gencert_t {
	char* ms_fname;
	char* ms_fcont;
	int ms_fcont_len;
} ms_test_sgx_put_gencert_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;


typedef struct ms_ocall_sgx_process_msg_all_t {
	int ms_retval;
	void* ms_p_req;
	int ms_p_req_size;
	void** ms_p_resp;
} ms_ocall_sgx_process_msg_all_t;

typedef struct ms_ocall_sgx_ra_free_network_response_buffer_t {
	void** ms_resp;
} ms_ocall_sgx_ra_free_network_response_buffer_t;

typedef struct ms_ocall_sgx_malloc_t {
	unsigned long long ms_retval;
	int ms_m_size;
} ms_ocall_sgx_malloc_t;

typedef struct ms_ocall_sgx_calloc_t {
	void* ms_retval;
	int ms_m_cnt;
	int ms_m_size;
} ms_ocall_sgx_calloc_t;

typedef struct ms_ocall_sgx_realloc_t {
	void* ms_retval;
	unsigned long long ms_old_mem;
	int ms_m_size;
} ms_ocall_sgx_realloc_t;

typedef struct ms_ocall_sgx_free_t {
	unsigned long long ms_ptr;
} ms_ocall_sgx_free_t;

typedef struct ms_ocall_sgx_fileno_stdout_t {
	int ms_retval;
} ms_ocall_sgx_fileno_stdout_t;

typedef struct ms_ocall_sgx_pthread_getspecific_t {
	void* ms_retval;
	int ms_key;
} ms_ocall_sgx_pthread_getspecific_t;

typedef struct ms_ocall_sgx_pthread_setspecific_t {
	int ms_retval;
	int ms_key;
	void* ms_value;
} ms_ocall_sgx_pthread_setspecific_t;

typedef struct ms_ocall_sgx_sleep_t {
	unsigned int ms_seconds;
} ms_ocall_sgx_sleep_t;

typedef struct ms_ocall_sgx_poll_t {
	int ms_retval;
	void* ms_fds;
	int ms_fd_size;
	int ms_nfds;
	int ms_timeout;
} ms_ocall_sgx_poll_t;

typedef struct ms_ocall_sgx_gettimeofday_t {
	int ms_retval;
	struct timeval* ms_tv;
	int ms_tv_size;
} ms_ocall_sgx_gettimeofday_t;

typedef struct ms_ocall_sgx_clock_gettime_t {
	int ms_retval;
	clockid_t ms_clk_id;
	struct timespec* ms_tp;
	int ms_tp_size;
} ms_ocall_sgx_clock_gettime_t;

typedef struct ms_ocall_sgx_select_t {
	int ms_retval;
	int ms_nfds;
	void* ms_rfd;
	void* ms_wfd;
	void* ms_efd;
	int ms_fd_size;
	struct timeval* ms_timeout;
	int ms_tv_size;
} ms_ocall_sgx_select_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optlen;
} ms_ocall_sgx_setsockopt_t;

typedef struct ms_ocall_sgx_socketpair_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
	int* ms_sv;
} ms_ocall_sgx_socketpair_t;

typedef struct ms_ocall_sgx_accept_t {
	int ms_retval;
	int ms_s;
	struct sockaddr* ms_addr;
	int ms_addr_size;
	int* ms_addrlen;
} ms_ocall_sgx_accept_t;

typedef struct ms_ocall_sgx_bind_t {
	int ms_retval;
	int ms_s;
	struct sockaddr* ms_addr;
	int ms_addr_size;
} ms_ocall_sgx_bind_t;

typedef struct ms_ocall_sgx_fstat_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
	int ms_buflen;
} ms_ocall_sgx_fstat_t;

typedef struct ms_ocall_sgx_socket_t {
	int ms_retval;
	int ms_af;
	int ms_type;
	int ms_protocol;
} ms_ocall_sgx_socket_t;

typedef struct ms_ocall_sgx_listen_t {
	int ms_retval;
	int ms_s;
	int ms_backlog;
} ms_ocall_sgx_listen_t;

typedef struct ms_ocall_sgx_connect_t {
	int ms_retval;
	int ms_s;
	struct sockaddr* ms_addr;
	int ms_addrlen;
} ms_ocall_sgx_connect_t;

typedef struct ms_ocall_sgx_gethostbyname_t {
	struct hostent* ms_retval;
	char* ms_name;
} ms_ocall_sgx_gethostbyname_t;

typedef struct ms_ocall_sgx_open_t {
	int ms_retval;
	char* ms_pathname;
	int ms_flags;
	unsigned int ms_mode;
} ms_ocall_sgx_open_t;

typedef struct ms_ocall_sgx_ftime_t {
	struct timeb* ms_tb;
	int ms_size_timeb;
} ms_ocall_sgx_ftime_t;

typedef struct ms_ocall_sgx_getenv_t {
	int ms_retval;
	char* ms_env;
	int ms_envlen;
	char* ms_ret_str;
	int ms_ret_len;
} ms_ocall_sgx_getenv_t;

typedef struct ms_ocall_sgx_getaddrinfo_t {
	int ms_retval;
	char* ms_node;
	char* ms_service;
	void* ms_hints;
	int ms_hints_len;
	void** ms_res;
	int ms_res_len;
} ms_ocall_sgx_getaddrinfo_t;

typedef struct ms_ocall_sgx_freeaddrinfo_t {
	void* ms_res;
	int ms_res_len;
} ms_ocall_sgx_freeaddrinfo_t;

typedef struct ms_ocall_sgx_getsockname_t {
	int ms_retval;
	int ms_s;
	struct sockaddr* ms_name;
	int ms_nlen;
	int* ms_namelen;
} ms_ocall_sgx_getsockname_t;

typedef struct ms_ocall_sgx_getsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optval_len;
	int* ms_optlen;
} ms_ocall_sgx_getsockopt_t;

typedef struct ms_ocall_sgx_getservbyname_t {
	char* ms_name;
	int ms_name_len;
	char* ms_proto;
	int ms_proto_len;
	void* ms_serv_ptr;
	int ms_serv_len;
} ms_ocall_sgx_getservbyname_t;

typedef struct ms_ocall_sgx_getprotobynumber_t {
	int ms_number;
	void* ms_proto;
	int ms_proto_len;
	char* ms_proto_name;
	int ms_proto_name_len;
} ms_ocall_sgx_getprotobynumber_t;

typedef struct ms_ocall_sgx_pthread_create_t {
	int ms_retval;
	void* ms_port;
	int ms_port_len;
} ms_ocall_sgx_pthread_create_t;

typedef struct ms_ocall_sgx_epoll_wait_t {
	int ms_retval;
	int ms_epfd;
	void* ms_events;
	int ms_events_len;
	int ms_maxevents;
	int ms_timeout;
} ms_ocall_sgx_epoll_wait_t;

typedef struct ms_ocall_sgx_epoll_ctl_t {
	int ms_retval;
	int ms_epfd;
	int ms_op;
	int ms_fd;
	void* ms_event;
	int ms_event_len;
} ms_ocall_sgx_epoll_ctl_t;

typedef struct ms_ocall_sgx_epoll_create_t {
	int ms_retval;
	int ms_size;
} ms_ocall_sgx_epoll_create_t;

typedef struct ms_ocall_sgx_signal_t {
	int ms_signum;
	int ms_f_id;
} ms_ocall_sgx_signal_t;

typedef struct ms_ocall_sgx_eventfd_t {
	int ms_retval;
	unsigned int ms_initval;
	int ms_flags;
} ms_ocall_sgx_eventfd_t;

typedef struct ms_ocall_sgx_sigfillset_t {
	int ms_retval;
	void* ms_set;
	int ms_setlen;
} ms_ocall_sgx_sigfillset_t;

typedef struct ms_ocall_sgx_sigemptyset_t {
	int ms_retval;
	void* ms_set;
	int ms_setlen;
} ms_ocall_sgx_sigemptyset_t;

typedef struct ms_ocall_sgx_sigaction_t {
	int ms_retval;
	int ms_signum;
	void* ms_act;
	int ms_act_len;
	void* ms_oldact;
	int ms_oldact_len;
} ms_ocall_sgx_sigaction_t;

typedef struct ms_ocall_sgx_fcntl_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	long int ms_arg;
} ms_ocall_sgx_fcntl_t;

typedef struct ms_ocall_sgx_fcntl2_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	void* ms_lock;
	int ms_lock_len;
} ms_ocall_sgx_fcntl2_t;

typedef struct ms_ocall_sgx_chmod_t {
	int ms_retval;
	char* ms_pathname;
	int ms_mode;
} ms_ocall_sgx_chmod_t;

typedef struct ms_ocall_sgx_chdir_t {
	int ms_retval;
	char* ms_path;
} ms_ocall_sgx_chdir_t;

typedef struct ms_ocall_sgx_pipe_t {
	int ms_retval;
	int* ms_pipefd;
} ms_ocall_sgx_pipe_t;

typedef struct ms_ocall_sgx_sysctl_t {
	int ms_retval;
	int* ms_name;
	int ms_nlen;
	void* ms_oldval;
	int ms_oldval_len;
	size_t* ms_oldlenp;
	void* ms_newval;
	size_t ms_newlen;
} ms_ocall_sgx_sysctl_t;

typedef struct ms_ocall_sgx_fork_t {
	pid_t ms_retval;
} ms_ocall_sgx_fork_t;

typedef struct ms_ocall_sgx_ntohs_t {
	unsigned short int ms_retval;
	unsigned short int ms_netshort;
} ms_ocall_sgx_ntohs_t;

typedef struct ms_ocall_sgx_ntohl_t {
	unsigned long int ms_retval;
	unsigned long int ms_netlong;
} ms_ocall_sgx_ntohl_t;

typedef struct ms_ocall_get_time_t {
	time_t ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_get_time_t;

typedef struct ms_ocall_sgx_recv_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_recv_t;

typedef struct ms_ocall_sgx_direct_recv_t {
	int ms_retval;
	int ms_s;
	unsigned long long ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_direct_recv_t;

typedef struct ms_ocall_sgx_send_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_send_t;

typedef struct ms_ocall_sgx_direct_send_t {
	int ms_retval;
	int ms_s;
	unsigned long long ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_direct_send_t;

typedef struct ms_ocall_sgx_rename_t {
	int ms_retval;
	char* ms_from_str;
	char* ms_to_str;
} ms_ocall_sgx_rename_t;

typedef struct ms_ocall_sgx_unlink_t {
	int ms_retval;
	char* ms_filename;
} ms_ocall_sgx_unlink_t;

typedef struct ms_ocall_sgx_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_close_t;

typedef struct ms_ocall_sgx_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_sgx_ftruncate_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_sgx_shutdown_t;

typedef struct ms_ocall_sgx_exit_t {
	int ms_exit_status;
} ms_ocall_sgx_exit_t;

typedef struct ms_ocall_sgx_write_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_write_t;

typedef struct ms_ocall_sgx_direct_write_t {
	int ms_retval;
	int ms_fd;
	unsigned long long ms_buf;
	int ms_n;
} ms_ocall_sgx_direct_write_t;

typedef struct ms_ocall_sgx_read_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_read_t;

typedef struct ms_ocall_sgx_direct_read_t {
	int ms_retval;
	int ms_fd;
	unsigned long long ms_buf;
	int ms_n;
} ms_ocall_sgx_direct_read_t;

typedef struct ms_ocall_sgx_waitpid_t {
	pid_t ms_retval;
	unsigned int ms_pid;
	int* ms__status;
	int ms_status_len;
	int ms_options;
} ms_ocall_sgx_waitpid_t;

typedef struct ms_ocall_sgx_getpid_t {
	pid_t ms_retval;
} ms_ocall_sgx_getpid_t;

typedef struct ms_ocall_sgx_setsid_t {
	pid_t ms_retval;
} ms_ocall_sgx_setsid_t;

typedef struct ms_ocall_sgx_getgroups_t {
	int ms_retval;
	int ms_size;
	unsigned int* ms_list;
	int ms_list_num;
} ms_ocall_sgx_getgroups_t;

typedef struct ms_ocall_sgx_setgroups_t {
	int ms_retval;
	size_t ms_size;
	unsigned int* ms_list;
	int ms_list_num;
} ms_ocall_sgx_setgroups_t;

typedef struct ms_ocall_sgx_setuid_t {
	int ms_retval;
	unsigned int ms_uid;
} ms_ocall_sgx_setuid_t;

typedef struct ms_ocall_sgx_setgid_t {
	int ms_retval;
	unsigned int ms_gid;
} ms_ocall_sgx_setgid_t;

typedef struct ms_ocall_sgx_seteuid_t {
	int ms_retval;
	unsigned int ms_uid;
} ms_ocall_sgx_seteuid_t;

typedef struct ms_ocall_sgx_setegid_t {
	int ms_retval;
	unsigned int ms_gid;
} ms_ocall_sgx_setegid_t;

typedef struct ms_ocall_sgx_dup2_t {
	int ms_retval;
	int ms_oldfd;
	int ms_newfd;
} ms_ocall_sgx_dup2_t;

typedef struct ms_ocall_sgx_getuid_t {
	uid_t ms_retval;
} ms_ocall_sgx_getuid_t;

typedef struct ms_ocall_sgx_getgid_t {
	gid_t ms_retval;
} ms_ocall_sgx_getgid_t;

typedef struct ms_ocall_sgx_geteuid_t {
	uid_t ms_retval;
} ms_ocall_sgx_geteuid_t;

typedef struct ms_ocall_sgx_getegid_t {
	gid_t ms_retval;
} ms_ocall_sgx_getegid_t;

typedef struct ms_ocall_sgx_lseek_t {
	off_t ms_retval;
	int ms_fildes;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_sgx_lseek_t;

typedef struct ms_ocall_sgx_gethostname_t {
	int ms_retval;
	char* ms_name;
	size_t ms_namelen;
} ms_ocall_sgx_gethostname_t;

typedef struct ms_ocall_sgx_localtime_t {
	struct tm* ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_localtime_t;

typedef struct ms_ocall_sgx_gmtime_t {
	struct tm* ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_gmtime_t;

typedef struct ms_ocall_sgx_mktime_t {
	time_t ms_retval;
	struct tm* ms_timeptr;
	int ms_tm_len;
} ms_ocall_sgx_mktime_t;

typedef struct ms_ocall_sgx_sendto_t {
	int ms_retval;
	int ms_s;
	void* ms_msg;
	int ms_len;
	int ms_flags;
	struct sockaddr* ms_to;
	int ms_tolen;
} ms_ocall_sgx_sendto_t;

typedef struct ms_ocall_sgx_recvfrom_t {
	int ms_retval;
	int ms_s;
	void* ms_msg;
	int ms_len;
	int ms_flags;
	struct sockaddr* ms_fr;
	int ms_frlen;
	int* ms_in_len;
} ms_ocall_sgx_recvfrom_t;

typedef struct ms_ocall_sgx_fclose_t {
	int ms_retval;
	FILE* ms_file;
	int ms_file_size;
} ms_ocall_sgx_fclose_t;

typedef struct ms_ocall_sgx_stat_t {
	int ms_retval;
	char* ms_filename;
	struct stat* ms_st;
	int ms_stat_size;
} ms_ocall_sgx_stat_t;

typedef struct ms_ocall_sgx_mkdir_t {
	int ms_retval;
	char* ms_path;
	int ms_mode;
} ms_ocall_sgx_mkdir_t;

typedef struct ms_ocall_sgx_clock_t {
	long int ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_type_char(void* pms)
{
	ms_ecall_type_char_t* ms = SGX_CAST(ms_ecall_type_char_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_char_t));

	ecall_type_char(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_int(void* pms)
{
	ms_ecall_type_int_t* ms = SGX_CAST(ms_ecall_type_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_int_t));

	ecall_type_int(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_float(void* pms)
{
	ms_ecall_type_float_t* ms = SGX_CAST(ms_ecall_type_float_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_float_t));

	ecall_type_float(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_double(void* pms)
{
	ms_ecall_type_double_t* ms = SGX_CAST(ms_ecall_type_double_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_double_t));

	ecall_type_double(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_size_t(void* pms)
{
	ms_ecall_type_size_t_t* ms = SGX_CAST(ms_ecall_type_size_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_size_t_t));

	ecall_type_size_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_wchar_t(void* pms)
{
	ms_ecall_type_wchar_t_t* ms = SGX_CAST(ms_ecall_type_wchar_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_wchar_t_t));

	ecall_type_wchar_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_struct(void* pms)
{
	ms_ecall_type_struct_t* ms = SGX_CAST(ms_ecall_type_struct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_struct_t));

	ecall_type_struct(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_enum_union(void* pms)
{
	ms_ecall_type_enum_union_t* ms = SGX_CAST(ms_ecall_type_enum_union_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	union union_foo_t* _tmp_val2 = ms->ms_val2;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_enum_union_t));

	ecall_type_enum_union(ms->ms_val1, _tmp_val2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_user_check(void* pms)
{
	ms_ecall_pointer_user_check_t* ms = SGX_CAST(ms_ecall_pointer_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = ms->ms_val;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_user_check_t));

	ms->ms_retval = ecall_pointer_user_check(_tmp_val, ms->ms_sz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in(void* pms)
{
	ms_ecall_pointer_in_t* ms = SGX_CAST(ms_ecall_pointer_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in(_in_val);
err:
	if (_in_val) free(_in_val);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_out(void* pms)
{
	ms_ecall_pointer_out_t* ms = SGX_CAST(ms_ecall_pointer_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_out_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}
	ecall_pointer_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in_out(void* pms)
{
	ms_ecall_pointer_in_out_t* ms = SGX_CAST(ms_ecall_pointer_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(*_tmp_val);
	int* _in_val = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_out_t));
	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	if (_tmp_val != NULL) {
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_val, _tmp_val, _len_val);
	}
	ecall_pointer_in_out(_in_val);
err:
	if (_in_val) {
		memcpy(_tmp_val, _in_val, _len_val);
		free(_in_val);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string(void* pms)
{
	ms_ecall_pointer_string_t* ms = SGX_CAST(ms_ecall_pointer_string_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	ecall_pointer_string(_in_str);
err:
	if (_in_str) {
		memcpy(_tmp_str, _in_str, _len_str);
		free(_in_str);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string_const(void* pms)
{
	ms_ecall_pointer_string_const_t* ms = SGX_CAST(ms_ecall_pointer_string_const_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = _tmp_str ? strlen(_tmp_str) + 1 : 0;
	char* _in_str = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_const_t));
	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	if (_tmp_str != NULL) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_str, _tmp_str, _len_str);
		_in_str[_len_str - 1] = '\0';
	}
	ecall_pointer_string_const((const char*)_in_str);
err:
	if (_in_str) free((void*)_in_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_size(void* pms)
{
	ms_ecall_pointer_size_t* ms = SGX_CAST(ms_ecall_pointer_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_size_t));
	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	if (_tmp_ptr != NULL) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ptr, _tmp_ptr, _len_ptr);
	}
	ecall_pointer_size(_in_ptr, _tmp_len);
err:
	if (_in_ptr) {
		memcpy(_tmp_ptr, _in_ptr, _len_ptr);
		free(_in_ptr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_count(void* pms)
{
	ms_ecall_pointer_count_t* ms = SGX_CAST(ms_ecall_pointer_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	int _tmp_cnt = ms->ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	if ((size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_count_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_pointer_count(_in_arr, _tmp_cnt);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_isptr_readonly(void* pms)
{
	ms_ecall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_ecall_pointer_isptr_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_isptr_readonly_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_buf, _tmp_buf, _len_buf);
	}
	ecall_pointer_isptr_readonly(_in_buf, _tmp_len);
err:
	if (_in_buf) free((void*)_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_sizefunc(void* pms)
{
	ms_ecall_pointer_sizefunc_t* ms = SGX_CAST(ms_ecall_pointer_sizefunc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = ((_tmp_buf) ? get_buffer_len(_tmp_buf) : 0);
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_sizefunc_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);

		/* check whether the pointer is modified. */
		if (get_buffer_len(_in_buf) != _len_buf) {
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
	}
	ecall_pointer_sizefunc(_in_buf);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ocall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pointer_attr();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_user_check(void* pms)
{
	ms_ecall_array_user_check_t* ms = SGX_CAST(ms_ecall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_user_check_t));

	ecall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in(void* pms)
{
	ms_ecall_array_in_t* ms = SGX_CAST(ms_ecall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in(_in_arr);
err:
	if (_in_arr) free(_in_arr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_out(void* pms)
{
	ms_ecall_array_out_t* ms = SGX_CAST(ms_ecall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_out_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}
	ecall_array_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in_out(void* pms)
{
	ms_ecall_array_in_out_t* ms = SGX_CAST(ms_ecall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_out_t));
	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	if (_tmp_arr != NULL) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	ecall_array_in_out(_in_arr);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_isary(void* pms)
{
	ms_ecall_array_isary_t* ms = SGX_CAST(ms_ecall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_isary_t));

	ecall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_public();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_private(void* pms)
{
	ms_ecall_function_private_t* ms = SGX_CAST(ms_ecall_function_private_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_private_t));

	ms->ms_retval = ecall_function_private();


	return status;
}

static sgx_status_t SGX_CDECL sgx_StartTorSGX(void* pms)
{
	ms_StartTorSGX_t* ms = SGX_CAST(ms_StartTorSGX_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_argv = ms->ms_argv;
	int _tmp_argv_len = ms->ms_argv_len;
	size_t _len_argv = _tmp_argv_len;
	char** _in_argv = NULL;
	char* _tmp_app_torrc = ms->ms_app_torrc;
	size_t _len_app_torrc = _tmp_app_torrc ? strlen(_tmp_app_torrc) + 1 : 0;
	char* _in_app_torrc = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_StartTorSGX_t));
	CHECK_UNIQUE_POINTER(_tmp_argv, _len_argv);
	CHECK_UNIQUE_POINTER(_tmp_app_torrc, _len_app_torrc);

	if (_tmp_argv != NULL) {
		_in_argv = (char**)malloc(_len_argv);
		if (_in_argv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_argv, _tmp_argv, _len_argv);
	}
	if (_tmp_app_torrc != NULL) {
		_in_app_torrc = (char*)malloc(_len_app_torrc);
		if (_in_app_torrc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_app_torrc, _tmp_app_torrc, _len_app_torrc);
		_in_app_torrc[_len_app_torrc - 1] = '\0';
	}
	StartTorSGX(ms->ms_argc, _in_argv, _tmp_argv_len, ms->ms_app_errno, ms->ms_app_environ, (const char*)_in_app_torrc);
err:
	if (_in_argv) free(_in_argv);
	if (_in_app_torrc) free((void*)_in_app_torrc);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_start_gencert(void* pms)
{
	ms_sgx_start_gencert_t* ms = SGX_CAST(ms_sgx_start_gencert_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_tor_cert = ms->ms_tor_cert;
	size_t _len_tor_cert = 8192;
	char* _in_tor_cert = NULL;
	char* _tmp_month = ms->ms_month;
	size_t _len_month = _tmp_month ? strlen(_tmp_month) + 1 : 0;
	char* _in_month = NULL;
	char* _tmp_address = ms->ms_address;
	size_t _len_address = _tmp_address ? strlen(_tmp_address) + 1 : 0;
	char* _in_address = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_start_gencert_t));
	CHECK_UNIQUE_POINTER(_tmp_tor_cert, _len_tor_cert);
	CHECK_UNIQUE_POINTER(_tmp_month, _len_month);
	CHECK_UNIQUE_POINTER(_tmp_address, _len_address);

	if (_tmp_tor_cert != NULL) {
		if ((_in_tor_cert = (char*)malloc(_len_tor_cert)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tor_cert, 0, _len_tor_cert);
	}
	if (_tmp_month != NULL) {
		_in_month = (char*)malloc(_len_month);
		if (_in_month == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_month, _tmp_month, _len_month);
		_in_month[_len_month - 1] = '\0';
	}
	if (_tmp_address != NULL) {
		_in_address = (char*)malloc(_len_address);
		if (_in_address == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_address, _tmp_address, _len_address);
		_in_address[_len_address - 1] = '\0';
	}
	sgx_start_gencert(_in_tor_cert, ms->ms_app_errno, (const char*)_in_month, (const char*)_in_address);
err:
	if (_in_tor_cert) {
		memcpy(_tmp_tor_cert, _in_tor_cert, _len_tor_cert);
		free(_in_tor_cert);
	}
	if (_in_month) free((void*)_in_month);
	if (_in_address) free((void*)_in_address);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_start_fingerprint(void* pms)
{
	ms_sgx_start_fingerprint_t* ms = SGX_CAST(ms_sgx_start_fingerprint_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_fingerprint = ms->ms_fingerprint;
	size_t _len_fingerprint = 1024;
	char* _in_fingerprint = NULL;
	char* _tmp_data_dir = ms->ms_data_dir;
	size_t _len_data_dir = _tmp_data_dir ? strlen(_tmp_data_dir) + 1 : 0;
	char* _in_data_dir = NULL;
	char* _tmp_app_torrc = ms->ms_app_torrc;
	size_t _len_app_torrc = _tmp_app_torrc ? strlen(_tmp_app_torrc) + 1 : 0;
	char* _in_app_torrc = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_start_fingerprint_t));
	CHECK_UNIQUE_POINTER(_tmp_fingerprint, _len_fingerprint);
	CHECK_UNIQUE_POINTER(_tmp_data_dir, _len_data_dir);
	CHECK_UNIQUE_POINTER(_tmp_app_torrc, _len_app_torrc);

	if (_tmp_fingerprint != NULL) {
		if ((_in_fingerprint = (char*)malloc(_len_fingerprint)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_fingerprint, 0, _len_fingerprint);
	}
	if (_tmp_data_dir != NULL) {
		_in_data_dir = (char*)malloc(_len_data_dir);
		if (_in_data_dir == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data_dir, _tmp_data_dir, _len_data_dir);
		_in_data_dir[_len_data_dir - 1] = '\0';
	}
	if (_tmp_app_torrc != NULL) {
		_in_app_torrc = (char*)malloc(_len_app_torrc);
		if (_in_app_torrc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_app_torrc, _tmp_app_torrc, _len_app_torrc);
		_in_app_torrc[_len_app_torrc - 1] = '\0';
	}
	sgx_start_fingerprint(_in_fingerprint, _in_data_dir, (const char*)_in_app_torrc, ms->ms_app_errno);
err:
	if (_in_fingerprint) {
		memcpy(_tmp_fingerprint, _in_fingerprint, _len_fingerprint);
		free(_in_fingerprint);
	}
	if (_in_data_dir) free(_in_data_dir);
	if (_in_app_torrc) free((void*)_in_app_torrc);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_seal_files(void* pms)
{
	ms_sgx_seal_files_t* ms = SGX_CAST(ms_sgx_seal_files_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_fname = ms->ms_fname;
	size_t _len_fname = _tmp_fname ? strlen(_tmp_fname) + 1 : 0;
	char* _in_fname = NULL;
	void* _tmp_fcont = ms->ms_fcont;
	size_t _len_fcont = 8192;
	void* _in_fcont = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_seal_files_t));
	CHECK_UNIQUE_POINTER(_tmp_fname, _len_fname);
	CHECK_UNIQUE_POINTER(_tmp_fcont, _len_fcont);

	if (_tmp_fname != NULL) {
		_in_fname = (char*)malloc(_len_fname);
		if (_in_fname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fname, _tmp_fname, _len_fname);
		_in_fname[_len_fname - 1] = '\0';
	}
	if (_tmp_fcont != NULL) {
		if ((_in_fcont = (void*)malloc(_len_fcont)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_fcont, 0, _len_fcont);
	}
	sgx_seal_files(_in_fname, _in_fcont);
err:
	if (_in_fname) free(_in_fname);
	if (_in_fcont) {
		memcpy(_tmp_fcont, _in_fcont, _len_fcont);
		free(_in_fcont);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_unseal_files(void* pms)
{
	ms_sgx_unseal_files_t* ms = SGX_CAST(ms_sgx_unseal_files_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_fname = ms->ms_fname;
	size_t _len_fname = _tmp_fname ? strlen(_tmp_fname) + 1 : 0;
	char* _in_fname = NULL;
	void* _tmp_fcont = ms->ms_fcont;
	size_t _len_fcont = 8192;
	void* _in_fcont = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_unseal_files_t));
	CHECK_UNIQUE_POINTER(_tmp_fname, _len_fname);
	CHECK_UNIQUE_POINTER(_tmp_fcont, _len_fcont);

	if (_tmp_fname != NULL) {
		_in_fname = (char*)malloc(_len_fname);
		if (_in_fname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fname, _tmp_fname, _len_fname);
		_in_fname[_len_fname - 1] = '\0';
	}
	if (_tmp_fcont != NULL) {
		_in_fcont = (void*)malloc(_len_fcont);
		if (_in_fcont == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fcont, _tmp_fcont, _len_fcont);
	}
	sgx_unseal_files(_in_fname, _in_fcont);
err:
	if (_in_fname) free(_in_fname);
	if (_in_fcont) free(_in_fcont);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_func_caller(void* pms)
{
	ms_enclave_func_caller_t* ms = SGX_CAST(ms_enclave_func_caller_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;
	int _tmp_args_len = ms->ms_args_len;
	size_t _len_args = _tmp_args_len;
	void* _in_args = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_func_caller_t));
	CHECK_UNIQUE_POINTER(_tmp_args, _len_args);

	if (_tmp_args != NULL) {
		_in_args = (void*)malloc(_len_args);
		if (_in_args == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_args, _tmp_args, _len_args);
	}
	enclave_func_caller(_in_args, _tmp_args_len);
err:
	if (_in_args) free(_in_args);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_signal_handle_caller(void* pms)
{
	ms_sgx_signal_handle_caller_t* ms = SGX_CAST(ms_sgx_signal_handle_caller_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_signal_handle_caller_t));

	sgx_signal_handle_caller(ms->ms_signum, ms->ms_f_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));

	ms->ms_retval = enclave_ra_close(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_att_result_mac(void* pms)
{
	ms_verify_att_result_mac_t* ms = SGX_CAST(ms_verify_att_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_verify_att_result_mac_t));
	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	if (_tmp_message != NULL) {
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_message, _tmp_message, _len_message);
	}
	if (_tmp_mac != NULL) {
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mac, _tmp_mac, _len_mac);
	}
	ms->ms_retval = verify_att_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);
err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_start_remote_attestation_server(void* pms)
{
	ms_sgx_start_remote_attestation_server_t* ms = SGX_CAST(ms_sgx_start_remote_attestation_server_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sgx_cert_cont = ms->ms_sgx_cert_cont;
	int _tmp_sgx_cert_size = ms->ms_sgx_cert_size;
	size_t _len_sgx_cert_cont = _tmp_sgx_cert_size;
	void* _in_sgx_cert_cont = NULL;
	void* _tmp_sgx_pkey_cont = ms->ms_sgx_pkey_cont;
	int _tmp_sgx_pkey_size = ms->ms_sgx_pkey_size;
	size_t _len_sgx_pkey_cont = _tmp_sgx_pkey_size;
	void* _in_sgx_pkey_cont = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_start_remote_attestation_server_t));
	CHECK_UNIQUE_POINTER(_tmp_sgx_cert_cont, _len_sgx_cert_cont);
	CHECK_UNIQUE_POINTER(_tmp_sgx_pkey_cont, _len_sgx_pkey_cont);

	if (_tmp_sgx_cert_cont != NULL) {
		_in_sgx_cert_cont = (void*)malloc(_len_sgx_cert_cont);
		if (_in_sgx_cert_cont == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sgx_cert_cont, _tmp_sgx_cert_cont, _len_sgx_cert_cont);
	}
	if (_tmp_sgx_pkey_cont != NULL) {
		_in_sgx_pkey_cont = (void*)malloc(_len_sgx_pkey_cont);
		if (_in_sgx_pkey_cont == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sgx_pkey_cont, _tmp_sgx_pkey_cont, _len_sgx_pkey_cont);
	}
	sgx_start_remote_attestation_server(ms->ms_remote_server_port, _in_sgx_cert_cont, _tmp_sgx_cert_size, _in_sgx_pkey_cont, _tmp_sgx_pkey_size, ms->ms_given_my_ip);
err:
	if (_in_sgx_cert_cont) free(_in_sgx_cert_cont);
	if (_in_sgx_pkey_cont) free(_in_sgx_pkey_cont);

	return status;
}

static sgx_status_t SGX_CDECL sgx_test_sgx_put_gencert(void* pms)
{
	ms_test_sgx_put_gencert_t* ms = SGX_CAST(ms_test_sgx_put_gencert_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_fname = ms->ms_fname;
	size_t _len_fname = _tmp_fname ? strlen(_tmp_fname) + 1 : 0;
	char* _in_fname = NULL;
	char* _tmp_fcont = ms->ms_fcont;
	int _tmp_fcont_len = ms->ms_fcont_len;
	size_t _len_fcont = _tmp_fcont_len;
	char* _in_fcont = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_test_sgx_put_gencert_t));
	CHECK_UNIQUE_POINTER(_tmp_fname, _len_fname);
	CHECK_UNIQUE_POINTER(_tmp_fcont, _len_fcont);

	if (_tmp_fname != NULL) {
		_in_fname = (char*)malloc(_len_fname);
		if (_in_fname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fname, _tmp_fname, _len_fname);
		_in_fname[_len_fname - 1] = '\0';
	}
	if (_tmp_fcont != NULL) {
		_in_fcont = (char*)malloc(_len_fcont);
		if (_in_fcont == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fcont, _tmp_fcont, _len_fcont);
	}
	test_sgx_put_gencert(_in_fname, _in_fcont, _tmp_fcont_len);
err:
	if (_in_fname) free(_in_fname);
	if (_in_fcont) free(_in_fcont);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[42];
} g_ecall_table = {
	42,
	{
		{(void*)(uintptr_t)sgx_ecall_type_char, 0},
		{(void*)(uintptr_t)sgx_ecall_type_int, 0},
		{(void*)(uintptr_t)sgx_ecall_type_float, 0},
		{(void*)(uintptr_t)sgx_ecall_type_double, 0},
		{(void*)(uintptr_t)sgx_ecall_type_size_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_wchar_t, 0},
		{(void*)(uintptr_t)sgx_ecall_type_struct, 0},
		{(void*)(uintptr_t)sgx_ecall_type_enum_union, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string_const, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_size, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_count, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_isptr_readonly, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_sizefunc, 0},
		{(void*)(uintptr_t)sgx_ocall_pointer_attr, 0},
		{(void*)(uintptr_t)sgx_ecall_array_user_check, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in, 0},
		{(void*)(uintptr_t)sgx_ecall_array_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in_out, 0},
		{(void*)(uintptr_t)sgx_ecall_array_isary, 0},
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0},
		{(void*)(uintptr_t)sgx_ecall_function_public, 0},
		{(void*)(uintptr_t)sgx_ecall_function_private, 1},
		{(void*)(uintptr_t)sgx_StartTorSGX, 0},
		{(void*)(uintptr_t)sgx_sgx_start_gencert, 0},
		{(void*)(uintptr_t)sgx_sgx_start_fingerprint, 0},
		{(void*)(uintptr_t)sgx_sgx_seal_files, 0},
		{(void*)(uintptr_t)sgx_sgx_unseal_files, 0},
		{(void*)(uintptr_t)sgx_enclave_func_caller, 0},
		{(void*)(uintptr_t)sgx_sgx_signal_handle_caller, 0},
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0},
		{(void*)(uintptr_t)sgx_sgx_start_remote_attestation_server, 0},
		{(void*)(uintptr_t)sgx_test_sgx_put_gencert, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[106][42];
} g_dyn_entry_table = {
	106,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pointer_user_check_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_user_check_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_user_check_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_user_check_t));

	ms->ms_val = SGX_CAST(int*, val);
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memset(ms->ms_val, 0, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(*val);

	ms_ocall_pointer_in_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_out_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_out_t));

	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (val) memcpy((void*)val, ms->ms_val, _len_val);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	ocalloc_size += (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) ? _len_dest : 0;
	ocalloc_size += (src != NULL && sgx_is_within_enclave(src, _len_src)) ? _len_src : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));

	if (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) {
		ms->ms_dest = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dest);
		memcpy(ms->ms_dest, dest, _len_dest);
	} else if (dest == NULL) {
		ms->ms_dest = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (src != NULL && sgx_is_within_enclave(src, _len_src)) {
		ms->ms_src = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_src);
		memcpy((void*)ms->ms_src, src, _len_src);
	} else if (src == NULL) {
		ms->ms_src = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = val;
	ms->ms_len = len;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (dest) memcpy((void*)dest, ms->ms_dest, _len_dest);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_function_allow()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_process_msg_all(int* retval, const void* p_req, int p_req_size, void** p_resp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_req = p_req_size;
	size_t _len_p_resp = 8;

	ms_ocall_sgx_process_msg_all_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_process_msg_all_t);
	void *__tmp = NULL;

	ocalloc_size += (p_req != NULL && sgx_is_within_enclave(p_req, _len_p_req)) ? _len_p_req : 0;
	ocalloc_size += (p_resp != NULL && sgx_is_within_enclave(p_resp, _len_p_resp)) ? _len_p_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_process_msg_all_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_process_msg_all_t));

	if (p_req != NULL && sgx_is_within_enclave(p_req, _len_p_req)) {
		ms->ms_p_req = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_p_req);
		memcpy((void*)ms->ms_p_req, p_req, _len_p_req);
	} else if (p_req == NULL) {
		ms->ms_p_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_p_req_size = p_req_size;
	if (p_resp != NULL && sgx_is_within_enclave(p_resp, _len_p_resp)) {
		ms->ms_p_resp = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_p_resp);
		memset(ms->ms_p_resp, 0, _len_p_resp);
	} else if (p_resp == NULL) {
		ms->ms_p_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;
	if (p_resp) memcpy((void*)p_resp, ms->ms_p_resp, _len_p_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ra_free_network_response_buffer(void** resp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_resp = 8;

	ms_ocall_sgx_ra_free_network_response_buffer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ra_free_network_response_buffer_t);
	void *__tmp = NULL;

	ocalloc_size += (resp != NULL && sgx_is_within_enclave(resp, _len_resp)) ? _len_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ra_free_network_response_buffer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ra_free_network_response_buffer_t));

	if (resp != NULL && sgx_is_within_enclave(resp, _len_resp)) {
		ms->ms_resp = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_resp);
		memcpy(ms->ms_resp, resp, _len_resp);
	} else if (resp == NULL) {
		ms->ms_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(8, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_malloc(unsigned long long* retval, int m_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_malloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_malloc_t));

	ms->ms_m_size = m_size;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_calloc(void** retval, int m_cnt, int m_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_calloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_calloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_calloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_calloc_t));

	ms->ms_m_cnt = m_cnt;
	ms->ms_m_size = m_size;
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_realloc(void** retval, unsigned long long old_mem, int m_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_realloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_realloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_realloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_realloc_t));

	ms->ms_old_mem = old_mem;
	ms->ms_m_size = m_size;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_free(unsigned long long ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_free_t));

	ms->ms_ptr = ptr;
	status = sgx_ocall(12, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fileno_stdout(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_fileno_stdout_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fileno_stdout_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fileno_stdout_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fileno_stdout_t));

	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_pthread_getspecific(void** retval, int key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_pthread_getspecific_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_pthread_getspecific_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_pthread_getspecific_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_pthread_getspecific_t));

	ms->ms_key = key;
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_pthread_setspecific(int* retval, int key, const void* value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_value = 4;

	ms_ocall_sgx_pthread_setspecific_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_pthread_setspecific_t);
	void *__tmp = NULL;

	ocalloc_size += (value != NULL && sgx_is_within_enclave(value, _len_value)) ? _len_value : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_pthread_setspecific_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_pthread_setspecific_t));

	ms->ms_key = key;
	if (value != NULL && sgx_is_within_enclave(value, _len_value)) {
		ms->ms_value = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_value);
		memcpy((void*)ms->ms_value, value, _len_value);
	} else if (value == NULL) {
		ms->ms_value = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sleep(unsigned int seconds)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sleep_t));

	ms->ms_seconds = seconds;
	status = sgx_ocall(16, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_poll(int* retval, void* fds, int fd_size, int nfds, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fds = fd_size;

	ms_ocall_sgx_poll_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_poll_t);
	void *__tmp = NULL;

	ocalloc_size += (fds != NULL && sgx_is_within_enclave(fds, _len_fds)) ? _len_fds : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_poll_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_poll_t));

	if (fds != NULL && sgx_is_within_enclave(fds, _len_fds)) {
		ms->ms_fds = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fds);
		memcpy(ms->ms_fds, fds, _len_fds);
	} else if (fds == NULL) {
		ms->ms_fds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd_size = fd_size;
	ms->ms_nfds = nfds;
	ms->ms_timeout = timeout;
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;
	if (fds) memcpy((void*)fds, ms->ms_fds, _len_fds);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gettimeofday(int* retval, struct timeval* tv, int tv_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = tv_size;

	ms_ocall_sgx_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gettimeofday_t);
	void *__tmp = NULL;

	ocalloc_size += (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) ? _len_tv : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gettimeofday_t));

	if (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) {
		ms->ms_tv = (struct timeval*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tv);
		memcpy(ms->ms_tv, tv, _len_tv);
	} else if (tv == NULL) {
		ms->ms_tv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tv_size = tv_size;
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;
	if (tv) memcpy((void*)tv, ms->ms_tv, _len_tv);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_clock_gettime(int* retval, clockid_t clk_id, struct timespec* tp, int tp_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tp = tp_size;

	ms_ocall_sgx_clock_gettime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_clock_gettime_t);
	void *__tmp = NULL;

	ocalloc_size += (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) ? _len_tp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_clock_gettime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_clock_gettime_t));

	ms->ms_clk_id = clk_id;
	if (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) {
		ms->ms_tp = (struct timespec*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tp);
		memset(ms->ms_tp, 0, _len_tp);
	} else if (tp == NULL) {
		ms->ms_tp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tp_size = tp_size;
	status = sgx_ocall(19, ms);

	if (retval) *retval = ms->ms_retval;
	if (tp) memcpy((void*)tp, ms->ms_tp, _len_tp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_select(int* retval, int nfds, void* rfd, void* wfd, void* efd, int fd_size, struct timeval* timeout, int tv_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rfd = fd_size;
	size_t _len_wfd = fd_size;
	size_t _len_efd = fd_size;
	size_t _len_timeout = tv_size;

	ms_ocall_sgx_select_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_select_t);
	void *__tmp = NULL;

	ocalloc_size += (rfd != NULL && sgx_is_within_enclave(rfd, _len_rfd)) ? _len_rfd : 0;
	ocalloc_size += (wfd != NULL && sgx_is_within_enclave(wfd, _len_wfd)) ? _len_wfd : 0;
	ocalloc_size += (efd != NULL && sgx_is_within_enclave(efd, _len_efd)) ? _len_efd : 0;
	ocalloc_size += (timeout != NULL && sgx_is_within_enclave(timeout, _len_timeout)) ? _len_timeout : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_select_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_select_t));

	ms->ms_nfds = nfds;
	if (rfd != NULL && sgx_is_within_enclave(rfd, _len_rfd)) {
		ms->ms_rfd = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_rfd);
		memcpy(ms->ms_rfd, rfd, _len_rfd);
	} else if (rfd == NULL) {
		ms->ms_rfd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (wfd != NULL && sgx_is_within_enclave(wfd, _len_wfd)) {
		ms->ms_wfd = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wfd);
		memcpy(ms->ms_wfd, wfd, _len_wfd);
	} else if (wfd == NULL) {
		ms->ms_wfd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (efd != NULL && sgx_is_within_enclave(efd, _len_efd)) {
		ms->ms_efd = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_efd);
		memcpy(ms->ms_efd, efd, _len_efd);
	} else if (efd == NULL) {
		ms->ms_efd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd_size = fd_size;
	if (timeout != NULL && sgx_is_within_enclave(timeout, _len_timeout)) {
		ms->ms_timeout = (struct timeval*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timeout);
		memcpy(ms->ms_timeout, timeout, _len_timeout);
	} else if (timeout == NULL) {
		ms->ms_timeout = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tv_size = tv_size;
	status = sgx_ocall(20, ms);

	if (retval) *retval = ms->ms_retval;
	if (rfd) memcpy((void*)rfd, ms->ms_rfd, _len_rfd);
	if (wfd) memcpy((void*)wfd, ms->ms_wfd, _len_wfd);
	if (efd) memcpy((void*)efd, ms->ms_efd, _len_efd);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int* retval, int s, int level, int optname, const char* optval, int optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_ocall_sgx_setsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setsockopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setsockopt_t));

	ms->ms_s = s;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optval);
		memcpy((void*)ms->ms_optval, optval, _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optlen = optlen;
	status = sgx_ocall(21, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_socketpair(int* retval, int domain, int type, int protocol, int* sv)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sv = 2;

	ms_ocall_sgx_socketpair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_socketpair_t);
	void *__tmp = NULL;

	ocalloc_size += (sv != NULL && sgx_is_within_enclave(sv, _len_sv)) ? _len_sv : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_socketpair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_socketpair_t));

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	if (sv != NULL && sgx_is_within_enclave(sv, _len_sv)) {
		ms->ms_sv = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sv);
		memset(ms->ms_sv, 0, _len_sv);
	} else if (sv == NULL) {
		ms->ms_sv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(22, ms);

	if (retval) *retval = ms->ms_retval;
	if (sv) memcpy((void*)sv, ms->ms_sv, _len_sv);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_accept(int* retval, int s, struct sockaddr* addr, int addr_size, int* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addr_size;
	size_t _len_addrlen = 4;

	ms_ocall_sgx_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_accept_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;
	ocalloc_size += (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_accept_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memset(ms->ms_addr, 0, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addr_size = addr_size;
	if (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) {
		ms->ms_addrlen = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		memcpy(ms->ms_addrlen, addrlen, _len_addrlen);
	} else if (addrlen == NULL) {
		ms->ms_addrlen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(23, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr) memcpy((void*)addr, ms->ms_addr, _len_addr);
	if (addrlen) memcpy((void*)addrlen, ms->ms_addrlen, _len_addrlen);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_bind(int* retval, int s, const struct sockaddr* addr, int addr_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addr_size;

	ms_ocall_sgx_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_bind_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_bind_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memcpy((void*)ms->ms_addr, addr, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addr_size = addr_size;
	status = sgx_ocall(24, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fstat(int* retval, int fd, struct stat* buf, int buflen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = buflen;

	ms_ocall_sgx_fstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fstat_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fstat_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buflen = buflen;
	status = sgx_ocall(25, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_socket(int* retval, int af, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_socket_t));

	ms->ms_af = af;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(26, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_listen(int* retval, int s, int backlog)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_listen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_listen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_listen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_listen_t));

	ms->ms_s = s;
	ms->ms_backlog = backlog;
	status = sgx_ocall(27, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_connect(int* retval, int s, const struct sockaddr* addr, int addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen;

	ms_ocall_sgx_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_connect_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_connect_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memcpy((void*)ms->ms_addr, addr, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(28, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gethostbyname(struct hostent** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_sgx_gethostbyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gethostbyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gethostbyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gethostbyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(29, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_open(int* retval, const char* pathname, int flags, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_sgx_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_open_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_open_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	ms->ms_mode = mode;
	status = sgx_ocall(30, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ftime(struct timeb* tb, int size_timeb)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tb = size_timeb;

	ms_ocall_sgx_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ftime_t);
	void *__tmp = NULL;

	ocalloc_size += (tb != NULL && sgx_is_within_enclave(tb, _len_tb)) ? _len_tb : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ftime_t));

	if (tb != NULL && sgx_is_within_enclave(tb, _len_tb)) {
		ms->ms_tb = (struct timeb*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tb);
		memset(ms->ms_tb, 0, _len_tb);
	} else if (tb == NULL) {
		ms->ms_tb = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size_timeb = size_timeb;
	status = sgx_ocall(31, ms);

	if (tb) memcpy((void*)tb, ms->ms_tb, _len_tb);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getenv(int* retval, const char* env, int envlen, char* ret_str, int ret_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_env = envlen;
	size_t _len_ret_str = ret_len;

	ms_ocall_sgx_getenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getenv_t);
	void *__tmp = NULL;

	ocalloc_size += (env != NULL && sgx_is_within_enclave(env, _len_env)) ? _len_env : 0;
	ocalloc_size += (ret_str != NULL && sgx_is_within_enclave(ret_str, _len_ret_str)) ? _len_ret_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getenv_t));

	if (env != NULL && sgx_is_within_enclave(env, _len_env)) {
		ms->ms_env = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_env);
		memcpy((void*)ms->ms_env, env, _len_env);
	} else if (env == NULL) {
		ms->ms_env = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_envlen = envlen;
	if (ret_str != NULL && sgx_is_within_enclave(ret_str, _len_ret_str)) {
		ms->ms_ret_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ret_str);
		memset(ms->ms_ret_str, 0, _len_ret_str);
	} else if (ret_str == NULL) {
		ms->ms_ret_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_ret_len = ret_len;
	status = sgx_ocall(32, ms);

	if (retval) *retval = ms->ms_retval;
	if (ret_str) memcpy((void*)ret_str, ms->ms_ret_str, _len_ret_str);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getaddrinfo(int* retval, const char* node, const char* service, const void* hints, int hints_len, void** res, int res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_node = node ? strlen(node) + 1 : 0;
	size_t _len_service = service ? strlen(service) + 1 : 0;
	size_t _len_hints = hints_len;
	size_t _len_res = res_len;

	ms_ocall_sgx_getaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getaddrinfo_t);
	void *__tmp = NULL;

	ocalloc_size += (node != NULL && sgx_is_within_enclave(node, _len_node)) ? _len_node : 0;
	ocalloc_size += (service != NULL && sgx_is_within_enclave(service, _len_service)) ? _len_service : 0;
	ocalloc_size += (hints != NULL && sgx_is_within_enclave(hints, _len_hints)) ? _len_hints : 0;
	ocalloc_size += (res != NULL && sgx_is_within_enclave(res, _len_res)) ? _len_res : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getaddrinfo_t));

	if (node != NULL && sgx_is_within_enclave(node, _len_node)) {
		ms->ms_node = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_node);
		memcpy((void*)ms->ms_node, node, _len_node);
	} else if (node == NULL) {
		ms->ms_node = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (service != NULL && sgx_is_within_enclave(service, _len_service)) {
		ms->ms_service = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_service);
		memcpy((void*)ms->ms_service, service, _len_service);
	} else if (service == NULL) {
		ms->ms_service = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (hints != NULL && sgx_is_within_enclave(hints, _len_hints)) {
		ms->ms_hints = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_hints);
		memcpy((void*)ms->ms_hints, hints, _len_hints);
	} else if (hints == NULL) {
		ms->ms_hints = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_hints_len = hints_len;
	if (res != NULL && sgx_is_within_enclave(res, _len_res)) {
		ms->ms_res = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_res);
		memset(ms->ms_res, 0, _len_res);
	} else if (res == NULL) {
		ms->ms_res = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_res_len = res_len;
	status = sgx_ocall(33, ms);

	if (retval) *retval = ms->ms_retval;
	if (hints) memcpy((void*)hints, ms->ms_hints, _len_hints);
	if (res) memcpy((void*)res, ms->ms_res, _len_res);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_freeaddrinfo(void* res, int res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_res = res_len;

	ms_ocall_sgx_freeaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_freeaddrinfo_t);
	void *__tmp = NULL;

	ocalloc_size += (res != NULL && sgx_is_within_enclave(res, _len_res)) ? _len_res : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_freeaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_freeaddrinfo_t));

	if (res != NULL && sgx_is_within_enclave(res, _len_res)) {
		ms->ms_res = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_res);
		memcpy(ms->ms_res, res, _len_res);
	} else if (res == NULL) {
		ms->ms_res = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_res_len = res_len;
	status = sgx_ocall(34, ms);

	if (res) memcpy((void*)res, ms->ms_res, _len_res);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getsockname(int* retval, int s, struct sockaddr* name, int nlen, int* namelen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = nlen;
	size_t _len_namelen = 4;

	ms_ocall_sgx_getsockname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getsockname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (namelen != NULL && sgx_is_within_enclave(namelen, _len_namelen)) ? _len_namelen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getsockname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getsockname_t));

	ms->ms_s = s;
	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memset(ms->ms_name, 0, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nlen = nlen;
	if (namelen != NULL && sgx_is_within_enclave(namelen, _len_namelen)) {
		ms->ms_namelen = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_namelen);
		memcpy(ms->ms_namelen, namelen, _len_namelen);
	} else if (namelen == NULL) {
		ms->ms_namelen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(35, ms);

	if (retval) *retval = ms->ms_retval;
	if (name) memcpy((void*)name, ms->ms_name, _len_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int* retval, int s, int level, int optname, char* optval, int optval_len, int* optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optval_len;
	size_t _len_optlen = 4;

	ms_ocall_sgx_getsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getsockopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;
	ocalloc_size += (optlen != NULL && sgx_is_within_enclave(optlen, _len_optlen)) ? _len_optlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getsockopt_t));

	ms->ms_s = s;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optval);
		memset(ms->ms_optval, 0, _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optval_len = optval_len;
	if (optlen != NULL && sgx_is_within_enclave(optlen, _len_optlen)) {
		ms->ms_optlen = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optlen);
		memcpy(ms->ms_optlen, optlen, _len_optlen);
	} else if (optlen == NULL) {
		ms->ms_optlen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(36, ms);

	if (retval) *retval = ms->ms_retval;
	if (optval) memcpy((void*)optval, ms->ms_optval, _len_optval);
	if (optlen) memcpy((void*)optlen, ms->ms_optlen, _len_optlen);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getservbyname(const char* name, int name_len, const char* proto, int proto_len, void* serv_ptr, int serv_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name_len;
	size_t _len_proto = proto_len;
	size_t _len_serv_ptr = serv_len;

	ms_ocall_sgx_getservbyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getservbyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) ? _len_proto : 0;
	ocalloc_size += (serv_ptr != NULL && sgx_is_within_enclave(serv_ptr, _len_serv_ptr)) ? _len_serv_ptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getservbyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getservbyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_name_len = name_len;
	if (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) {
		ms->ms_proto = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_proto);
		memcpy((void*)ms->ms_proto, proto, _len_proto);
	} else if (proto == NULL) {
		ms->ms_proto = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_proto_len = proto_len;
	if (serv_ptr != NULL && sgx_is_within_enclave(serv_ptr, _len_serv_ptr)) {
		ms->ms_serv_ptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_serv_ptr);
		memset(ms->ms_serv_ptr, 0, _len_serv_ptr);
	} else if (serv_ptr == NULL) {
		ms->ms_serv_ptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_serv_len = serv_len;
	status = sgx_ocall(37, ms);

	if (serv_ptr) memcpy((void*)serv_ptr, ms->ms_serv_ptr, _len_serv_ptr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getprotobynumber(int number, void* proto, int proto_len, char* proto_name, int proto_name_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_proto = proto_len;
	size_t _len_proto_name = proto_name_len;

	ms_ocall_sgx_getprotobynumber_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getprotobynumber_t);
	void *__tmp = NULL;

	ocalloc_size += (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) ? _len_proto : 0;
	ocalloc_size += (proto_name != NULL && sgx_is_within_enclave(proto_name, _len_proto_name)) ? _len_proto_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getprotobynumber_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getprotobynumber_t));

	ms->ms_number = number;
	if (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) {
		ms->ms_proto = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_proto);
		memset(ms->ms_proto, 0, _len_proto);
	} else if (proto == NULL) {
		ms->ms_proto = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_proto_len = proto_len;
	if (proto_name != NULL && sgx_is_within_enclave(proto_name, _len_proto_name)) {
		ms->ms_proto_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_proto_name);
		memset(ms->ms_proto_name, 0, _len_proto_name);
	} else if (proto_name == NULL) {
		ms->ms_proto_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_proto_name_len = proto_name_len;
	status = sgx_ocall(38, ms);

	if (proto) memcpy((void*)proto, ms->ms_proto, _len_proto);
	if (proto_name) memcpy((void*)proto_name, ms->ms_proto_name, _len_proto_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_pthread_create(int* retval, void* port, int port_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_port = port_len;

	ms_ocall_sgx_pthread_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_pthread_create_t);
	void *__tmp = NULL;

	ocalloc_size += (port != NULL && sgx_is_within_enclave(port, _len_port)) ? _len_port : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_pthread_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_pthread_create_t));

	if (port != NULL && sgx_is_within_enclave(port, _len_port)) {
		ms->ms_port = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_port);
		memcpy(ms->ms_port, port, _len_port);
	} else if (port == NULL) {
		ms->ms_port = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port_len = port_len;
	status = sgx_ocall(39, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_epoll_wait(int* retval, int epfd, void* events, int events_len, int maxevents, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_events = events_len;

	ms_ocall_sgx_epoll_wait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_epoll_wait_t);
	void *__tmp = NULL;

	ocalloc_size += (events != NULL && sgx_is_within_enclave(events, _len_events)) ? _len_events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_epoll_wait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_epoll_wait_t));

	ms->ms_epfd = epfd;
	if (events != NULL && sgx_is_within_enclave(events, _len_events)) {
		ms->ms_events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_events);
		memcpy(ms->ms_events, events, _len_events);
	} else if (events == NULL) {
		ms->ms_events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_events_len = events_len;
	ms->ms_maxevents = maxevents;
	ms->ms_timeout = timeout;
	status = sgx_ocall(40, ms);

	if (retval) *retval = ms->ms_retval;
	if (events) memcpy((void*)events, ms->ms_events, _len_events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_epoll_ctl(int* retval, int epfd, int op, int fd, void* event, int event_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_event = event_len;

	ms_ocall_sgx_epoll_ctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_epoll_ctl_t);
	void *__tmp = NULL;

	ocalloc_size += (event != NULL && sgx_is_within_enclave(event, _len_event)) ? _len_event : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_epoll_ctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_epoll_ctl_t));

	ms->ms_epfd = epfd;
	ms->ms_op = op;
	ms->ms_fd = fd;
	if (event != NULL && sgx_is_within_enclave(event, _len_event)) {
		ms->ms_event = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_event);
		memcpy(ms->ms_event, event, _len_event);
	} else if (event == NULL) {
		ms->ms_event = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_len = event_len;
	status = sgx_ocall(41, ms);

	if (retval) *retval = ms->ms_retval;
	if (event) memcpy((void*)event, ms->ms_event, _len_event);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_epoll_create(int* retval, int size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_epoll_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_epoll_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_epoll_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_epoll_create_t));

	ms->ms_size = size;
	status = sgx_ocall(42, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_signal(int signum, int f_id)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_signal_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_signal_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_signal_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_signal_t));

	ms->ms_signum = signum;
	ms->ms_f_id = f_id;
	status = sgx_ocall(43, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_eventfd(int* retval, unsigned int initval, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_eventfd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_eventfd_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_eventfd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_eventfd_t));

	ms->ms_initval = initval;
	ms->ms_flags = flags;
	status = sgx_ocall(44, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sigfillset(int* retval, void* set, int setlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = setlen;

	ms_ocall_sgx_sigfillset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sigfillset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sigfillset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sigfillset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_setlen = setlen;
	status = sgx_ocall(45, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sigemptyset(int* retval, void* set, int setlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = setlen;

	ms_ocall_sgx_sigemptyset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sigemptyset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sigemptyset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sigemptyset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_setlen = setlen;
	status = sgx_ocall(46, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sigaction(int* retval, int signum, const void* act, int act_len, void* oldact, int oldact_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_act = act_len;
	size_t _len_oldact = oldact_len;

	ms_ocall_sgx_sigaction_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sigaction_t);
	void *__tmp = NULL;

	ocalloc_size += (act != NULL && sgx_is_within_enclave(act, _len_act)) ? _len_act : 0;
	ocalloc_size += (oldact != NULL && sgx_is_within_enclave(oldact, _len_oldact)) ? _len_oldact : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sigaction_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sigaction_t));

	ms->ms_signum = signum;
	if (act != NULL && sgx_is_within_enclave(act, _len_act)) {
		ms->ms_act = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_act);
		memcpy((void*)ms->ms_act, act, _len_act);
	} else if (act == NULL) {
		ms->ms_act = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_act_len = act_len;
	if (oldact != NULL && sgx_is_within_enclave(oldact, _len_oldact)) {
		ms->ms_oldact = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_oldact);
		memcpy(ms->ms_oldact, oldact, _len_oldact);
	} else if (oldact == NULL) {
		ms->ms_oldact = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_oldact_len = oldact_len;
	status = sgx_ocall(47, ms);

	if (retval) *retval = ms->ms_retval;
	if (oldact) memcpy((void*)oldact, ms->ms_oldact, _len_oldact);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fcntl(int* retval, int fd, int cmd, long int arg)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_fcntl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fcntl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fcntl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fcntl_t));

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(48, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fcntl2(int* retval, int fd, int cmd, void* lock, int lock_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lock = lock_len;

	ms_ocall_sgx_fcntl2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fcntl2_t);
	void *__tmp = NULL;

	ocalloc_size += (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) ? _len_lock : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fcntl2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fcntl2_t));

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	if (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) {
		ms->ms_lock = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lock);
		memcpy(ms->ms_lock, lock, _len_lock);
	} else if (lock == NULL) {
		ms->ms_lock = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_lock_len = lock_len;
	status = sgx_ocall(49, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_chmod(int* retval, const char* pathname, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_sgx_chmod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_chmod_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_chmod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_chmod_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(50, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_chdir(int* retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_sgx_chdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_chdir_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_chdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_chdir_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(51, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_pipe(int* retval, int* pipefd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pipefd = 2;

	ms_ocall_sgx_pipe_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_pipe_t);
	void *__tmp = NULL;

	ocalloc_size += (pipefd != NULL && sgx_is_within_enclave(pipefd, _len_pipefd)) ? _len_pipefd : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_pipe_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_pipe_t));

	if (pipefd != NULL && sgx_is_within_enclave(pipefd, _len_pipefd)) {
		ms->ms_pipefd = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pipefd);
		memcpy(ms->ms_pipefd, pipefd, _len_pipefd);
	} else if (pipefd == NULL) {
		ms->ms_pipefd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(52, ms);

	if (retval) *retval = ms->ms_retval;
	if (pipefd) memcpy((void*)pipefd, ms->ms_pipefd, _len_pipefd);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sysctl(int* retval, int* name, int nlen, void* oldval, int oldval_len, size_t* oldlenp, void* newval, size_t newlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = nlen;
	size_t _len_oldval = oldval_len;
	size_t _len_oldlenp = 8;
	size_t _len_newval = newlen;

	ms_ocall_sgx_sysctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sysctl_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (oldval != NULL && sgx_is_within_enclave(oldval, _len_oldval)) ? _len_oldval : 0;
	ocalloc_size += (oldlenp != NULL && sgx_is_within_enclave(oldlenp, _len_oldlenp)) ? _len_oldlenp : 0;
	ocalloc_size += (newval != NULL && sgx_is_within_enclave(newval, _len_newval)) ? _len_newval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sysctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sysctl_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy(ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nlen = nlen;
	if (oldval != NULL && sgx_is_within_enclave(oldval, _len_oldval)) {
		ms->ms_oldval = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_oldval);
		memcpy(ms->ms_oldval, oldval, _len_oldval);
	} else if (oldval == NULL) {
		ms->ms_oldval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_oldval_len = oldval_len;
	if (oldlenp != NULL && sgx_is_within_enclave(oldlenp, _len_oldlenp)) {
		ms->ms_oldlenp = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_oldlenp);
		memcpy(ms->ms_oldlenp, oldlenp, _len_oldlenp);
	} else if (oldlenp == NULL) {
		ms->ms_oldlenp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (newval != NULL && sgx_is_within_enclave(newval, _len_newval)) {
		ms->ms_newval = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_newval);
		memcpy(ms->ms_newval, newval, _len_newval);
	} else if (newval == NULL) {
		ms->ms_newval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_newlen = newlen;
	status = sgx_ocall(53, ms);

	if (retval) *retval = ms->ms_retval;
	if (oldval) memcpy((void*)oldval, ms->ms_oldval, _len_oldval);
	if (oldlenp) memcpy((void*)oldlenp, ms->ms_oldlenp, _len_oldlenp);
	if (newval) memcpy((void*)newval, ms->ms_newval, _len_newval);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fork(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_fork_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fork_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fork_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fork_t));

	status = sgx_ocall(54, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ntohs(unsigned short int* retval, unsigned short int netshort)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_ntohs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ntohs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ntohs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ntohs_t));

	ms->ms_netshort = netshort;
	status = sgx_ocall(55, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ntohl(unsigned long int* retval, unsigned long int netlong)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_ntohl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ntohl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ntohl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ntohl_t));

	ms->ms_netlong = netlong;
	status = sgx_ocall(56, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time(time_t* retval, time_t* timep, int t_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;

	ms_ocall_get_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_t);
	void *__tmp = NULL;

	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timep);
		memset(ms->ms_timep, 0, _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	status = sgx_ocall(57, ms);

	if (retval) *retval = ms->ms_retval;
	if (timep) memcpy((void*)timep, ms->ms_timep, _len_timep);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_recv(int* retval, int s, char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_sgx_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_recv_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_recv_t));

	ms->ms_s = s;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(58, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_direct_recv(int* retval, int s, unsigned long long buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_direct_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_direct_recv_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_direct_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_direct_recv_t));

	ms->ms_s = s;
	ms->ms_buf = buf;
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(59, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_send(int* retval, int s, const char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_sgx_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_send_t));

	ms->ms_s = s;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(60, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_direct_send(int* retval, int s, unsigned long long buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_direct_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_direct_send_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_direct_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_direct_send_t));

	ms->ms_s = s;
	ms->ms_buf = buf;
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(61, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_rename(int* retval, const char* from_str, const char* to_str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_from_str = from_str ? strlen(from_str) + 1 : 0;
	size_t _len_to_str = to_str ? strlen(to_str) + 1 : 0;

	ms_ocall_sgx_rename_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_rename_t);
	void *__tmp = NULL;

	ocalloc_size += (from_str != NULL && sgx_is_within_enclave(from_str, _len_from_str)) ? _len_from_str : 0;
	ocalloc_size += (to_str != NULL && sgx_is_within_enclave(to_str, _len_to_str)) ? _len_to_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_rename_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_rename_t));

	if (from_str != NULL && sgx_is_within_enclave(from_str, _len_from_str)) {
		ms->ms_from_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_from_str);
		memcpy((void*)ms->ms_from_str, from_str, _len_from_str);
	} else if (from_str == NULL) {
		ms->ms_from_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (to_str != NULL && sgx_is_within_enclave(to_str, _len_to_str)) {
		ms->ms_to_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_to_str);
		memcpy((void*)ms->ms_to_str, to_str, _len_to_str);
	} else if (to_str == NULL) {
		ms->ms_to_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(62, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_unlink(int* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_ocall_sgx_unlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_unlink_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_unlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_unlink_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(63, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_close_t));

	ms->ms_fd = fd;
	status = sgx_ocall(64, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ftruncate(int* retval, int fd, off_t length)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ftruncate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ftruncate_t));

	ms->ms_fd = fd;
	ms->ms_length = length;
	status = sgx_ocall(65, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_shutdown_t));

	ms->ms_fd = fd;
	ms->ms_how = how;
	status = sgx_ocall(66, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_exit(int exit_status)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_exit_t));

	ms->ms_exit_status = exit_status;
	status = sgx_ocall(67, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_write(int* retval, int fd, const void* buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_ocall_sgx_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_write_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_n = n;
	status = sgx_ocall(68, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_direct_write(int* retval, int fd, unsigned long long buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_direct_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_direct_write_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_direct_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_direct_write_t));

	ms->ms_fd = fd;
	ms->ms_buf = buf;
	ms->ms_n = n;
	status = sgx_ocall(69, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_read(int* retval, int fd, void* buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_ocall_sgx_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_read_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_read_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_n = n;
	status = sgx_ocall(70, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_direct_read(int* retval, int fd, unsigned long long buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_direct_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_direct_read_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_direct_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_direct_read_t));

	ms->ms_fd = fd;
	ms->ms_buf = buf;
	ms->ms_n = n;
	status = sgx_ocall(71, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_waitpid(pid_t* retval, unsigned int pid, int* _status, int status_len, int options)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__status = status_len;

	ms_ocall_sgx_waitpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_waitpid_t);
	void *__tmp = NULL;

	ocalloc_size += (_status != NULL && sgx_is_within_enclave(_status, _len__status)) ? _len__status : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_waitpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_waitpid_t));

	ms->ms_pid = pid;
	if (_status != NULL && sgx_is_within_enclave(_status, _len__status)) {
		ms->ms__status = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__status);
		memcpy(ms->ms__status, _status, _len__status);
	} else if (_status == NULL) {
		ms->ms__status = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_status_len = status_len;
	ms->ms_options = options;
	status = sgx_ocall(72, ms);

	if (retval) *retval = ms->ms_retval;
	if (_status) memcpy((void*)_status, ms->ms__status, _len__status);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getpid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_getpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getpid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getpid_t));

	status = sgx_ocall(73, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setsid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_setsid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setsid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setsid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setsid_t));

	status = sgx_ocall(74, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getgroups(int* retval, int size, unsigned int* list, int list_num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_list = list_num;

	ms_ocall_sgx_getgroups_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getgroups_t);
	void *__tmp = NULL;

	ocalloc_size += (list != NULL && sgx_is_within_enclave(list, _len_list)) ? _len_list : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getgroups_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getgroups_t));

	ms->ms_size = size;
	if (list != NULL && sgx_is_within_enclave(list, _len_list)) {
		ms->ms_list = (unsigned int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_list);
		memcpy(ms->ms_list, list, _len_list);
	} else if (list == NULL) {
		ms->ms_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_list_num = list_num;
	status = sgx_ocall(75, ms);

	if (retval) *retval = ms->ms_retval;
	if (list) memcpy((void*)list, ms->ms_list, _len_list);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setgroups(int* retval, size_t size, const unsigned int* list, int list_num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_list = list_num;

	ms_ocall_sgx_setgroups_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setgroups_t);
	void *__tmp = NULL;

	ocalloc_size += (list != NULL && sgx_is_within_enclave(list, _len_list)) ? _len_list : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setgroups_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setgroups_t));

	ms->ms_size = size;
	if (list != NULL && sgx_is_within_enclave(list, _len_list)) {
		ms->ms_list = (unsigned int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_list);
		memcpy((void*)ms->ms_list, list, _len_list);
	} else if (list == NULL) {
		ms->ms_list = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_list_num = list_num;
	status = sgx_ocall(76, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setuid(int* retval, unsigned int uid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_setuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setuid_t));

	ms->ms_uid = uid;
	status = sgx_ocall(77, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setgid(int* retval, unsigned int gid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_setgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setgid_t));

	ms->ms_gid = gid;
	status = sgx_ocall(78, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_seteuid(int* retval, unsigned int uid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_seteuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_seteuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_seteuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_seteuid_t));

	ms->ms_uid = uid;
	status = sgx_ocall(79, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setegid(int* retval, unsigned int gid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_setegid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setegid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setegid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setegid_t));

	ms->ms_gid = gid;
	status = sgx_ocall(80, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_dup2(int* retval, int oldfd, int newfd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_dup2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_dup2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_dup2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_dup2_t));

	ms->ms_oldfd = oldfd;
	ms->ms_newfd = newfd;
	status = sgx_ocall(81, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_getuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getuid_t));

	status = sgx_ocall(82, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getgid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_getgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getgid_t));

	status = sgx_ocall(83, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_geteuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_geteuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_geteuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_geteuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_geteuid_t));

	status = sgx_ocall(84, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getegid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_getegid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getegid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getegid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getegid_t));

	status = sgx_ocall(85, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_lseek(off_t* retval, int fildes, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_lseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_lseek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_lseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_lseek_t));

	ms->ms_fildes = fildes;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(86, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gethostname(int* retval, char* name, size_t namelen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = namelen;

	ms_ocall_sgx_gethostname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gethostname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gethostname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gethostname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memset(ms->ms_name, 0, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_namelen = namelen;
	status = sgx_ocall(87, ms);

	if (retval) *retval = ms->ms_retval;
	if (name) memcpy((void*)name, ms->ms_name, _len_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm** retval, const time_t* timep, int t_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;

	ms_ocall_sgx_localtime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_localtime_t);
	void *__tmp = NULL;

	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_localtime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_localtime_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timep);
		memcpy((void*)ms->ms_timep, timep, _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	status = sgx_ocall(88, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gmtime(struct tm** retval, const time_t* timep, int t_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;

	ms_ocall_sgx_gmtime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gmtime_t);
	void *__tmp = NULL;

	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gmtime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gmtime_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timep);
		memcpy((void*)ms->ms_timep, timep, _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	status = sgx_ocall(89, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_mktime(time_t* retval, struct tm* timeptr, int tm_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = tm_len;

	ms_ocall_sgx_mktime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_mktime_t);
	void *__tmp = NULL;

	ocalloc_size += (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) ? _len_timeptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_mktime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_mktime_t));

	if (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) {
		ms->ms_timeptr = (struct tm*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		memcpy(ms->ms_timeptr, timeptr, _len_timeptr);
	} else if (timeptr == NULL) {
		ms->ms_timeptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tm_len = tm_len;
	status = sgx_ocall(90, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_sendto(int* retval, int s, const void* msg, int len, int flags, const struct sockaddr* to, int tolen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg = len;
	size_t _len_to = tolen;

	ms_ocall_sgx_sendto_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_sendto_t);
	void *__tmp = NULL;

	ocalloc_size += (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) ? _len_msg : 0;
	ocalloc_size += (to != NULL && sgx_is_within_enclave(to, _len_to)) ? _len_to : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_sendto_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_sendto_t));

	ms->ms_s = s;
	if (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) {
		ms->ms_msg = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_msg);
		memcpy((void*)ms->ms_msg, msg, _len_msg);
	} else if (msg == NULL) {
		ms->ms_msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (to != NULL && sgx_is_within_enclave(to, _len_to)) {
		ms->ms_to = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_to);
		memcpy((void*)ms->ms_to, to, _len_to);
	} else if (to == NULL) {
		ms->ms_to = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tolen = tolen;
	status = sgx_ocall(91, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_recvfrom(int* retval, int s, void* msg, int len, int flags, struct sockaddr* fr, int frlen, int* in_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg = len;
	size_t _len_fr = frlen;
	size_t _len_in_len = 4;

	ms_ocall_sgx_recvfrom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_recvfrom_t);
	void *__tmp = NULL;

	ocalloc_size += (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) ? _len_msg : 0;
	ocalloc_size += (fr != NULL && sgx_is_within_enclave(fr, _len_fr)) ? _len_fr : 0;
	ocalloc_size += (in_len != NULL && sgx_is_within_enclave(in_len, _len_in_len)) ? _len_in_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_recvfrom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_recvfrom_t));

	ms->ms_s = s;
	if (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) {
		ms->ms_msg = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_msg);
		memset(ms->ms_msg, 0, _len_msg);
	} else if (msg == NULL) {
		ms->ms_msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (fr != NULL && sgx_is_within_enclave(fr, _len_fr)) {
		ms->ms_fr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fr);
		memset(ms->ms_fr, 0, _len_fr);
	} else if (fr == NULL) {
		ms->ms_fr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_frlen = frlen;
	if (in_len != NULL && sgx_is_within_enclave(in_len, _len_in_len)) {
		ms->ms_in_len = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_in_len);
		memcpy(ms->ms_in_len, in_len, _len_in_len);
	} else if (in_len == NULL) {
		ms->ms_in_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(92, ms);

	if (retval) *retval = ms->ms_retval;
	if (msg) memcpy((void*)msg, ms->ms_msg, _len_msg);
	if (fr) memcpy((void*)fr, ms->ms_fr, _len_fr);
	if (in_len) memcpy((void*)in_len, ms->ms_in_len, _len_in_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fclose(int* retval, FILE* file, int file_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file_size;

	ms_ocall_sgx_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fclose_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fclose_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (FILE*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy(ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_file_size = file_size;
	status = sgx_ocall(93, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_stat(int* retval, const char* filename, struct stat* st, int stat_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_st = stat_size;

	ms_ocall_sgx_stat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_stat_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (st != NULL && sgx_is_within_enclave(st, _len_st)) ? _len_st : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_stat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_stat_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (st != NULL && sgx_is_within_enclave(st, _len_st)) {
		ms->ms_st = (struct stat*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_st);
		memset(ms->ms_st, 0, _len_st);
	} else if (st == NULL) {
		ms->ms_st = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_stat_size = stat_size;
	status = sgx_ocall(94, ms);

	if (retval) *retval = ms->ms_retval;
	if (st) memcpy((void*)st, ms->ms_st, _len_st);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_mkdir(int* retval, const char* path, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_sgx_mkdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_mkdir_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_mkdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_mkdir_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(95, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_clock(long int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_clock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_clock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_clock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_clock_t));

	status = sgx_ocall(96, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(97, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(98, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(99, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(100, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(101, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(102, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(103, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(104, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(105, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

