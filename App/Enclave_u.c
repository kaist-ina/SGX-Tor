#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_user_check(void* pms)
{
	ms_ocall_pointer_user_check_t* ms = SGX_CAST(ms_ocall_pointer_user_check_t*, pms);
	ocall_pointer_user_check(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in(void* pms)
{
	ms_ocall_pointer_in_t* ms = SGX_CAST(ms_ocall_pointer_in_t*, pms);
	ocall_pointer_in(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_out(void* pms)
{
	ms_ocall_pointer_out_t* ms = SGX_CAST(ms_ocall_pointer_out_t*, pms);
	ocall_pointer_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pointer_in_out(void* pms)
{
	ms_ocall_pointer_in_out_t* ms = SGX_CAST(ms_ocall_pointer_in_out_t*, pms);
	ocall_pointer_in_out(ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_memccpy(void* pms)
{
	ms_memccpy_t* ms = SGX_CAST(ms_memccpy_t*, pms);
	ms->ms_retval = memccpy(ms->ms_dest, (const void*)ms->ms_src, ms->ms_val, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_function_allow(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_function_allow();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_process_msg_all(void* pms)
{
	ms_ocall_sgx_process_msg_all_t* ms = SGX_CAST(ms_ocall_sgx_process_msg_all_t*, pms);
	ms->ms_retval = ocall_sgx_process_msg_all((const void*)ms->ms_p_req, ms->ms_p_req_size, ms->ms_p_resp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_ra_free_network_response_buffer(void* pms)
{
	ms_ocall_sgx_ra_free_network_response_buffer_t* ms = SGX_CAST(ms_ocall_sgx_ra_free_network_response_buffer_t*, pms);
	ocall_sgx_ra_free_network_response_buffer(ms->ms_resp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_malloc(void* pms)
{
	ms_ocall_sgx_malloc_t* ms = SGX_CAST(ms_ocall_sgx_malloc_t*, pms);
	ms->ms_retval = ocall_sgx_malloc(ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_calloc(void* pms)
{
	ms_ocall_sgx_calloc_t* ms = SGX_CAST(ms_ocall_sgx_calloc_t*, pms);
	ms->ms_retval = ocall_sgx_calloc(ms->ms_m_cnt, ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_realloc(void* pms)
{
	ms_ocall_sgx_realloc_t* ms = SGX_CAST(ms_ocall_sgx_realloc_t*, pms);
	ms->ms_retval = ocall_sgx_realloc(ms->ms_old_mem, ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_free(void* pms)
{
	ms_ocall_sgx_free_t* ms = SGX_CAST(ms_ocall_sgx_free_t*, pms);
	ocall_sgx_free(ms->ms_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fileno_stdout(void* pms)
{
	ms_ocall_sgx_fileno_stdout_t* ms = SGX_CAST(ms_ocall_sgx_fileno_stdout_t*, pms);
	ms->ms_retval = ocall_sgx_fileno_stdout();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_pthread_getspecific(void* pms)
{
	ms_ocall_sgx_pthread_getspecific_t* ms = SGX_CAST(ms_ocall_sgx_pthread_getspecific_t*, pms);
	ms->ms_retval = ocall_sgx_pthread_getspecific(ms->ms_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_pthread_setspecific(void* pms)
{
	ms_ocall_sgx_pthread_setspecific_t* ms = SGX_CAST(ms_ocall_sgx_pthread_setspecific_t*, pms);
	ms->ms_retval = ocall_sgx_pthread_setspecific(ms->ms_key, (const void*)ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sleep(void* pms)
{
	ms_ocall_sgx_sleep_t* ms = SGX_CAST(ms_ocall_sgx_sleep_t*, pms);
	ocall_sgx_sleep(ms->ms_seconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_poll(void* pms)
{
	ms_ocall_sgx_poll_t* ms = SGX_CAST(ms_ocall_sgx_poll_t*, pms);
	ms->ms_retval = ocall_sgx_poll(ms->ms_fds, ms->ms_fd_size, ms->ms_nfds, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gettimeofday(void* pms)
{
	ms_ocall_sgx_gettimeofday_t* ms = SGX_CAST(ms_ocall_sgx_gettimeofday_t*, pms);
	ms->ms_retval = ocall_sgx_gettimeofday(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_clock_gettime(void* pms)
{
	ms_ocall_sgx_clock_gettime_t* ms = SGX_CAST(ms_ocall_sgx_clock_gettime_t*, pms);
	ms->ms_retval = ocall_sgx_clock_gettime(ms->ms_clk_id, ms->ms_tp, ms->ms_tp_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_select(void* pms)
{
	ms_ocall_sgx_select_t* ms = SGX_CAST(ms_ocall_sgx_select_t*, pms);
	ms->ms_retval = ocall_sgx_select(ms->ms_nfds, ms->ms_rfd, ms->ms_wfd, ms->ms_efd, ms->ms_fd_size, ms->ms_timeout, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setsockopt(void* pms)
{
	ms_ocall_sgx_setsockopt_t* ms = SGX_CAST(ms_ocall_sgx_setsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_setsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, (const char*)ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_socketpair(void* pms)
{
	ms_ocall_sgx_socketpair_t* ms = SGX_CAST(ms_ocall_sgx_socketpair_t*, pms);
	ms->ms_retval = ocall_sgx_socketpair(ms->ms_domain, ms->ms_type, ms->ms_protocol, ms->ms_sv);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_accept(void* pms)
{
	ms_ocall_sgx_accept_t* ms = SGX_CAST(ms_ocall_sgx_accept_t*, pms);
	ms->ms_retval = ocall_sgx_accept(ms->ms_s, ms->ms_addr, ms->ms_addr_size, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_bind(void* pms)
{
	ms_ocall_sgx_bind_t* ms = SGX_CAST(ms_ocall_sgx_bind_t*, pms);
	ms->ms_retval = ocall_sgx_bind(ms->ms_s, (const struct sockaddr*)ms->ms_addr, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fstat(void* pms)
{
	ms_ocall_sgx_fstat_t* ms = SGX_CAST(ms_ocall_sgx_fstat_t*, pms);
	ms->ms_retval = ocall_sgx_fstat(ms->ms_fd, ms->ms_buf, ms->ms_buflen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_socket(void* pms)
{
	ms_ocall_sgx_socket_t* ms = SGX_CAST(ms_ocall_sgx_socket_t*, pms);
	ms->ms_retval = ocall_sgx_socket(ms->ms_af, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_listen(void* pms)
{
	ms_ocall_sgx_listen_t* ms = SGX_CAST(ms_ocall_sgx_listen_t*, pms);
	ms->ms_retval = ocall_sgx_listen(ms->ms_s, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_connect(void* pms)
{
	ms_ocall_sgx_connect_t* ms = SGX_CAST(ms_ocall_sgx_connect_t*, pms);
	ms->ms_retval = ocall_sgx_connect(ms->ms_s, (const struct sockaddr*)ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gethostbyname(void* pms)
{
	ms_ocall_sgx_gethostbyname_t* ms = SGX_CAST(ms_ocall_sgx_gethostbyname_t*, pms);
	ms->ms_retval = ocall_sgx_gethostbyname((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_open(void* pms)
{
	ms_ocall_sgx_open_t* ms = SGX_CAST(ms_ocall_sgx_open_t*, pms);
	ms->ms_retval = ocall_sgx_open((const char*)ms->ms_pathname, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_ftime(void* pms)
{
	ms_ocall_sgx_ftime_t* ms = SGX_CAST(ms_ocall_sgx_ftime_t*, pms);
	ocall_sgx_ftime(ms->ms_tb, ms->ms_size_timeb);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getenv(void* pms)
{
	ms_ocall_sgx_getenv_t* ms = SGX_CAST(ms_ocall_sgx_getenv_t*, pms);
	ms->ms_retval = ocall_sgx_getenv((const char*)ms->ms_env, ms->ms_envlen, ms->ms_ret_str, ms->ms_ret_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getaddrinfo(void* pms)
{
	ms_ocall_sgx_getaddrinfo_t* ms = SGX_CAST(ms_ocall_sgx_getaddrinfo_t*, pms);
	ms->ms_retval = ocall_sgx_getaddrinfo((const char*)ms->ms_node, (const char*)ms->ms_service, (const void*)ms->ms_hints, ms->ms_hints_len, ms->ms_res, ms->ms_res_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_freeaddrinfo(void* pms)
{
	ms_ocall_sgx_freeaddrinfo_t* ms = SGX_CAST(ms_ocall_sgx_freeaddrinfo_t*, pms);
	ocall_sgx_freeaddrinfo(ms->ms_res, ms->ms_res_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getsockname(void* pms)
{
	ms_ocall_sgx_getsockname_t* ms = SGX_CAST(ms_ocall_sgx_getsockname_t*, pms);
	ms->ms_retval = ocall_sgx_getsockname(ms->ms_s, ms->ms_name, ms->ms_nlen, ms->ms_namelen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getsockopt(void* pms)
{
	ms_ocall_sgx_getsockopt_t* ms = SGX_CAST(ms_ocall_sgx_getsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_getsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optval_len, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getservbyname(void* pms)
{
	ms_ocall_sgx_getservbyname_t* ms = SGX_CAST(ms_ocall_sgx_getservbyname_t*, pms);
	ocall_sgx_getservbyname((const char*)ms->ms_name, ms->ms_name_len, (const char*)ms->ms_proto, ms->ms_proto_len, ms->ms_serv_ptr, ms->ms_serv_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getprotobynumber(void* pms)
{
	ms_ocall_sgx_getprotobynumber_t* ms = SGX_CAST(ms_ocall_sgx_getprotobynumber_t*, pms);
	ocall_sgx_getprotobynumber(ms->ms_number, ms->ms_proto, ms->ms_proto_len, ms->ms_proto_name, ms->ms_proto_name_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_pthread_create(void* pms)
{
	ms_ocall_sgx_pthread_create_t* ms = SGX_CAST(ms_ocall_sgx_pthread_create_t*, pms);
	ms->ms_retval = ocall_sgx_pthread_create(ms->ms_port, ms->ms_port_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_epoll_wait(void* pms)
{
	ms_ocall_sgx_epoll_wait_t* ms = SGX_CAST(ms_ocall_sgx_epoll_wait_t*, pms);
	ms->ms_retval = ocall_sgx_epoll_wait(ms->ms_epfd, ms->ms_events, ms->ms_events_len, ms->ms_maxevents, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_epoll_ctl(void* pms)
{
	ms_ocall_sgx_epoll_ctl_t* ms = SGX_CAST(ms_ocall_sgx_epoll_ctl_t*, pms);
	ms->ms_retval = ocall_sgx_epoll_ctl(ms->ms_epfd, ms->ms_op, ms->ms_fd, ms->ms_event, ms->ms_event_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_epoll_create(void* pms)
{
	ms_ocall_sgx_epoll_create_t* ms = SGX_CAST(ms_ocall_sgx_epoll_create_t*, pms);
	ms->ms_retval = ocall_sgx_epoll_create(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_signal(void* pms)
{
	ms_ocall_sgx_signal_t* ms = SGX_CAST(ms_ocall_sgx_signal_t*, pms);
	ocall_sgx_signal(ms->ms_signum, ms->ms_f_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_eventfd(void* pms)
{
	ms_ocall_sgx_eventfd_t* ms = SGX_CAST(ms_ocall_sgx_eventfd_t*, pms);
	ms->ms_retval = ocall_sgx_eventfd(ms->ms_initval, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sigfillset(void* pms)
{
	ms_ocall_sgx_sigfillset_t* ms = SGX_CAST(ms_ocall_sgx_sigfillset_t*, pms);
	ms->ms_retval = ocall_sgx_sigfillset(ms->ms_set, ms->ms_setlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sigemptyset(void* pms)
{
	ms_ocall_sgx_sigemptyset_t* ms = SGX_CAST(ms_ocall_sgx_sigemptyset_t*, pms);
	ms->ms_retval = ocall_sgx_sigemptyset(ms->ms_set, ms->ms_setlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sigaction(void* pms)
{
	ms_ocall_sgx_sigaction_t* ms = SGX_CAST(ms_ocall_sgx_sigaction_t*, pms);
	ms->ms_retval = ocall_sgx_sigaction(ms->ms_signum, (const void*)ms->ms_act, ms->ms_act_len, ms->ms_oldact, ms->ms_oldact_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fcntl(void* pms)
{
	ms_ocall_sgx_fcntl_t* ms = SGX_CAST(ms_ocall_sgx_fcntl_t*, pms);
	ms->ms_retval = ocall_sgx_fcntl(ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fcntl2(void* pms)
{
	ms_ocall_sgx_fcntl2_t* ms = SGX_CAST(ms_ocall_sgx_fcntl2_t*, pms);
	ms->ms_retval = ocall_sgx_fcntl2(ms->ms_fd, ms->ms_cmd, ms->ms_lock, ms->ms_lock_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_chmod(void* pms)
{
	ms_ocall_sgx_chmod_t* ms = SGX_CAST(ms_ocall_sgx_chmod_t*, pms);
	ms->ms_retval = ocall_sgx_chmod((const char*)ms->ms_pathname, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_chdir(void* pms)
{
	ms_ocall_sgx_chdir_t* ms = SGX_CAST(ms_ocall_sgx_chdir_t*, pms);
	ms->ms_retval = ocall_sgx_chdir((const char*)ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_pipe(void* pms)
{
	ms_ocall_sgx_pipe_t* ms = SGX_CAST(ms_ocall_sgx_pipe_t*, pms);
	ms->ms_retval = ocall_sgx_pipe(ms->ms_pipefd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sysctl(void* pms)
{
	ms_ocall_sgx_sysctl_t* ms = SGX_CAST(ms_ocall_sgx_sysctl_t*, pms);
	ms->ms_retval = ocall_sgx_sysctl(ms->ms_name, ms->ms_nlen, ms->ms_oldval, ms->ms_oldval_len, ms->ms_oldlenp, ms->ms_newval, ms->ms_newlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fork(void* pms)
{
	ms_ocall_sgx_fork_t* ms = SGX_CAST(ms_ocall_sgx_fork_t*, pms);
	ms->ms_retval = ocall_sgx_fork();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_ntohs(void* pms)
{
	ms_ocall_sgx_ntohs_t* ms = SGX_CAST(ms_ocall_sgx_ntohs_t*, pms);
	ms->ms_retval = ocall_sgx_ntohs(ms->ms_netshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_ntohl(void* pms)
{
	ms_ocall_sgx_ntohl_t* ms = SGX_CAST(ms_ocall_sgx_ntohl_t*, pms);
	ms->ms_retval = ocall_sgx_ntohl(ms->ms_netlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ms->ms_retval = ocall_get_time(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_recv(void* pms)
{
	ms_ocall_sgx_recv_t* ms = SGX_CAST(ms_ocall_sgx_recv_t*, pms);
	ms->ms_retval = ocall_sgx_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_direct_recv(void* pms)
{
	ms_ocall_sgx_direct_recv_t* ms = SGX_CAST(ms_ocall_sgx_direct_recv_t*, pms);
	ms->ms_retval = ocall_sgx_direct_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_send(void* pms)
{
	ms_ocall_sgx_send_t* ms = SGX_CAST(ms_ocall_sgx_send_t*, pms);
	ms->ms_retval = ocall_sgx_send(ms->ms_s, (const char*)ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_direct_send(void* pms)
{
	ms_ocall_sgx_direct_send_t* ms = SGX_CAST(ms_ocall_sgx_direct_send_t*, pms);
	ms->ms_retval = ocall_sgx_direct_send(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_rename(void* pms)
{
	ms_ocall_sgx_rename_t* ms = SGX_CAST(ms_ocall_sgx_rename_t*, pms);
	ms->ms_retval = ocall_sgx_rename((const char*)ms->ms_from_str, (const char*)ms->ms_to_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_unlink(void* pms)
{
	ms_ocall_sgx_unlink_t* ms = SGX_CAST(ms_ocall_sgx_unlink_t*, pms);
	ms->ms_retval = ocall_sgx_unlink((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_close(void* pms)
{
	ms_ocall_sgx_close_t* ms = SGX_CAST(ms_ocall_sgx_close_t*, pms);
	ms->ms_retval = ocall_sgx_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_ftruncate(void* pms)
{
	ms_ocall_sgx_ftruncate_t* ms = SGX_CAST(ms_ocall_sgx_ftruncate_t*, pms);
	ms->ms_retval = ocall_sgx_ftruncate(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_shutdown(void* pms)
{
	ms_ocall_sgx_shutdown_t* ms = SGX_CAST(ms_ocall_sgx_shutdown_t*, pms);
	ms->ms_retval = ocall_sgx_shutdown(ms->ms_fd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_exit(void* pms)
{
	ms_ocall_sgx_exit_t* ms = SGX_CAST(ms_ocall_sgx_exit_t*, pms);
	ocall_sgx_exit(ms->ms_exit_status);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_write(void* pms)
{
	ms_ocall_sgx_write_t* ms = SGX_CAST(ms_ocall_sgx_write_t*, pms);
	ms->ms_retval = ocall_sgx_write(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_direct_write(void* pms)
{
	ms_ocall_sgx_direct_write_t* ms = SGX_CAST(ms_ocall_sgx_direct_write_t*, pms);
	ms->ms_retval = ocall_sgx_direct_write(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_read(void* pms)
{
	ms_ocall_sgx_read_t* ms = SGX_CAST(ms_ocall_sgx_read_t*, pms);
	ms->ms_retval = ocall_sgx_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_direct_read(void* pms)
{
	ms_ocall_sgx_direct_read_t* ms = SGX_CAST(ms_ocall_sgx_direct_read_t*, pms);
	ms->ms_retval = ocall_sgx_direct_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_waitpid(void* pms)
{
	ms_ocall_sgx_waitpid_t* ms = SGX_CAST(ms_ocall_sgx_waitpid_t*, pms);
	ms->ms_retval = ocall_sgx_waitpid(ms->ms_pid, ms->ms__status, ms->ms_status_len, ms->ms_options);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getpid(void* pms)
{
	ms_ocall_sgx_getpid_t* ms = SGX_CAST(ms_ocall_sgx_getpid_t*, pms);
	ms->ms_retval = ocall_sgx_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setsid(void* pms)
{
	ms_ocall_sgx_setsid_t* ms = SGX_CAST(ms_ocall_sgx_setsid_t*, pms);
	ms->ms_retval = ocall_sgx_setsid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getgroups(void* pms)
{
	ms_ocall_sgx_getgroups_t* ms = SGX_CAST(ms_ocall_sgx_getgroups_t*, pms);
	ms->ms_retval = ocall_sgx_getgroups(ms->ms_size, ms->ms_list, ms->ms_list_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setgroups(void* pms)
{
	ms_ocall_sgx_setgroups_t* ms = SGX_CAST(ms_ocall_sgx_setgroups_t*, pms);
	ms->ms_retval = ocall_sgx_setgroups(ms->ms_size, (const unsigned int*)ms->ms_list, ms->ms_list_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setuid(void* pms)
{
	ms_ocall_sgx_setuid_t* ms = SGX_CAST(ms_ocall_sgx_setuid_t*, pms);
	ms->ms_retval = ocall_sgx_setuid(ms->ms_uid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setgid(void* pms)
{
	ms_ocall_sgx_setgid_t* ms = SGX_CAST(ms_ocall_sgx_setgid_t*, pms);
	ms->ms_retval = ocall_sgx_setgid(ms->ms_gid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_seteuid(void* pms)
{
	ms_ocall_sgx_seteuid_t* ms = SGX_CAST(ms_ocall_sgx_seteuid_t*, pms);
	ms->ms_retval = ocall_sgx_seteuid(ms->ms_uid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setegid(void* pms)
{
	ms_ocall_sgx_setegid_t* ms = SGX_CAST(ms_ocall_sgx_setegid_t*, pms);
	ms->ms_retval = ocall_sgx_setegid(ms->ms_gid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_dup2(void* pms)
{
	ms_ocall_sgx_dup2_t* ms = SGX_CAST(ms_ocall_sgx_dup2_t*, pms);
	ms->ms_retval = ocall_sgx_dup2(ms->ms_oldfd, ms->ms_newfd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getuid(void* pms)
{
	ms_ocall_sgx_getuid_t* ms = SGX_CAST(ms_ocall_sgx_getuid_t*, pms);
	ms->ms_retval = ocall_sgx_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getgid(void* pms)
{
	ms_ocall_sgx_getgid_t* ms = SGX_CAST(ms_ocall_sgx_getgid_t*, pms);
	ms->ms_retval = ocall_sgx_getgid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_geteuid(void* pms)
{
	ms_ocall_sgx_geteuid_t* ms = SGX_CAST(ms_ocall_sgx_geteuid_t*, pms);
	ms->ms_retval = ocall_sgx_geteuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getegid(void* pms)
{
	ms_ocall_sgx_getegid_t* ms = SGX_CAST(ms_ocall_sgx_getegid_t*, pms);
	ms->ms_retval = ocall_sgx_getegid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_lseek(void* pms)
{
	ms_ocall_sgx_lseek_t* ms = SGX_CAST(ms_ocall_sgx_lseek_t*, pms);
	ms->ms_retval = ocall_sgx_lseek(ms->ms_fildes, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gethostname(void* pms)
{
	ms_ocall_sgx_gethostname_t* ms = SGX_CAST(ms_ocall_sgx_gethostname_t*, pms);
	ms->ms_retval = ocall_sgx_gethostname(ms->ms_name, ms->ms_namelen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_localtime(void* pms)
{
	ms_ocall_sgx_localtime_t* ms = SGX_CAST(ms_ocall_sgx_localtime_t*, pms);
	ms->ms_retval = ocall_sgx_localtime((const time_t*)ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gmtime(void* pms)
{
	ms_ocall_sgx_gmtime_t* ms = SGX_CAST(ms_ocall_sgx_gmtime_t*, pms);
	ms->ms_retval = ocall_sgx_gmtime((const time_t*)ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_mktime(void* pms)
{
	ms_ocall_sgx_mktime_t* ms = SGX_CAST(ms_ocall_sgx_mktime_t*, pms);
	ms->ms_retval = ocall_sgx_mktime(ms->ms_timeptr, ms->ms_tm_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_sendto(void* pms)
{
	ms_ocall_sgx_sendto_t* ms = SGX_CAST(ms_ocall_sgx_sendto_t*, pms);
	ms->ms_retval = ocall_sgx_sendto(ms->ms_s, (const void*)ms->ms_msg, ms->ms_len, ms->ms_flags, (const struct sockaddr*)ms->ms_to, ms->ms_tolen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_recvfrom(void* pms)
{
	ms_ocall_sgx_recvfrom_t* ms = SGX_CAST(ms_ocall_sgx_recvfrom_t*, pms);
	ms->ms_retval = ocall_sgx_recvfrom(ms->ms_s, ms->ms_msg, ms->ms_len, ms->ms_flags, ms->ms_fr, ms->ms_frlen, ms->ms_in_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_fclose(void* pms)
{
	ms_ocall_sgx_fclose_t* ms = SGX_CAST(ms_ocall_sgx_fclose_t*, pms);
	ms->ms_retval = ocall_sgx_fclose(ms->ms_file, ms->ms_file_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_stat(void* pms)
{
	ms_ocall_sgx_stat_t* ms = SGX_CAST(ms_ocall_sgx_stat_t*, pms);
	ms->ms_retval = ocall_sgx_stat((const char*)ms->ms_filename, ms->ms_st, ms->ms_stat_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_mkdir(void* pms)
{
	ms_ocall_sgx_mkdir_t* ms = SGX_CAST(ms_ocall_sgx_mkdir_t*, pms);
	ms->ms_retval = ocall_sgx_mkdir((const char*)ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_clock(void* pms)
{
	ms_ocall_sgx_clock_t* ms = SGX_CAST(ms_ocall_sgx_clock_t*, pms);
	ms->ms_retval = ocall_sgx_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[106];
} ocall_table_Enclave = {
	106,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_pointer_user_check,
		(void*)Enclave_ocall_pointer_in,
		(void*)Enclave_ocall_pointer_out,
		(void*)Enclave_ocall_pointer_in_out,
		(void*)Enclave_memccpy,
		(void*)Enclave_ocall_function_allow,
		(void*)Enclave_ocall_sgx_process_msg_all,
		(void*)Enclave_ocall_sgx_ra_free_network_response_buffer,
		(void*)Enclave_ocall_sgx_malloc,
		(void*)Enclave_ocall_sgx_calloc,
		(void*)Enclave_ocall_sgx_realloc,
		(void*)Enclave_ocall_sgx_free,
		(void*)Enclave_ocall_sgx_fileno_stdout,
		(void*)Enclave_ocall_sgx_pthread_getspecific,
		(void*)Enclave_ocall_sgx_pthread_setspecific,
		(void*)Enclave_ocall_sgx_sleep,
		(void*)Enclave_ocall_sgx_poll,
		(void*)Enclave_ocall_sgx_gettimeofday,
		(void*)Enclave_ocall_sgx_clock_gettime,
		(void*)Enclave_ocall_sgx_select,
		(void*)Enclave_ocall_sgx_setsockopt,
		(void*)Enclave_ocall_sgx_socketpair,
		(void*)Enclave_ocall_sgx_accept,
		(void*)Enclave_ocall_sgx_bind,
		(void*)Enclave_ocall_sgx_fstat,
		(void*)Enclave_ocall_sgx_socket,
		(void*)Enclave_ocall_sgx_listen,
		(void*)Enclave_ocall_sgx_connect,
		(void*)Enclave_ocall_sgx_gethostbyname,
		(void*)Enclave_ocall_sgx_open,
		(void*)Enclave_ocall_sgx_ftime,
		(void*)Enclave_ocall_sgx_getenv,
		(void*)Enclave_ocall_sgx_getaddrinfo,
		(void*)Enclave_ocall_sgx_freeaddrinfo,
		(void*)Enclave_ocall_sgx_getsockname,
		(void*)Enclave_ocall_sgx_getsockopt,
		(void*)Enclave_ocall_sgx_getservbyname,
		(void*)Enclave_ocall_sgx_getprotobynumber,
		(void*)Enclave_ocall_sgx_pthread_create,
		(void*)Enclave_ocall_sgx_epoll_wait,
		(void*)Enclave_ocall_sgx_epoll_ctl,
		(void*)Enclave_ocall_sgx_epoll_create,
		(void*)Enclave_ocall_sgx_signal,
		(void*)Enclave_ocall_sgx_eventfd,
		(void*)Enclave_ocall_sgx_sigfillset,
		(void*)Enclave_ocall_sgx_sigemptyset,
		(void*)Enclave_ocall_sgx_sigaction,
		(void*)Enclave_ocall_sgx_fcntl,
		(void*)Enclave_ocall_sgx_fcntl2,
		(void*)Enclave_ocall_sgx_chmod,
		(void*)Enclave_ocall_sgx_chdir,
		(void*)Enclave_ocall_sgx_pipe,
		(void*)Enclave_ocall_sgx_sysctl,
		(void*)Enclave_ocall_sgx_fork,
		(void*)Enclave_ocall_sgx_ntohs,
		(void*)Enclave_ocall_sgx_ntohl,
		(void*)Enclave_ocall_get_time,
		(void*)Enclave_ocall_sgx_recv,
		(void*)Enclave_ocall_sgx_direct_recv,
		(void*)Enclave_ocall_sgx_send,
		(void*)Enclave_ocall_sgx_direct_send,
		(void*)Enclave_ocall_sgx_rename,
		(void*)Enclave_ocall_sgx_unlink,
		(void*)Enclave_ocall_sgx_close,
		(void*)Enclave_ocall_sgx_ftruncate,
		(void*)Enclave_ocall_sgx_shutdown,
		(void*)Enclave_ocall_sgx_exit,
		(void*)Enclave_ocall_sgx_write,
		(void*)Enclave_ocall_sgx_direct_write,
		(void*)Enclave_ocall_sgx_read,
		(void*)Enclave_ocall_sgx_direct_read,
		(void*)Enclave_ocall_sgx_waitpid,
		(void*)Enclave_ocall_sgx_getpid,
		(void*)Enclave_ocall_sgx_setsid,
		(void*)Enclave_ocall_sgx_getgroups,
		(void*)Enclave_ocall_sgx_setgroups,
		(void*)Enclave_ocall_sgx_setuid,
		(void*)Enclave_ocall_sgx_setgid,
		(void*)Enclave_ocall_sgx_seteuid,
		(void*)Enclave_ocall_sgx_setegid,
		(void*)Enclave_ocall_sgx_dup2,
		(void*)Enclave_ocall_sgx_getuid,
		(void*)Enclave_ocall_sgx_getgid,
		(void*)Enclave_ocall_sgx_geteuid,
		(void*)Enclave_ocall_sgx_getegid,
		(void*)Enclave_ocall_sgx_lseek,
		(void*)Enclave_ocall_sgx_gethostname,
		(void*)Enclave_ocall_sgx_localtime,
		(void*)Enclave_ocall_sgx_gmtime,
		(void*)Enclave_ocall_sgx_mktime,
		(void*)Enclave_ocall_sgx_sendto,
		(void*)Enclave_ocall_sgx_recvfrom,
		(void*)Enclave_ocall_sgx_fclose,
		(void*)Enclave_ocall_sgx_stat,
		(void*)Enclave_ocall_sgx_mkdir,
		(void*)Enclave_ocall_sgx_clock,
		(void*)Enclave_create_session_ocall,
		(void*)Enclave_exchange_report_ocall,
		(void*)Enclave_close_session_ocall,
		(void*)Enclave_invoke_service_ocall,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_type_char(sgx_enclave_id_t eid, char val)
{
	sgx_status_t status;
	ms_ecall_type_char_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_int(sgx_enclave_id_t eid, int val)
{
	sgx_status_t status;
	ms_ecall_type_int_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_float(sgx_enclave_id_t eid, float val)
{
	sgx_status_t status;
	ms_ecall_type_float_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_double(sgx_enclave_id_t eid, double val)
{
	sgx_status_t status;
	ms_ecall_type_double_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_size_t(sgx_enclave_id_t eid, size_t val)
{
	sgx_status_t status;
	ms_ecall_type_size_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_wchar_t(sgx_enclave_id_t eid, wchar_t val)
{
	sgx_status_t status;
	ms_ecall_type_wchar_t_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_struct(sgx_enclave_id_t eid, struct struct_foo_t val)
{
	sgx_status_t status;
	ms_ecall_type_struct_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_type_enum_union(sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t* val2)
{
	sgx_status_t status;
	ms_ecall_type_enum_union_t ms;
	ms.ms_val1 = val1;
	ms.ms_val2 = val2;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_user_check(sgx_enclave_id_t eid, size_t* retval, void* val, size_t sz)
{
	sgx_status_t status;
	ms_ecall_pointer_user_check_t ms;
	ms.ms_val = val;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_pointer_in(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_in_out(sgx_enclave_id_t eid, int* val)
{
	sgx_status_t status;
	ms_ecall_pointer_in_out_t ms;
	ms.ms_val = val;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_string_const(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_pointer_string_const_t ms;
	ms.ms_str = (char*)str;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_size(sgx_enclave_id_t eid, void* ptr, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_size_t ms;
	ms.ms_ptr = ptr;
	ms.ms_len = len;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_count(sgx_enclave_id_t eid, int* arr, int cnt)
{
	sgx_status_t status;
	ms_ecall_pointer_count_t ms;
	ms.ms_arr = arr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_isptr_readonly(sgx_enclave_id_t eid, buffer_t buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_pointer_isptr_readonly_t ms;
	ms.ms_buf = (buffer_t)buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_pointer_sizefunc(sgx_enclave_id_t eid, char* buf)
{
	sgx_status_t status;
	ms_ecall_pointer_sizefunc_t ms;
	ms.ms_buf = buf;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ocall_pointer_attr(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_array_user_check(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_user_check_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_in_out(sgx_enclave_id_t eid, int arr[4])
{
	sgx_status_t status;
	ms_ecall_array_in_out_t ms;
	ms.ms_arr = (int*)arr;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_array_isary(sgx_enclave_id_t eid, array_t arr)
{
	sgx_status_t status;
	ms_ecall_array_isary_t ms;
	ms.ms_arr = (array_t *)&arr[0];
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_public(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_function_private(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_function_private_t ms;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t StartTorSGX(sgx_enclave_id_t eid, int argc, char** argv, int argv_len, unsigned long long app_errno, unsigned long long app_environ, const char* app_torrc)
{
	sgx_status_t status;
	ms_StartTorSGX_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	ms.ms_argv_len = argv_len;
	ms.ms_app_errno = app_errno;
	ms.ms_app_environ = app_environ;
	ms.ms_app_torrc = (char*)app_torrc;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_start_gencert(sgx_enclave_id_t eid, char* tor_cert, unsigned long long app_errno, const char* month, const char* address)
{
	sgx_status_t status;
	ms_sgx_start_gencert_t ms;
	ms.ms_tor_cert = tor_cert;
	ms.ms_app_errno = app_errno;
	ms.ms_month = (char*)month;
	ms.ms_address = (char*)address;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_start_fingerprint(sgx_enclave_id_t eid, char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno)
{
	sgx_status_t status;
	ms_sgx_start_fingerprint_t ms;
	ms.ms_fingerprint = fingerprint;
	ms.ms_data_dir = data_dir;
	ms.ms_app_torrc = (char*)app_torrc;
	ms.ms_app_errno = app_errno;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_seal_files(sgx_enclave_id_t eid, char* fname, void* fcont)
{
	sgx_status_t status;
	ms_sgx_seal_files_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_unseal_files(sgx_enclave_id_t eid, char* fname, void* fcont)
{
	sgx_status_t status;
	ms_sgx_unseal_files_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclave_func_caller(sgx_enclave_id_t eid, void* args, int args_len)
{
	sgx_status_t status;
	ms_enclave_func_caller_t ms;
	ms.ms_args = args;
	ms.ms_args_len = args_len;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_signal_handle_caller(sgx_enclave_id_t eid, int signum, int f_id)
{
	sgx_status_t status;
	ms_sgx_signal_handle_caller_t ms;
	ms.ms_signum = signum;
	ms.ms_f_id = f_id;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 34, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 35, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 36, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_start_remote_attestation_server(sgx_enclave_id_t eid, int remote_server_port, void* sgx_cert_cont, int sgx_cert_size, void* sgx_pkey_cont, int sgx_pkey_size, unsigned long int given_my_ip)
{
	sgx_status_t status;
	ms_sgx_start_remote_attestation_server_t ms;
	ms.ms_remote_server_port = remote_server_port;
	ms.ms_sgx_cert_cont = sgx_cert_cont;
	ms.ms_sgx_cert_size = sgx_cert_size;
	ms.ms_sgx_pkey_cont = sgx_pkey_cont;
	ms.ms_sgx_pkey_size = sgx_pkey_size;
	ms.ms_given_my_ip = given_my_ip;
	status = sgx_ecall(eid, 37, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t test_sgx_put_gencert(sgx_enclave_id_t eid, char* fname, char* fcont, int fcont_len)
{
	sgx_status_t status;
	ms_test_sgx_put_gencert_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	ms.ms_fcont_len = fcont_len;
	status = sgx_ecall(eid, 38, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 39, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 40, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 41, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

