#include "TorSGX_u.h"
#include <errno.h>

typedef struct ms_sgx_start_tor_t {
	int ms_argc;
	char** ms_argv;
	int ms_argv_len;
	void* ms_version;
	int ms_version_size;
	unsigned long long ms_app_errno;
	unsigned long long ms_app_environ;
	char* ms_app_conf_root;
	char* ms_app_torrc;
	char* ms_app_system_dir;
	MEMORYSTATUSEX* ms_app_mse;
	SYSTEM_INFO* ms_app_info;
} ms_sgx_start_tor_t;

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
	MEMORYSTATUSEX* ms_app_mse;
} ms_sgx_start_fingerprint_t;

typedef struct ms_sgx_start_remote_attestation_server_t {
	int ms_remote_server_port;
	void* ms_sgx_cert_cont;
	int ms_sgx_cert_size;
	void* ms_sgx_pkey_cont;
	int ms_sgx_pkey_size;
	unsigned long int ms_given_my_ip;
} ms_sgx_start_remote_attestation_server_t;

typedef struct ms_sgx_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_sgx_init_ra_t;

typedef struct ms_sgx_close_ra_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_sgx_close_ra_t;

typedef struct ms_sgx_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_sgx_verify_att_result_mac_t;

typedef struct ms_enclave_func_caller_t {
	void* ms_args;
	int ms_args_len;
} ms_enclave_func_caller_t;

typedef struct ms_test_sgx_put_gencert_t {
	char* ms_fname;
	char* ms_fcont;
	int ms_fcont_len;
} ms_test_sgx_put_gencert_t;

typedef struct ms_sgx_seal_files_t {
	char* ms_fname;
	void* ms_fcont;
} ms_sgx_seal_files_t;

typedef struct ms_sgx_unseal_files_t {
	char* ms_fname;
	void* ms_fcont;
} ms_sgx_unseal_files_t;

typedef struct ms_sgx_signal_handle_caller_t {
	int ms_signum;
	int ms_f_id;
} ms_sgx_signal_handle_caller_t;

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
	void* ms_retval;
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

typedef struct ms_ocall_sgx_GetSystemTimeAsFileTime_t {
	FILETIME* ms_ft;
	int ms_ft_size;
} ms_ocall_sgx_GetSystemTimeAsFileTime_t;

typedef struct ms_ocall_sgx_GetAdaptersAddresses_t {
	unsigned long int ms_retval;
	unsigned long int ms_family;
	unsigned long int ms_flags;
	void* ms_addresses;
	unsigned long int ms_addresses_size;
	unsigned long int* ms_psize;
} ms_ocall_sgx_GetAdaptersAddresses_t;

typedef struct ms_ocall_sgx_TlsAlloc_t {
	unsigned long int ms_retval;
} ms_ocall_sgx_TlsAlloc_t;

typedef struct ms_ocall_sgx_TlsGetValue_t {
	void* ms_retval;
	unsigned long int ms_index;
} ms_ocall_sgx_TlsGetValue_t;

typedef struct ms_ocall_sgx_TlsSetValue_t {
	int ms_retval;
	unsigned long int ms_index;
	void* ms_val;
} ms_ocall_sgx_TlsSetValue_t;

typedef struct ms_ocall_sgx_Sleep_t {
	unsigned long int ms_milli;
} ms_ocall_sgx_Sleep_t;

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

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optlen;
} ms_ocall_sgx_setsockopt_t;

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

typedef struct ms_ocall_sgx_ioctlsocket_t {
	int ms_retval;
	int ms_s;
	long int ms_cmd;
	unsigned long int* ms_argp;
	int ms_argp_len;
} ms_ocall_sgx_ioctlsocket_t;

typedef struct ms_ocall_sgx_EnterCriticalSection_t {
	void* ms_lock;
	int ms_lock_len;
} ms_ocall_sgx_EnterCriticalSection_t;

typedef struct ms_ocall_sgx_LeaveCriticalSection_t {
	void* ms_lock;
	int ms_lock_len;
} ms_ocall_sgx_LeaveCriticalSection_t;

typedef struct ms_ocall_sgx_DeleteCriticalSection_t {
	void* ms_lock;
	int ms_lock_len;
} ms_ocall_sgx_DeleteCriticalSection_t;

typedef struct ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t {
	void* ms_lock;
	int ms_lock_len;
	int ms_count;
} ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t;

typedef struct ms_ocall_sgx_gethostbyname_t {
	struct hostent* ms_retval;
	char* ms_name;
} ms_ocall_sgx_gethostbyname_t;

typedef struct ms_ocall_sgx_WaitForSingleObject_t {
	int ms_handle;
	unsigned long int ms_ms_;
} ms_ocall_sgx_WaitForSingleObject_t;

typedef struct ms_ocall_sgx_CryptGenRandom_t {
	int ms_retval;
	unsigned long long ms_prov;
	int ms_buf_len;
	unsigned char* ms_buf;
} ms_ocall_sgx_CryptGenRandom_t;

typedef struct ms_ocall_sgx_CryptReleaseContext_t {
	int ms_retval;
	unsigned long long ms_hProv;
	unsigned long int ms_dwFlags;
} ms_ocall_sgx_CryptReleaseContext_t;

typedef struct ms_ocall_sgx_CloseHandle_t {
	int ms_retval;
	int ms_hObject;
} ms_ocall_sgx_CloseHandle_t;

typedef struct ms_ocall_sgx_GetLastError_t {
	int ms_retval;
} ms_ocall_sgx_GetLastError_t;

typedef struct ms_ocall_sgx_CreateIoCompletionPort_t {
	int ms_retval;
	int ms_FileHandle;
	int ms_p;
	unsigned long int ms_k;
	unsigned long int ms_numthreads;
} ms_ocall_sgx_CreateIoCompletionPort_t;

typedef struct ms_ocall_sgx_GetQueuedCompletionStatus_t {
	int ms_retval;
	int ms_p;
	unsigned long int* ms_numbytes;
	int ms_numbytes_len;
	__int64* ms_k;
	int ms_k_len;
	void* ms_lpOverlapped;
	int ms_lpOverlapped_len;
	unsigned long int ms_dwMilliseconds;
} ms_ocall_sgx_GetQueuedCompletionStatus_t;

typedef struct ms_ocall_sgx_GetSystemDirectory_t {
	unsigned int ms_retval;
	char* ms_lpBuffer;
	unsigned int ms_uSize;
} ms_ocall_sgx_GetSystemDirectory_t;

typedef struct ms_ocall_sgx_LoadLibrary_t {
	unsigned long long ms_retval;
	char* ms_lpFileName;
} ms_ocall_sgx_LoadLibrary_t;

typedef struct ms_ocall_sgx_open_t {
	int ms_retval;
	char* ms_pathname;
	int ms_flags;
	unsigned int ms_mode;
} ms_ocall_sgx_open_t;

typedef struct ms_ocall_sgx_ftime_t {
	struct _timeb* ms_tb;
	int ms_size_timeb;
} ms_ocall_sgx_ftime_t;

typedef struct ms_ocall_sgx_CreateSemaphore_t {
	int ms_retval;
	void* ms_attr;
	int ms_attr_len;
	long int ms_initcount;
	long int ms_maxcount;
	void* ms_name;
	int ms_name_len;
} ms_ocall_sgx_CreateSemaphore_t;

typedef struct ms_ocall_sgx_ReleaseSemaphore_t {
	int ms_retval;
	int ms_hSemaphore;
	long int ms_lReleaseCount;
	long int* ms_lpPreviousCount;
	int ms_lp_len;
} ms_ocall_sgx_ReleaseSemaphore_t;

typedef struct ms_ocall_sgx_CryptAcquireContext_t {
	int ms_retval;
	void* ms_prov;
	void* ms_container;
	void* ms_provider;
	unsigned long int ms_provtype;
	unsigned long int ms_dwflags;
} ms_ocall_sgx_CryptAcquireContext_t;

typedef struct ms_ocall_sgx_getenv_t {
	int ms_retval;
	char* ms_env;
	int ms_envlen;
	char* ms_ret_str;
	int ms_ret_len;
} ms_ocall_sgx_getenv_t;

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

typedef struct ms_ocall_sgx_beginthread_t {
	unsigned long long ms_retval;
	void* ms_port;
	int ms_port_len;
} ms_ocall_sgx_beginthread_t;


typedef struct ms_ocall_sgx_PostQueuedCompletionStatus_t {
	int ms_retval;
	int ms_p;
	unsigned int ms_n;
	unsigned int ms_key;
	void* ms_o;
	int ms_o_len;
} ms_ocall_sgx_PostQueuedCompletionStatus_t;

typedef struct ms_ocall_sgx_signal_t {
	int ms_signum;
	int ms_f_id;
} ms_ocall_sgx_signal_t;

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

typedef struct ms_ocall_sgx_ucheck_recv_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_ucheck_recv_t;

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

typedef struct ms_ocall_sgx_ucheck_send_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_ucheck_send_t;

typedef struct ms_ocall_sgx_direct_send_t {
	int ms_retval;
	int ms_s;
	unsigned long long ms_buf;
	int ms_len;
	int ms_flags;
} ms_ocall_sgx_direct_send_t;

typedef struct ms_ocall_sgx_WSAGetLastError_t {
	int ms_retval;
} ms_ocall_sgx_WSAGetLastError_t;

typedef struct ms_ocall_sgx_SetLastError_t {
	int ms_e;
} ms_ocall_sgx_SetLastError_t;

typedef struct ms_ocall_sgx_WSASetLastError_t {
	int ms_e;
} ms_ocall_sgx_WSASetLastError_t;

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

typedef struct ms_ocall_sgx_chsize_t {
	int ms_retval;
	int ms_fd;
	long int ms_val;
} ms_ocall_sgx_chsize_t;

typedef struct ms_ocall_sgx_closesocket_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_closesocket_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
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

typedef struct ms_ocall_sgx_getpid_t {
	pid_t ms_retval;
} ms_ocall_sgx_getpid_t;

typedef struct ms_ocall_sgx_lseek_t {
	off_t ms_retval;
	int ms_fildes;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_sgx_lseek_t;

typedef struct ms_ocall_sgx_locking_t {
	int ms_retval;
	int ms_fd;
	int ms_mode;
	long int ms_num;
} ms_ocall_sgx_locking_t;

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

typedef struct ms_ocall_sgx_GetNetworkParams_t {
	unsigned long int ms_retval;
	void* ms_fixed;
	unsigned long int ms_fixed_sz;
	unsigned long int* ms_fixed_size;
} ms_ocall_sgx_GetNetworkParams_t;

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

typedef struct ms_ocall_sgx_SHGetSpecialFolderPathA_t {
	int ms_retval;
	HWND ms_hwnd;
	char* ms_path;
	int ms_path_len;
	int ms_csidl;
	int ms_fCreate;
} ms_ocall_sgx_SHGetSpecialFolderPathA_t;

typedef struct ms_ocall_sgx_fputs_t {
	int ms_retval;
	char* ms_str;
	FILE* ms_stream;
	int ms_stream_size;
} ms_ocall_sgx_fputs_t;

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
} ms_ocall_sgx_mkdir_t;

typedef struct ms_ocall_sgx_UnmapViewOfFile_t {
	int ms_retval;
	unsigned long long ms_lpBaseAddress;
} ms_ocall_sgx_UnmapViewOfFile_t;

typedef struct ms_ocall_sgx_MapViewOfFile_t {
	void* ms_retval;
	int ms_hFileMappingObject;
	unsigned long int ms_dwDesiredAccess;
	unsigned long int ms_dwFileOffsetHigh;
	unsigned long int ms_dwFileOffsetLow;
	unsigned long long ms_dwNumberOfBytesToMap;
} ms_ocall_sgx_MapViewOfFile_t;

typedef struct ms_ocall_sgx_CreateFileMapping_t {
	int ms_retval;
	int ms_hFile;
	void* ms__null;
	unsigned long int ms_flProtect;
	unsigned long int ms_dwMaximumSizeHigh;
	unsigned long int ms_dwMaximumSizeLow;
	char* ms_lpName;
} ms_ocall_sgx_CreateFileMapping_t;

typedef struct ms_ocall_sgx_GetFileSize_t {
	unsigned long int ms_retval;
	int ms_hFile;
	unsigned long int* ms_lpFileSizeHigh;
} ms_ocall_sgx_GetFileSize_t;

typedef struct ms_ocall_sgx_CreateFile_t {
	HANDLE ms_retval;
	char* ms_lpFileName;
	unsigned long int ms_dwDesiredAccess;
	unsigned long int ms_dwShareMode;
	void* ms__null;
	unsigned long int ms_dwCreationDisposition;
	unsigned long int ms_dwFlagsAndAttributes;
	int ms_hTemplateFile;
} ms_ocall_sgx_CreateFile_t;

typedef struct ms_ocall_sgx_clock_t {
	long long ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_ocall_sgx_fdopen_t {
	unsigned long long ms_retval;
	int ms_fd;
	char* ms_format;
} ms_ocall_sgx_fdopen_t;

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

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_process_msg_all(void* pms)
{
	ms_ocall_sgx_process_msg_all_t* ms = SGX_CAST(ms_ocall_sgx_process_msg_all_t*, pms);
	ms->ms_retval = ocall_sgx_process_msg_all((const void*)ms->ms_p_req, ms->ms_p_req_size, ms->ms_p_resp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ra_free_network_response_buffer(void* pms)
{
	ms_ocall_sgx_ra_free_network_response_buffer_t* ms = SGX_CAST(ms_ocall_sgx_ra_free_network_response_buffer_t*, pms);
	ocall_sgx_ra_free_network_response_buffer(ms->ms_resp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_malloc(void* pms)
{
	ms_ocall_sgx_malloc_t* ms = SGX_CAST(ms_ocall_sgx_malloc_t*, pms);
	ms->ms_retval = ocall_sgx_malloc(ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_calloc(void* pms)
{
	ms_ocall_sgx_calloc_t* ms = SGX_CAST(ms_ocall_sgx_calloc_t*, pms);
	ms->ms_retval = ocall_sgx_calloc(ms->ms_m_cnt, ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_realloc(void* pms)
{
	ms_ocall_sgx_realloc_t* ms = SGX_CAST(ms_ocall_sgx_realloc_t*, pms);
	ms->ms_retval = ocall_sgx_realloc(ms->ms_old_mem, ms->ms_m_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_free(void* pms)
{
	ms_ocall_sgx_free_t* ms = SGX_CAST(ms_ocall_sgx_free_t*, pms);
	ocall_sgx_free(ms->ms_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetSystemTimeAsFileTime(void* pms)
{
	ms_ocall_sgx_GetSystemTimeAsFileTime_t* ms = SGX_CAST(ms_ocall_sgx_GetSystemTimeAsFileTime_t*, pms);
	ocall_sgx_GetSystemTimeAsFileTime(ms->ms_ft, ms->ms_ft_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetAdaptersAddresses(void* pms)
{
	ms_ocall_sgx_GetAdaptersAddresses_t* ms = SGX_CAST(ms_ocall_sgx_GetAdaptersAddresses_t*, pms);
	ms->ms_retval = ocall_sgx_GetAdaptersAddresses(ms->ms_family, ms->ms_flags, ms->ms_addresses, ms->ms_addresses_size, ms->ms_psize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_TlsAlloc(void* pms)
{
	ms_ocall_sgx_TlsAlloc_t* ms = SGX_CAST(ms_ocall_sgx_TlsAlloc_t*, pms);
	ms->ms_retval = ocall_sgx_TlsAlloc();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_TlsGetValue(void* pms)
{
	ms_ocall_sgx_TlsGetValue_t* ms = SGX_CAST(ms_ocall_sgx_TlsGetValue_t*, pms);
	ms->ms_retval = ocall_sgx_TlsGetValue(ms->ms_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_TlsSetValue(void* pms)
{
	ms_ocall_sgx_TlsSetValue_t* ms = SGX_CAST(ms_ocall_sgx_TlsSetValue_t*, pms);
	ms->ms_retval = ocall_sgx_TlsSetValue(ms->ms_index, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_Sleep(void* pms)
{
	ms_ocall_sgx_Sleep_t* ms = SGX_CAST(ms_ocall_sgx_Sleep_t*, pms);
	ocall_sgx_Sleep(ms->ms_milli);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_select(void* pms)
{
	ms_ocall_sgx_select_t* ms = SGX_CAST(ms_ocall_sgx_select_t*, pms);
	ms->ms_retval = ocall_sgx_select(ms->ms_nfds, ms->ms_rfd, ms->ms_wfd, ms->ms_efd, ms->ms_fd_size, ms->ms_timeout, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_setsockopt(void* pms)
{
	ms_ocall_sgx_setsockopt_t* ms = SGX_CAST(ms_ocall_sgx_setsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_setsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, (const char*)ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_accept(void* pms)
{
	ms_ocall_sgx_accept_t* ms = SGX_CAST(ms_ocall_sgx_accept_t*, pms);
	ms->ms_retval = ocall_sgx_accept(ms->ms_s, ms->ms_addr, ms->ms_addr_size, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_bind(void* pms)
{
	ms_ocall_sgx_bind_t* ms = SGX_CAST(ms_ocall_sgx_bind_t*, pms);
	ms->ms_retval = ocall_sgx_bind(ms->ms_s, (const struct sockaddr*)ms->ms_addr, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_fstat(void* pms)
{
	ms_ocall_sgx_fstat_t* ms = SGX_CAST(ms_ocall_sgx_fstat_t*, pms);
	ms->ms_retval = ocall_sgx_fstat(ms->ms_fd, ms->ms_buf, ms->ms_buflen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_socket(void* pms)
{
	ms_ocall_sgx_socket_t* ms = SGX_CAST(ms_ocall_sgx_socket_t*, pms);
	ms->ms_retval = ocall_sgx_socket(ms->ms_af, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_listen(void* pms)
{
	ms_ocall_sgx_listen_t* ms = SGX_CAST(ms_ocall_sgx_listen_t*, pms);
	ms->ms_retval = ocall_sgx_listen(ms->ms_s, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_connect(void* pms)
{
	ms_ocall_sgx_connect_t* ms = SGX_CAST(ms_ocall_sgx_connect_t*, pms);
	ms->ms_retval = ocall_sgx_connect(ms->ms_s, (const struct sockaddr*)ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ioctlsocket(void* pms)
{
	ms_ocall_sgx_ioctlsocket_t* ms = SGX_CAST(ms_ocall_sgx_ioctlsocket_t*, pms);
	ms->ms_retval = ocall_sgx_ioctlsocket(ms->ms_s, ms->ms_cmd, ms->ms_argp, ms->ms_argp_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_EnterCriticalSection(void* pms)
{
	ms_ocall_sgx_EnterCriticalSection_t* ms = SGX_CAST(ms_ocall_sgx_EnterCriticalSection_t*, pms);
	ocall_sgx_EnterCriticalSection(ms->ms_lock, ms->ms_lock_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_LeaveCriticalSection(void* pms)
{
	ms_ocall_sgx_LeaveCriticalSection_t* ms = SGX_CAST(ms_ocall_sgx_LeaveCriticalSection_t*, pms);
	ocall_sgx_LeaveCriticalSection(ms->ms_lock, ms->ms_lock_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_DeleteCriticalSection(void* pms)
{
	ms_ocall_sgx_DeleteCriticalSection_t* ms = SGX_CAST(ms_ocall_sgx_DeleteCriticalSection_t*, pms);
	ocall_sgx_DeleteCriticalSection(ms->ms_lock, ms->ms_lock_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_InitializeCriticalSectionAndSpinCount(void* pms)
{
	ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t* ms = SGX_CAST(ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t*, pms);
	ocall_sgx_InitializeCriticalSectionAndSpinCount(ms->ms_lock, ms->ms_lock_len, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_gethostbyname(void* pms)
{
	ms_ocall_sgx_gethostbyname_t* ms = SGX_CAST(ms_ocall_sgx_gethostbyname_t*, pms);
	ms->ms_retval = ocall_sgx_gethostbyname((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_WaitForSingleObject(void* pms)
{
	ms_ocall_sgx_WaitForSingleObject_t* ms = SGX_CAST(ms_ocall_sgx_WaitForSingleObject_t*, pms);
	ocall_sgx_WaitForSingleObject(ms->ms_handle, ms->ms_ms_);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CryptGenRandom(void* pms)
{
	ms_ocall_sgx_CryptGenRandom_t* ms = SGX_CAST(ms_ocall_sgx_CryptGenRandom_t*, pms);
	ms->ms_retval = ocall_sgx_CryptGenRandom(ms->ms_prov, ms->ms_buf_len, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CryptReleaseContext(void* pms)
{
	ms_ocall_sgx_CryptReleaseContext_t* ms = SGX_CAST(ms_ocall_sgx_CryptReleaseContext_t*, pms);
	ms->ms_retval = ocall_sgx_CryptReleaseContext(ms->ms_hProv, ms->ms_dwFlags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CloseHandle(void* pms)
{
	ms_ocall_sgx_CloseHandle_t* ms = SGX_CAST(ms_ocall_sgx_CloseHandle_t*, pms);
	ms->ms_retval = ocall_sgx_CloseHandle(ms->ms_hObject);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetLastError(void* pms)
{
	ms_ocall_sgx_GetLastError_t* ms = SGX_CAST(ms_ocall_sgx_GetLastError_t*, pms);
	ms->ms_retval = ocall_sgx_GetLastError();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CreateIoCompletionPort(void* pms)
{
	ms_ocall_sgx_CreateIoCompletionPort_t* ms = SGX_CAST(ms_ocall_sgx_CreateIoCompletionPort_t*, pms);
	ms->ms_retval = ocall_sgx_CreateIoCompletionPort(ms->ms_FileHandle, ms->ms_p, ms->ms_k, ms->ms_numthreads);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetQueuedCompletionStatus(void* pms)
{
	ms_ocall_sgx_GetQueuedCompletionStatus_t* ms = SGX_CAST(ms_ocall_sgx_GetQueuedCompletionStatus_t*, pms);
	ms->ms_retval = ocall_sgx_GetQueuedCompletionStatus(ms->ms_p, ms->ms_numbytes, ms->ms_numbytes_len, ms->ms_k, ms->ms_k_len, ms->ms_lpOverlapped, ms->ms_lpOverlapped_len, ms->ms_dwMilliseconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetSystemDirectory(void* pms)
{
	ms_ocall_sgx_GetSystemDirectory_t* ms = SGX_CAST(ms_ocall_sgx_GetSystemDirectory_t*, pms);
	ms->ms_retval = ocall_sgx_GetSystemDirectory(ms->ms_lpBuffer, ms->ms_uSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_LoadLibrary(void* pms)
{
	ms_ocall_sgx_LoadLibrary_t* ms = SGX_CAST(ms_ocall_sgx_LoadLibrary_t*, pms);
	ms->ms_retval = ocall_sgx_LoadLibrary(ms->ms_lpFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_open(void* pms)
{
	ms_ocall_sgx_open_t* ms = SGX_CAST(ms_ocall_sgx_open_t*, pms);
	ms->ms_retval = ocall_sgx_open((const char*)ms->ms_pathname, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ftime(void* pms)
{
	ms_ocall_sgx_ftime_t* ms = SGX_CAST(ms_ocall_sgx_ftime_t*, pms);
	ocall_sgx_ftime(ms->ms_tb, ms->ms_size_timeb);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CreateSemaphore(void* pms)
{
	ms_ocall_sgx_CreateSemaphore_t* ms = SGX_CAST(ms_ocall_sgx_CreateSemaphore_t*, pms);
	ms->ms_retval = ocall_sgx_CreateSemaphore(ms->ms_attr, ms->ms_attr_len, ms->ms_initcount, ms->ms_maxcount, ms->ms_name, ms->ms_name_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ReleaseSemaphore(void* pms)
{
	ms_ocall_sgx_ReleaseSemaphore_t* ms = SGX_CAST(ms_ocall_sgx_ReleaseSemaphore_t*, pms);
	ms->ms_retval = ocall_sgx_ReleaseSemaphore(ms->ms_hSemaphore, ms->ms_lReleaseCount, ms->ms_lpPreviousCount, ms->ms_lp_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CryptAcquireContext(void* pms)
{
	ms_ocall_sgx_CryptAcquireContext_t* ms = SGX_CAST(ms_ocall_sgx_CryptAcquireContext_t*, pms);
	ms->ms_retval = ocall_sgx_CryptAcquireContext(ms->ms_prov, ms->ms_container, ms->ms_provider, ms->ms_provtype, ms->ms_dwflags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getenv(void* pms)
{
	ms_ocall_sgx_getenv_t* ms = SGX_CAST(ms_ocall_sgx_getenv_t*, pms);
	ms->ms_retval = ocall_sgx_getenv((const char*)ms->ms_env, ms->ms_envlen, ms->ms_ret_str, ms->ms_ret_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getsockname(void* pms)
{
	ms_ocall_sgx_getsockname_t* ms = SGX_CAST(ms_ocall_sgx_getsockname_t*, pms);
	ms->ms_retval = ocall_sgx_getsockname(ms->ms_s, ms->ms_name, ms->ms_nlen, ms->ms_namelen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getsockopt(void* pms)
{
	ms_ocall_sgx_getsockopt_t* ms = SGX_CAST(ms_ocall_sgx_getsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_getsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optval_len, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getservbyname(void* pms)
{
	ms_ocall_sgx_getservbyname_t* ms = SGX_CAST(ms_ocall_sgx_getservbyname_t*, pms);
	ocall_sgx_getservbyname((const char*)ms->ms_name, ms->ms_name_len, (const char*)ms->ms_proto, ms->ms_proto_len, ms->ms_serv_ptr, ms->ms_serv_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getprotobynumber(void* pms)
{
	ms_ocall_sgx_getprotobynumber_t* ms = SGX_CAST(ms_ocall_sgx_getprotobynumber_t*, pms);
	ocall_sgx_getprotobynumber(ms->ms_number, ms->ms_proto, ms->ms_proto_len, ms->ms_proto_name, ms->ms_proto_name_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_beginthread(void* pms)
{
	ms_ocall_sgx_beginthread_t* ms = SGX_CAST(ms_ocall_sgx_beginthread_t*, pms);
	ms->ms_retval = ocall_sgx_beginthread(ms->ms_port, ms->ms_port_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_endthread(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_sgx_endthread();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_PostQueuedCompletionStatus(void* pms)
{
	ms_ocall_sgx_PostQueuedCompletionStatus_t* ms = SGX_CAST(ms_ocall_sgx_PostQueuedCompletionStatus_t*, pms);
	ms->ms_retval = ocall_sgx_PostQueuedCompletionStatus(ms->ms_p, ms->ms_n, ms->ms_key, ms->ms_o, ms->ms_o_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_signal(void* pms)
{
	ms_ocall_sgx_signal_t* ms = SGX_CAST(ms_ocall_sgx_signal_t*, pms);
	ocall_sgx_signal(ms->ms_signum, ms->ms_f_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ntohs(void* pms)
{
	ms_ocall_sgx_ntohs_t* ms = SGX_CAST(ms_ocall_sgx_ntohs_t*, pms);
	ms->ms_retval = ocall_sgx_ntohs(ms->ms_netshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ntohl(void* pms)
{
	ms_ocall_sgx_ntohl_t* ms = SGX_CAST(ms_ocall_sgx_ntohl_t*, pms);
	ms->ms_retval = ocall_sgx_ntohl(ms->ms_netlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_get_time(void* pms)
{
	ms_ocall_get_time_t* ms = SGX_CAST(ms_ocall_get_time_t*, pms);
	ms->ms_retval = ocall_get_time(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ucheck_recv(void* pms)
{
	ms_ocall_sgx_ucheck_recv_t* ms = SGX_CAST(ms_ocall_sgx_ucheck_recv_t*, pms);
	ms->ms_retval = ocall_sgx_ucheck_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_recv(void* pms)
{
	ms_ocall_sgx_recv_t* ms = SGX_CAST(ms_ocall_sgx_recv_t*, pms);
	ms->ms_retval = ocall_sgx_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_direct_recv(void* pms)
{
	ms_ocall_sgx_direct_recv_t* ms = SGX_CAST(ms_ocall_sgx_direct_recv_t*, pms);
	ms->ms_retval = ocall_sgx_direct_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_send(void* pms)
{
	ms_ocall_sgx_send_t* ms = SGX_CAST(ms_ocall_sgx_send_t*, pms);
	ms->ms_retval = ocall_sgx_send(ms->ms_s, (const char*)ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_ucheck_send(void* pms)
{
	ms_ocall_sgx_ucheck_send_t* ms = SGX_CAST(ms_ocall_sgx_ucheck_send_t*, pms);
	ms->ms_retval = ocall_sgx_ucheck_send(ms->ms_s, (const char*)ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_direct_send(void* pms)
{
	ms_ocall_sgx_direct_send_t* ms = SGX_CAST(ms_ocall_sgx_direct_send_t*, pms);
	ms->ms_retval = ocall_sgx_direct_send(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_WSAGetLastError(void* pms)
{
	ms_ocall_sgx_WSAGetLastError_t* ms = SGX_CAST(ms_ocall_sgx_WSAGetLastError_t*, pms);
	ms->ms_retval = ocall_sgx_WSAGetLastError();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_SetLastError(void* pms)
{
	ms_ocall_sgx_SetLastError_t* ms = SGX_CAST(ms_ocall_sgx_SetLastError_t*, pms);
	ocall_sgx_SetLastError(ms->ms_e);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_WSASetLastError(void* pms)
{
	ms_ocall_sgx_WSASetLastError_t* ms = SGX_CAST(ms_ocall_sgx_WSASetLastError_t*, pms);
	ocall_sgx_WSASetLastError(ms->ms_e);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_rename(void* pms)
{
	ms_ocall_sgx_rename_t* ms = SGX_CAST(ms_ocall_sgx_rename_t*, pms);
	ms->ms_retval = ocall_sgx_rename((const char*)ms->ms_from_str, (const char*)ms->ms_to_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_unlink(void* pms)
{
	ms_ocall_sgx_unlink_t* ms = SGX_CAST(ms_ocall_sgx_unlink_t*, pms);
	ms->ms_retval = ocall_sgx_unlink((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_close(void* pms)
{
	ms_ocall_sgx_close_t* ms = SGX_CAST(ms_ocall_sgx_close_t*, pms);
	ms->ms_retval = ocall_sgx_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_chsize(void* pms)
{
	ms_ocall_sgx_chsize_t* ms = SGX_CAST(ms_ocall_sgx_chsize_t*, pms);
	ms->ms_retval = ocall_sgx_chsize(ms->ms_fd, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_closesocket(void* pms)
{
	ms_ocall_sgx_closesocket_t* ms = SGX_CAST(ms_ocall_sgx_closesocket_t*, pms);
	ms->ms_retval = ocall_sgx_closesocket(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_shutdown(void* pms)
{
	ms_ocall_sgx_shutdown_t* ms = SGX_CAST(ms_ocall_sgx_shutdown_t*, pms);
	ms->ms_retval = ocall_sgx_shutdown(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_exit(void* pms)
{
	ms_ocall_sgx_exit_t* ms = SGX_CAST(ms_ocall_sgx_exit_t*, pms);
	ocall_sgx_exit(ms->ms_exit_status);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_write(void* pms)
{
	ms_ocall_sgx_write_t* ms = SGX_CAST(ms_ocall_sgx_write_t*, pms);
	ms->ms_retval = ocall_sgx_write(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_direct_write(void* pms)
{
	ms_ocall_sgx_direct_write_t* ms = SGX_CAST(ms_ocall_sgx_direct_write_t*, pms);
	ms->ms_retval = ocall_sgx_direct_write(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_read(void* pms)
{
	ms_ocall_sgx_read_t* ms = SGX_CAST(ms_ocall_sgx_read_t*, pms);
	ms->ms_retval = ocall_sgx_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_direct_read(void* pms)
{
	ms_ocall_sgx_direct_read_t* ms = SGX_CAST(ms_ocall_sgx_direct_read_t*, pms);
	ms->ms_retval = ocall_sgx_direct_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_getpid(void* pms)
{
	ms_ocall_sgx_getpid_t* ms = SGX_CAST(ms_ocall_sgx_getpid_t*, pms);
	ms->ms_retval = ocall_sgx_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_lseek(void* pms)
{
	ms_ocall_sgx_lseek_t* ms = SGX_CAST(ms_ocall_sgx_lseek_t*, pms);
	ms->ms_retval = ocall_sgx_lseek(ms->ms_fildes, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_locking(void* pms)
{
	ms_ocall_sgx_locking_t* ms = SGX_CAST(ms_ocall_sgx_locking_t*, pms);
	ms->ms_retval = ocall_sgx_locking(ms->ms_fd, ms->ms_mode, ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_gethostname(void* pms)
{
	ms_ocall_sgx_gethostname_t* ms = SGX_CAST(ms_ocall_sgx_gethostname_t*, pms);
	ms->ms_retval = ocall_sgx_gethostname(ms->ms_name, ms->ms_namelen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_localtime(void* pms)
{
	ms_ocall_sgx_localtime_t* ms = SGX_CAST(ms_ocall_sgx_localtime_t*, pms);
	ms->ms_retval = ocall_sgx_localtime((const time_t*)ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_gmtime(void* pms)
{
	ms_ocall_sgx_gmtime_t* ms = SGX_CAST(ms_ocall_sgx_gmtime_t*, pms);
	ms->ms_retval = ocall_sgx_gmtime((const time_t*)ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_mktime(void* pms)
{
	ms_ocall_sgx_mktime_t* ms = SGX_CAST(ms_ocall_sgx_mktime_t*, pms);
	ms->ms_retval = ocall_sgx_mktime(ms->ms_timeptr, ms->ms_tm_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetNetworkParams(void* pms)
{
	ms_ocall_sgx_GetNetworkParams_t* ms = SGX_CAST(ms_ocall_sgx_GetNetworkParams_t*, pms);
	ms->ms_retval = ocall_sgx_GetNetworkParams(ms->ms_fixed, ms->ms_fixed_sz, ms->ms_fixed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_sendto(void* pms)
{
	ms_ocall_sgx_sendto_t* ms = SGX_CAST(ms_ocall_sgx_sendto_t*, pms);
	ms->ms_retval = ocall_sgx_sendto(ms->ms_s, (const void*)ms->ms_msg, ms->ms_len, ms->ms_flags, (const struct sockaddr*)ms->ms_to, ms->ms_tolen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_recvfrom(void* pms)
{
	ms_ocall_sgx_recvfrom_t* ms = SGX_CAST(ms_ocall_sgx_recvfrom_t*, pms);
	ms->ms_retval = ocall_sgx_recvfrom(ms->ms_s, ms->ms_msg, ms->ms_len, ms->ms_flags, ms->ms_fr, ms->ms_frlen, ms->ms_in_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_SHGetSpecialFolderPathA(void* pms)
{
	ms_ocall_sgx_SHGetSpecialFolderPathA_t* ms = SGX_CAST(ms_ocall_sgx_SHGetSpecialFolderPathA_t*, pms);
	ms->ms_retval = ocall_sgx_SHGetSpecialFolderPathA(ms->ms_hwnd, ms->ms_path, ms->ms_path_len, ms->ms_csidl, ms->ms_fCreate);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_fputs(void* pms)
{
	ms_ocall_sgx_fputs_t* ms = SGX_CAST(ms_ocall_sgx_fputs_t*, pms);
	ms->ms_retval = ocall_sgx_fputs((const char*)ms->ms_str, ms->ms_stream, ms->ms_stream_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_fclose(void* pms)
{
	ms_ocall_sgx_fclose_t* ms = SGX_CAST(ms_ocall_sgx_fclose_t*, pms);
	ms->ms_retval = ocall_sgx_fclose(ms->ms_file, ms->ms_file_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_stat(void* pms)
{
	ms_ocall_sgx_stat_t* ms = SGX_CAST(ms_ocall_sgx_stat_t*, pms);
	ms->ms_retval = ocall_sgx_stat((const char*)ms->ms_filename, ms->ms_st, ms->ms_stat_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_mkdir(void* pms)
{
	ms_ocall_sgx_mkdir_t* ms = SGX_CAST(ms_ocall_sgx_mkdir_t*, pms);
	ms->ms_retval = ocall_sgx_mkdir((const char*)ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_UnmapViewOfFile(void* pms)
{
	ms_ocall_sgx_UnmapViewOfFile_t* ms = SGX_CAST(ms_ocall_sgx_UnmapViewOfFile_t*, pms);
	ms->ms_retval = ocall_sgx_UnmapViewOfFile(ms->ms_lpBaseAddress);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_MapViewOfFile(void* pms)
{
	ms_ocall_sgx_MapViewOfFile_t* ms = SGX_CAST(ms_ocall_sgx_MapViewOfFile_t*, pms);
	ms->ms_retval = ocall_sgx_MapViewOfFile(ms->ms_hFileMappingObject, ms->ms_dwDesiredAccess, ms->ms_dwFileOffsetHigh, ms->ms_dwFileOffsetLow, ms->ms_dwNumberOfBytesToMap);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CreateFileMapping(void* pms)
{
	ms_ocall_sgx_CreateFileMapping_t* ms = SGX_CAST(ms_ocall_sgx_CreateFileMapping_t*, pms);
	ms->ms_retval = ocall_sgx_CreateFileMapping(ms->ms_hFile, ms->ms__null, ms->ms_flProtect, ms->ms_dwMaximumSizeHigh, ms->ms_dwMaximumSizeLow, (const char*)ms->ms_lpName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_GetFileSize(void* pms)
{
	ms_ocall_sgx_GetFileSize_t* ms = SGX_CAST(ms_ocall_sgx_GetFileSize_t*, pms);
	ms->ms_retval = ocall_sgx_GetFileSize(ms->ms_hFile, ms->ms_lpFileSizeHigh);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_CreateFile(void* pms)
{
	ms_ocall_sgx_CreateFile_t* ms = SGX_CAST(ms_ocall_sgx_CreateFile_t*, pms);
	ms->ms_retval = ocall_sgx_CreateFile((const char*)ms->ms_lpFileName, ms->ms_dwDesiredAccess, ms->ms_dwShareMode, ms->ms__null, ms->ms_dwCreationDisposition, ms->ms_dwFlagsAndAttributes, ms->ms_hTemplateFile);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_clock(void* pms)
{
	ms_ocall_sgx_clock_t* ms = SGX_CAST(ms_ocall_sgx_clock_t*, pms);
	ms->ms_retval = ocall_sgx_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_ocall_sgx_fdopen(void* pms)
{
	ms_ocall_sgx_fdopen_t* ms = SGX_CAST(ms_ocall_sgx_fdopen_t*, pms);
	ms->ms_retval = ocall_sgx_fdopen(ms->ms_fd, (const char*)ms->ms_format);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TorSGX_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[104];
} ocall_table_TorSGX = {
	104,
	{
		(void*)(uintptr_t)TorSGX_ocall_sgx_process_msg_all,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ra_free_network_response_buffer,
		(void*)(uintptr_t)TorSGX_ocall_sgx_malloc,
		(void*)(uintptr_t)TorSGX_ocall_sgx_calloc,
		(void*)(uintptr_t)TorSGX_ocall_sgx_realloc,
		(void*)(uintptr_t)TorSGX_ocall_sgx_free,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetSystemTimeAsFileTime,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetAdaptersAddresses,
		(void*)(uintptr_t)TorSGX_ocall_sgx_TlsAlloc,
		(void*)(uintptr_t)TorSGX_ocall_sgx_TlsGetValue,
		(void*)(uintptr_t)TorSGX_ocall_sgx_TlsSetValue,
		(void*)(uintptr_t)TorSGX_ocall_sgx_Sleep,
		(void*)(uintptr_t)TorSGX_ocall_sgx_select,
		(void*)(uintptr_t)TorSGX_ocall_print_string,
		(void*)(uintptr_t)TorSGX_ocall_sgx_setsockopt,
		(void*)(uintptr_t)TorSGX_ocall_sgx_accept,
		(void*)(uintptr_t)TorSGX_ocall_sgx_bind,
		(void*)(uintptr_t)TorSGX_ocall_sgx_fstat,
		(void*)(uintptr_t)TorSGX_ocall_sgx_socket,
		(void*)(uintptr_t)TorSGX_ocall_sgx_listen,
		(void*)(uintptr_t)TorSGX_ocall_sgx_connect,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ioctlsocket,
		(void*)(uintptr_t)TorSGX_ocall_sgx_EnterCriticalSection,
		(void*)(uintptr_t)TorSGX_ocall_sgx_LeaveCriticalSection,
		(void*)(uintptr_t)TorSGX_ocall_sgx_DeleteCriticalSection,
		(void*)(uintptr_t)TorSGX_ocall_sgx_InitializeCriticalSectionAndSpinCount,
		(void*)(uintptr_t)TorSGX_ocall_sgx_gethostbyname,
		(void*)(uintptr_t)TorSGX_ocall_sgx_WaitForSingleObject,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CryptGenRandom,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CryptReleaseContext,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CloseHandle,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetLastError,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CreateIoCompletionPort,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetQueuedCompletionStatus,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetSystemDirectory,
		(void*)(uintptr_t)TorSGX_ocall_sgx_LoadLibrary,
		(void*)(uintptr_t)TorSGX_ocall_sgx_open,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ftime,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CreateSemaphore,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ReleaseSemaphore,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CryptAcquireContext,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getenv,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getsockname,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getsockopt,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getservbyname,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getprotobynumber,
		(void*)(uintptr_t)TorSGX_ocall_sgx_beginthread,
		(void*)(uintptr_t)TorSGX_ocall_sgx_endthread,
		(void*)(uintptr_t)TorSGX_ocall_sgx_PostQueuedCompletionStatus,
		(void*)(uintptr_t)TorSGX_ocall_sgx_signal,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ntohs,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ntohl,
		(void*)(uintptr_t)TorSGX_ocall_get_time,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ucheck_recv,
		(void*)(uintptr_t)TorSGX_ocall_sgx_recv,
		(void*)(uintptr_t)TorSGX_ocall_sgx_direct_recv,
		(void*)(uintptr_t)TorSGX_ocall_sgx_send,
		(void*)(uintptr_t)TorSGX_ocall_sgx_ucheck_send,
		(void*)(uintptr_t)TorSGX_ocall_sgx_direct_send,
		(void*)(uintptr_t)TorSGX_ocall_sgx_WSAGetLastError,
		(void*)(uintptr_t)TorSGX_ocall_sgx_SetLastError,
		(void*)(uintptr_t)TorSGX_ocall_sgx_WSASetLastError,
		(void*)(uintptr_t)TorSGX_ocall_sgx_rename,
		(void*)(uintptr_t)TorSGX_ocall_sgx_unlink,
		(void*)(uintptr_t)TorSGX_ocall_sgx_close,
		(void*)(uintptr_t)TorSGX_ocall_sgx_chsize,
		(void*)(uintptr_t)TorSGX_ocall_sgx_closesocket,
		(void*)(uintptr_t)TorSGX_ocall_sgx_shutdown,
		(void*)(uintptr_t)TorSGX_ocall_sgx_exit,
		(void*)(uintptr_t)TorSGX_ocall_sgx_write,
		(void*)(uintptr_t)TorSGX_ocall_sgx_direct_write,
		(void*)(uintptr_t)TorSGX_ocall_sgx_read,
		(void*)(uintptr_t)TorSGX_ocall_sgx_direct_read,
		(void*)(uintptr_t)TorSGX_ocall_sgx_getpid,
		(void*)(uintptr_t)TorSGX_ocall_sgx_lseek,
		(void*)(uintptr_t)TorSGX_ocall_sgx_locking,
		(void*)(uintptr_t)TorSGX_ocall_sgx_gethostname,
		(void*)(uintptr_t)TorSGX_ocall_sgx_localtime,
		(void*)(uintptr_t)TorSGX_ocall_sgx_gmtime,
		(void*)(uintptr_t)TorSGX_ocall_sgx_mktime,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetNetworkParams,
		(void*)(uintptr_t)TorSGX_ocall_sgx_sendto,
		(void*)(uintptr_t)TorSGX_ocall_sgx_recvfrom,
		(void*)(uintptr_t)TorSGX_ocall_sgx_SHGetSpecialFolderPathA,
		(void*)(uintptr_t)TorSGX_ocall_sgx_fputs,
		(void*)(uintptr_t)TorSGX_ocall_sgx_fclose,
		(void*)(uintptr_t)TorSGX_ocall_sgx_stat,
		(void*)(uintptr_t)TorSGX_ocall_sgx_mkdir,
		(void*)(uintptr_t)TorSGX_ocall_sgx_UnmapViewOfFile,
		(void*)(uintptr_t)TorSGX_ocall_sgx_MapViewOfFile,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CreateFileMapping,
		(void*)(uintptr_t)TorSGX_ocall_sgx_GetFileSize,
		(void*)(uintptr_t)TorSGX_ocall_sgx_CreateFile,
		(void*)(uintptr_t)TorSGX_ocall_sgx_clock,
		(void*)(uintptr_t)TorSGX_ocall_sgx_fdopen,
		(void*)(uintptr_t)TorSGX_create_session_ocall,
		(void*)(uintptr_t)TorSGX_exchange_report_ocall,
		(void*)(uintptr_t)TorSGX_close_session_ocall,
		(void*)(uintptr_t)TorSGX_invoke_service_ocall,
		(void*)(uintptr_t)TorSGX_sgx_oc_cpuidex,
		(void*)(uintptr_t)TorSGX_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)TorSGX_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)TorSGX_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)TorSGX_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t sgx_start_tor(sgx_enclave_id_t eid, int argc, char** argv, int argv_len, void* version, int version_size, unsigned long long app_errno, unsigned long long app_environ, const char* app_conf_root, const char* app_torrc, const char* app_system_dir, MEMORYSTATUSEX* app_mse, SYSTEM_INFO* app_info)
{
	sgx_status_t status;
	ms_sgx_start_tor_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	ms.ms_argv_len = argv_len;
	ms.ms_version = version;
	ms.ms_version_size = version_size;
	ms.ms_app_errno = app_errno;
	ms.ms_app_environ = app_environ;
	ms.ms_app_conf_root = (char*)app_conf_root;
	ms.ms_app_torrc = (char*)app_torrc;
	ms.ms_app_system_dir = (char*)app_system_dir;
	ms.ms_app_mse = app_mse;
	ms.ms_app_info = app_info;
	status = sgx_ecall(eid, 0, &ocall_table_TorSGX, &ms);
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
	status = sgx_ecall(eid, 1, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_start_fingerprint(sgx_enclave_id_t eid, char* fingerprint, char* data_dir, const char* app_torrc, unsigned long long app_errno, MEMORYSTATUSEX* app_mse)
{
	sgx_status_t status;
	ms_sgx_start_fingerprint_t ms;
	ms.ms_fingerprint = fingerprint;
	ms.ms_data_dir = data_dir;
	ms.ms_app_torrc = (char*)app_torrc;
	ms.ms_app_errno = app_errno;
	ms.ms_app_mse = app_mse;
	status = sgx_ecall(eid, 2, &ocall_table_TorSGX, &ms);
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
	status = sgx_ecall(eid, 3, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_sgx_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 4, &ocall_table_TorSGX, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_close_ra(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_sgx_close_ra_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 5, &ocall_table_TorSGX, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_sgx_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 6, &ocall_table_TorSGX, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_func_caller(sgx_enclave_id_t eid, void* args, int args_len)
{
	sgx_status_t status;
	ms_enclave_func_caller_t ms;
	ms.ms_args = args;
	ms.ms_args_len = args_len;
	status = sgx_ecall(eid, 7, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t test_sgx_put_gencert(sgx_enclave_id_t eid, char* fname, char* fcont, int fcont_len)
{
	sgx_status_t status;
	ms_test_sgx_put_gencert_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	ms.ms_fcont_len = fcont_len;
	status = sgx_ecall(eid, 8, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_seal_files(sgx_enclave_id_t eid, char* fname, void* fcont)
{
	sgx_status_t status;
	ms_sgx_seal_files_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	status = sgx_ecall(eid, 9, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_unseal_files(sgx_enclave_id_t eid, char* fname, void* fcont)
{
	sgx_status_t status;
	ms_sgx_unseal_files_t ms;
	ms.ms_fname = fname;
	ms.ms_fcont = fcont;
	status = sgx_ecall(eid, 10, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_signal_handle_caller(sgx_enclave_id_t eid, int signum, int f_id)
{
	sgx_status_t status;
	ms_sgx_signal_handle_caller_t ms;
	ms.ms_signum = signum;
	ms.ms_f_id = f_id;
	status = sgx_ecall(eid, 11, &ocall_table_TorSGX, &ms);
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 12, &ocall_table_TorSGX, &ms);
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
	status = sgx_ecall(eid, 13, &ocall_table_TorSGX, &ms);
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
	status = sgx_ecall(eid, 14, &ocall_table_TorSGX, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

