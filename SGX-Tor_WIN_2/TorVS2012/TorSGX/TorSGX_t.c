#include "TorSGX_t.h"

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_sgx_start_tor(void* pms)
{
	ms_sgx_start_tor_t* ms = SGX_CAST(ms_sgx_start_tor_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_argv = ms->ms_argv;
	int _tmp_argv_len = ms->ms_argv_len;
	size_t _len_argv = _tmp_argv_len;
	char** _in_argv = NULL;
	void* _tmp_version = ms->ms_version;
	int _tmp_version_size = ms->ms_version_size;
	size_t _len_version = _tmp_version_size;
	void* _in_version = NULL;
	char* _tmp_app_conf_root = ms->ms_app_conf_root;
	size_t _len_app_conf_root = _tmp_app_conf_root ? strlen(_tmp_app_conf_root) + 1 : 0;
	char* _in_app_conf_root = NULL;
	char* _tmp_app_torrc = ms->ms_app_torrc;
	size_t _len_app_torrc = _tmp_app_torrc ? strlen(_tmp_app_torrc) + 1 : 0;
	char* _in_app_torrc = NULL;
	char* _tmp_app_system_dir = ms->ms_app_system_dir;
	size_t _len_app_system_dir = _tmp_app_system_dir ? strlen(_tmp_app_system_dir) + 1 : 0;
	char* _in_app_system_dir = NULL;
	MEMORYSTATUSEX* _tmp_app_mse = ms->ms_app_mse;
	size_t _len_app_mse = 64;
	MEMORYSTATUSEX* _in_app_mse = NULL;
	SYSTEM_INFO* _tmp_app_info = ms->ms_app_info;
	size_t _len_app_info = 64;
	SYSTEM_INFO* _in_app_info = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_start_tor_t));
	CHECK_UNIQUE_POINTER(_tmp_argv, _len_argv);
	CHECK_UNIQUE_POINTER(_tmp_version, _len_version);
	CHECK_UNIQUE_POINTER(_tmp_app_conf_root, _len_app_conf_root);
	CHECK_UNIQUE_POINTER(_tmp_app_torrc, _len_app_torrc);
	CHECK_UNIQUE_POINTER(_tmp_app_system_dir, _len_app_system_dir);
	CHECK_UNIQUE_POINTER(_tmp_app_mse, _len_app_mse);
	CHECK_UNIQUE_POINTER(_tmp_app_info, _len_app_info);

	if (_tmp_argv != NULL) {
		_in_argv = (char**)malloc(_len_argv);
		if (_in_argv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_argv, _tmp_argv, _len_argv);
	}
	if (_tmp_version != NULL) {
		_in_version = (void*)malloc(_len_version);
		if (_in_version == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_version, _tmp_version, _len_version);
	}
	if (_tmp_app_conf_root != NULL) {
		_in_app_conf_root = (char*)malloc(_len_app_conf_root);
		if (_in_app_conf_root == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_app_conf_root, _tmp_app_conf_root, _len_app_conf_root);
		_in_app_conf_root[_len_app_conf_root - 1] = '\0';
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
	if (_tmp_app_system_dir != NULL) {
		_in_app_system_dir = (char*)malloc(_len_app_system_dir);
		if (_in_app_system_dir == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_app_system_dir, _tmp_app_system_dir, _len_app_system_dir);
		_in_app_system_dir[_len_app_system_dir - 1] = '\0';
	}
	if (_tmp_app_mse != NULL) {
		_in_app_mse = (MEMORYSTATUSEX*)malloc(_len_app_mse);
		if (_in_app_mse == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_app_mse, _tmp_app_mse, _len_app_mse);
	}
	if (_tmp_app_info != NULL) {
		_in_app_info = (SYSTEM_INFO*)malloc(_len_app_info);
		if (_in_app_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_app_info, _tmp_app_info, _len_app_info);
	}
	sgx_start_tor(ms->ms_argc, _in_argv, _tmp_argv_len, _in_version, _tmp_version_size, ms->ms_app_errno, ms->ms_app_environ, (const char*)_in_app_conf_root, (const char*)_in_app_torrc, (const char*)_in_app_system_dir, _in_app_mse, _in_app_info);
err:
	if (_in_argv) free(_in_argv);
	if (_in_version) free(_in_version);
	if (_in_app_conf_root) free((void*)_in_app_conf_root);
	if (_in_app_torrc) free((void*)_in_app_torrc);
	if (_in_app_system_dir) free((void*)_in_app_system_dir);
	if (_in_app_mse) free(_in_app_mse);
	if (_in_app_info) free(_in_app_info);

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
	MEMORYSTATUSEX* _tmp_app_mse = ms->ms_app_mse;
	size_t _len_app_mse = 64;
	MEMORYSTATUSEX* _in_app_mse = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_start_fingerprint_t));
	CHECK_UNIQUE_POINTER(_tmp_fingerprint, _len_fingerprint);
	CHECK_UNIQUE_POINTER(_tmp_data_dir, _len_data_dir);
	CHECK_UNIQUE_POINTER(_tmp_app_torrc, _len_app_torrc);
	CHECK_UNIQUE_POINTER(_tmp_app_mse, _len_app_mse);

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
	if (_tmp_app_mse != NULL) {
		_in_app_mse = (MEMORYSTATUSEX*)malloc(_len_app_mse);
		if (_in_app_mse == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_app_mse, _tmp_app_mse, _len_app_mse);
	}
	sgx_start_fingerprint(_in_fingerprint, _in_data_dir, (const char*)_in_app_torrc, ms->ms_app_errno, _in_app_mse);
err:
	if (_in_fingerprint) {
		memcpy(_tmp_fingerprint, _in_fingerprint, _len_fingerprint);
		free(_in_fingerprint);
	}
	if (_in_data_dir) free(_in_data_dir);
	if (_in_app_torrc) free((void*)_in_app_torrc);
	if (_in_app_mse) free(_in_app_mse);

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

static sgx_status_t SGX_CDECL sgx_sgx_init_ra(void* pms)
{
	ms_sgx_init_ra_t* ms = SGX_CAST(ms_sgx_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_init_ra_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = sgx_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_close_ra(void* pms)
{
	ms_sgx_close_ra_t* ms = SGX_CAST(ms_sgx_close_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_close_ra_t));

	ms->ms_retval = sgx_close_ra(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_verify_att_result_mac(void* pms)
{
	ms_sgx_verify_att_result_mac_t* ms = SGX_CAST(ms_sgx_verify_att_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_verify_att_result_mac_t));
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
	ms->ms_retval = sgx_verify_att_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);
err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);

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

static sgx_status_t SGX_CDECL sgx_sgx_signal_handle_caller(void* pms)
{
	ms_sgx_signal_handle_caller_t* ms = SGX_CAST(ms_sgx_signal_handle_caller_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_signal_handle_caller_t));

	sgx_signal_handle_caller(ms->ms_signum, ms->ms_f_id);


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
	struct {void* call_addr; uint8_t is_priv;} ecall_table[15];
} g_ecall_table = {
	15,
	{
		{(void*)(uintptr_t)sgx_sgx_start_tor, 0},
		{(void*)(uintptr_t)sgx_sgx_start_gencert, 0},
		{(void*)(uintptr_t)sgx_sgx_start_fingerprint, 0},
		{(void*)(uintptr_t)sgx_sgx_start_remote_attestation_server, 0},
		{(void*)(uintptr_t)sgx_sgx_init_ra, 0},
		{(void*)(uintptr_t)sgx_sgx_close_ra, 0},
		{(void*)(uintptr_t)sgx_sgx_verify_att_result_mac, 0},
		{(void*)(uintptr_t)sgx_enclave_func_caller, 0},
		{(void*)(uintptr_t)sgx_test_sgx_put_gencert, 0},
		{(void*)(uintptr_t)sgx_sgx_seal_files, 0},
		{(void*)(uintptr_t)sgx_sgx_unseal_files, 0},
		{(void*)(uintptr_t)sgx_sgx_signal_handle_caller, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[104][15];
} g_dyn_entry_table = {
	104,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


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
	
	status = sgx_ocall(0, ms);

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
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_malloc(void** retval, int m_size)
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
	status = sgx_ocall(2, ms);

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
	status = sgx_ocall(3, ms);

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
	status = sgx_ocall(4, ms);

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
	status = sgx_ocall(5, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetSystemTimeAsFileTime(FILETIME* ft, int ft_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ft = ft_size;

	ms_ocall_sgx_GetSystemTimeAsFileTime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetSystemTimeAsFileTime_t);
	void *__tmp = NULL;

	ocalloc_size += (ft != NULL && sgx_is_within_enclave(ft, _len_ft)) ? _len_ft : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetSystemTimeAsFileTime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetSystemTimeAsFileTime_t));

	if (ft != NULL && sgx_is_within_enclave(ft, _len_ft)) {
		ms->ms_ft = (FILETIME*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ft);
		memset(ms->ms_ft, 0, _len_ft);
	} else if (ft == NULL) {
		ms->ms_ft = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_ft_size = ft_size;
	status = sgx_ocall(6, ms);

	if (ft) memcpy((void*)ft, ms->ms_ft, _len_ft);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetAdaptersAddresses(unsigned long int* retval, unsigned long int family, unsigned long int flags, void* addresses, unsigned long int addresses_size, unsigned long int* psize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addresses = addresses_size;
	size_t _len_psize = 4;

	ms_ocall_sgx_GetAdaptersAddresses_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetAdaptersAddresses_t);
	void *__tmp = NULL;

	ocalloc_size += (addresses != NULL && sgx_is_within_enclave(addresses, _len_addresses)) ? _len_addresses : 0;
	ocalloc_size += (psize != NULL && sgx_is_within_enclave(psize, _len_psize)) ? _len_psize : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetAdaptersAddresses_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetAdaptersAddresses_t));

	ms->ms_family = family;
	ms->ms_flags = flags;
	if (addresses != NULL && sgx_is_within_enclave(addresses, _len_addresses)) {
		ms->ms_addresses = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addresses);
		memcpy(ms->ms_addresses, addresses, _len_addresses);
	} else if (addresses == NULL) {
		ms->ms_addresses = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addresses_size = addresses_size;
	if (psize != NULL && sgx_is_within_enclave(psize, _len_psize)) {
		ms->ms_psize = (unsigned long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_psize);
		memcpy(ms->ms_psize, psize, _len_psize);
	} else if (psize == NULL) {
		ms->ms_psize = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;
	if (addresses) memcpy((void*)addresses, ms->ms_addresses, _len_addresses);
	if (psize) memcpy((void*)psize, ms->ms_psize, _len_psize);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_TlsAlloc(unsigned long int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_TlsAlloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_TlsAlloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_TlsAlloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_TlsAlloc_t));

	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_TlsGetValue(void** retval, unsigned long int index)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_TlsGetValue_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_TlsGetValue_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_TlsGetValue_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_TlsGetValue_t));

	ms->ms_index = index;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_TlsSetValue(int* retval, unsigned long int index, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = 4;

	ms_ocall_sgx_TlsSetValue_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_TlsSetValue_t);
	void *__tmp = NULL;

	ocalloc_size += (val != NULL && sgx_is_within_enclave(val, _len_val)) ? _len_val : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_TlsSetValue_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_TlsSetValue_t));

	ms->ms_index = index;
	if (val != NULL && sgx_is_within_enclave(val, _len_val)) {
		ms->ms_val = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_val);
		memcpy(ms->ms_val, val, _len_val);
	} else if (val == NULL) {
		ms->ms_val = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_Sleep(unsigned long int milli)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_Sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_Sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_Sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_Sleep_t));

	ms->ms_milli = milli;
	status = sgx_ocall(11, ms);


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
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;
	if (rfd) memcpy((void*)rfd, ms->ms_rfd, _len_rfd);
	if (wfd) memcpy((void*)wfd, ms->ms_wfd, _len_wfd);
	if (efd) memcpy((void*)efd, ms->ms_efd, _len_efd);

	sgx_ocfree();
	return status;
}

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
	
	status = sgx_ocall(13, ms);


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
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

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
	
	status = sgx_ocall(15, ms);

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
	status = sgx_ocall(16, ms);

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
	status = sgx_ocall(17, ms);

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
	status = sgx_ocall(18, ms);

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
	status = sgx_ocall(19, ms);

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
	status = sgx_ocall(20, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ioctlsocket(int* retval, int s, long int cmd, unsigned long int* argp, int argp_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_argp = argp_len;

	ms_ocall_sgx_ioctlsocket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ioctlsocket_t);
	void *__tmp = NULL;

	ocalloc_size += (argp != NULL && sgx_is_within_enclave(argp, _len_argp)) ? _len_argp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ioctlsocket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ioctlsocket_t));

	ms->ms_s = s;
	ms->ms_cmd = cmd;
	if (argp != NULL && sgx_is_within_enclave(argp, _len_argp)) {
		ms->ms_argp = (unsigned long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_argp);
		memcpy(ms->ms_argp, argp, _len_argp);
	} else if (argp == NULL) {
		ms->ms_argp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_argp_len = argp_len;
	status = sgx_ocall(21, ms);

	if (retval) *retval = ms->ms_retval;
	if (argp) memcpy((void*)argp, ms->ms_argp, _len_argp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_EnterCriticalSection(void* lock, int lock_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lock = lock_len;

	ms_ocall_sgx_EnterCriticalSection_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_EnterCriticalSection_t);
	void *__tmp = NULL;

	ocalloc_size += (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) ? _len_lock : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_EnterCriticalSection_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_EnterCriticalSection_t));

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
	status = sgx_ocall(22, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_LeaveCriticalSection(void* lock, int lock_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lock = lock_len;

	ms_ocall_sgx_LeaveCriticalSection_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_LeaveCriticalSection_t);
	void *__tmp = NULL;

	ocalloc_size += (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) ? _len_lock : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_LeaveCriticalSection_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_LeaveCriticalSection_t));

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
	status = sgx_ocall(23, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_DeleteCriticalSection(void* lock, int lock_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lock = lock_len;

	ms_ocall_sgx_DeleteCriticalSection_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_DeleteCriticalSection_t);
	void *__tmp = NULL;

	ocalloc_size += (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) ? _len_lock : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_DeleteCriticalSection_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_DeleteCriticalSection_t));

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
	status = sgx_ocall(24, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_InitializeCriticalSectionAndSpinCount(void* lock, int lock_len, int count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lock = lock_len;

	ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t);
	void *__tmp = NULL;

	ocalloc_size += (lock != NULL && sgx_is_within_enclave(lock, _len_lock)) ? _len_lock : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_InitializeCriticalSectionAndSpinCount_t));

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
	ms->ms_count = count;
	status = sgx_ocall(25, ms);


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
	
	status = sgx_ocall(26, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_WaitForSingleObject(int handle, unsigned long int ms_)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_WaitForSingleObject_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_WaitForSingleObject_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_WaitForSingleObject_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_WaitForSingleObject_t));

	ms->ms_handle = handle;
	ms->ms_ms_ = ms_;
	status = sgx_ocall(27, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CryptGenRandom(int* retval, unsigned long long prov, int buf_len, unsigned char* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = buf_len;

	ms_ocall_sgx_CryptGenRandom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CryptGenRandom_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CryptGenRandom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CryptGenRandom_t));

	ms->ms_prov = prov;
	ms->ms_buf_len = buf_len;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (unsigned char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(28, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CryptReleaseContext(int* retval, unsigned long long hProv, unsigned long int dwFlags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_CryptReleaseContext_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CryptReleaseContext_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CryptReleaseContext_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CryptReleaseContext_t));

	ms->ms_hProv = hProv;
	ms->ms_dwFlags = dwFlags;
	status = sgx_ocall(29, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CloseHandle(int* retval, int hObject)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_CloseHandle_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CloseHandle_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CloseHandle_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CloseHandle_t));

	ms->ms_hObject = hObject;
	status = sgx_ocall(30, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetLastError(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_GetLastError_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetLastError_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetLastError_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetLastError_t));

	status = sgx_ocall(31, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CreateIoCompletionPort(int* retval, int FileHandle, int p, unsigned long int k, unsigned long int numthreads)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_CreateIoCompletionPort_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CreateIoCompletionPort_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CreateIoCompletionPort_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CreateIoCompletionPort_t));

	ms->ms_FileHandle = FileHandle;
	ms->ms_p = p;
	ms->ms_k = k;
	ms->ms_numthreads = numthreads;
	status = sgx_ocall(32, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetQueuedCompletionStatus(int* retval, int p, unsigned long int* numbytes, int numbytes_len, __int64* k, int k_len, void* lpOverlapped, int lpOverlapped_len, unsigned long int dwMilliseconds)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_numbytes = numbytes_len;
	size_t _len_k = k_len;
	size_t _len_lpOverlapped = lpOverlapped_len;

	ms_ocall_sgx_GetQueuedCompletionStatus_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetQueuedCompletionStatus_t);
	void *__tmp = NULL;

	ocalloc_size += (numbytes != NULL && sgx_is_within_enclave(numbytes, _len_numbytes)) ? _len_numbytes : 0;
	ocalloc_size += (k != NULL && sgx_is_within_enclave(k, _len_k)) ? _len_k : 0;
	ocalloc_size += (lpOverlapped != NULL && sgx_is_within_enclave(lpOverlapped, _len_lpOverlapped)) ? _len_lpOverlapped : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetQueuedCompletionStatus_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetQueuedCompletionStatus_t));

	ms->ms_p = p;
	if (numbytes != NULL && sgx_is_within_enclave(numbytes, _len_numbytes)) {
		ms->ms_numbytes = (unsigned long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_numbytes);
		memcpy(ms->ms_numbytes, numbytes, _len_numbytes);
	} else if (numbytes == NULL) {
		ms->ms_numbytes = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_numbytes_len = numbytes_len;
	if (k != NULL && sgx_is_within_enclave(k, _len_k)) {
		ms->ms_k = (__int64*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_k);
		memcpy(ms->ms_k, k, _len_k);
	} else if (k == NULL) {
		ms->ms_k = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_k_len = k_len;
	if (lpOverlapped != NULL && sgx_is_within_enclave(lpOverlapped, _len_lpOverlapped)) {
		ms->ms_lpOverlapped = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpOverlapped);
		memcpy(ms->ms_lpOverlapped, lpOverlapped, _len_lpOverlapped);
	} else if (lpOverlapped == NULL) {
		ms->ms_lpOverlapped = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_lpOverlapped_len = lpOverlapped_len;
	ms->ms_dwMilliseconds = dwMilliseconds;
	status = sgx_ocall(33, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetSystemDirectory(unsigned int* retval, char* lpBuffer, unsigned int uSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lpBuffer = uSize;

	ms_ocall_sgx_GetSystemDirectory_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetSystemDirectory_t);
	void *__tmp = NULL;

	ocalloc_size += (lpBuffer != NULL && sgx_is_within_enclave(lpBuffer, _len_lpBuffer)) ? _len_lpBuffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetSystemDirectory_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetSystemDirectory_t));

	if (lpBuffer != NULL && sgx_is_within_enclave(lpBuffer, _len_lpBuffer)) {
		ms->ms_lpBuffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpBuffer);
		memset(ms->ms_lpBuffer, 0, _len_lpBuffer);
	} else if (lpBuffer == NULL) {
		ms->ms_lpBuffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_uSize = uSize;
	status = sgx_ocall(34, ms);

	if (retval) *retval = ms->ms_retval;
	if (lpBuffer) memcpy((void*)lpBuffer, ms->ms_lpBuffer, _len_lpBuffer);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_LoadLibrary(unsigned long long* retval, char* lpFileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lpFileName = lpFileName ? strlen(lpFileName) + 1 : 0;

	ms_ocall_sgx_LoadLibrary_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_LoadLibrary_t);
	void *__tmp = NULL;

	ocalloc_size += (lpFileName != NULL && sgx_is_within_enclave(lpFileName, _len_lpFileName)) ? _len_lpFileName : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_LoadLibrary_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_LoadLibrary_t));

	if (lpFileName != NULL && sgx_is_within_enclave(lpFileName, _len_lpFileName)) {
		ms->ms_lpFileName = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpFileName);
		memcpy(ms->ms_lpFileName, lpFileName, _len_lpFileName);
	} else if (lpFileName == NULL) {
		ms->ms_lpFileName = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(35, ms);

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
	status = sgx_ocall(36, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ftime(struct _timeb* tb, int size_timeb)
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
		ms->ms_tb = (struct _timeb*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tb);
		memset(ms->ms_tb, 0, _len_tb);
	} else if (tb == NULL) {
		ms->ms_tb = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size_timeb = size_timeb;
	status = sgx_ocall(37, ms);

	if (tb) memcpy((void*)tb, ms->ms_tb, _len_tb);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CreateSemaphore(int* retval, void* attr, int attr_len, long int initcount, long int maxcount, void* name, int name_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_attr = attr_len;
	size_t _len_name = name_len;

	ms_ocall_sgx_CreateSemaphore_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CreateSemaphore_t);
	void *__tmp = NULL;

	ocalloc_size += (attr != NULL && sgx_is_within_enclave(attr, _len_attr)) ? _len_attr : 0;
	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CreateSemaphore_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CreateSemaphore_t));

	if (attr != NULL && sgx_is_within_enclave(attr, _len_attr)) {
		ms->ms_attr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_attr);
		memcpy(ms->ms_attr, attr, _len_attr);
	} else if (attr == NULL) {
		ms->ms_attr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_attr_len = attr_len;
	ms->ms_initcount = initcount;
	ms->ms_maxcount = maxcount;
	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy(ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_name_len = name_len;
	status = sgx_ocall(38, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ReleaseSemaphore(int* retval, int hSemaphore, long int lReleaseCount, long int* lpPreviousCount, int lp_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lpPreviousCount = lp_len;

	ms_ocall_sgx_ReleaseSemaphore_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ReleaseSemaphore_t);
	void *__tmp = NULL;

	ocalloc_size += (lpPreviousCount != NULL && sgx_is_within_enclave(lpPreviousCount, _len_lpPreviousCount)) ? _len_lpPreviousCount : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ReleaseSemaphore_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ReleaseSemaphore_t));

	ms->ms_hSemaphore = hSemaphore;
	ms->ms_lReleaseCount = lReleaseCount;
	if (lpPreviousCount != NULL && sgx_is_within_enclave(lpPreviousCount, _len_lpPreviousCount)) {
		ms->ms_lpPreviousCount = (long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpPreviousCount);
		memcpy(ms->ms_lpPreviousCount, lpPreviousCount, _len_lpPreviousCount);
	} else if (lpPreviousCount == NULL) {
		ms->ms_lpPreviousCount = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_lp_len = lp_len;
	status = sgx_ocall(39, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CryptAcquireContext(int* retval, void* prov, void* container, void* provider, unsigned long int provtype, unsigned long int dwflags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_prov = 8;
	size_t _len_container = 0;
	size_t _len_provider = 0;

	ms_ocall_sgx_CryptAcquireContext_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CryptAcquireContext_t);
	void *__tmp = NULL;

	ocalloc_size += (prov != NULL && sgx_is_within_enclave(prov, _len_prov)) ? _len_prov : 0;
	ocalloc_size += (container != NULL && sgx_is_within_enclave(container, _len_container)) ? _len_container : 0;
	ocalloc_size += (provider != NULL && sgx_is_within_enclave(provider, _len_provider)) ? _len_provider : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CryptAcquireContext_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CryptAcquireContext_t));

	if (prov != NULL && sgx_is_within_enclave(prov, _len_prov)) {
		ms->ms_prov = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_prov);
		memset(ms->ms_prov, 0, _len_prov);
	} else if (prov == NULL) {
		ms->ms_prov = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (container != NULL && sgx_is_within_enclave(container, _len_container)) {
		ms->ms_container = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_container);
		memcpy(ms->ms_container, container, _len_container);
	} else if (container == NULL) {
		ms->ms_container = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (provider != NULL && sgx_is_within_enclave(provider, _len_provider)) {
		ms->ms_provider = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_provider);
		memcpy(ms->ms_provider, provider, _len_provider);
	} else if (provider == NULL) {
		ms->ms_provider = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_provtype = provtype;
	ms->ms_dwflags = dwflags;
	status = sgx_ocall(40, ms);

	if (retval) *retval = ms->ms_retval;
	if (prov) memcpy((void*)prov, ms->ms_prov, _len_prov);

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
	status = sgx_ocall(41, ms);

	if (retval) *retval = ms->ms_retval;
	if (ret_str) memcpy((void*)ret_str, ms->ms_ret_str, _len_ret_str);

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
	
	status = sgx_ocall(42, ms);

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
	
	status = sgx_ocall(43, ms);

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
	status = sgx_ocall(44, ms);

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
	status = sgx_ocall(45, ms);

	if (proto) memcpy((void*)proto, ms->ms_proto, _len_proto);
	if (proto_name) memcpy((void*)proto_name, ms->ms_proto_name, _len_proto_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_beginthread(unsigned long long* retval, void* port, int port_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_port = port_len;

	ms_ocall_sgx_beginthread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_beginthread_t);
	void *__tmp = NULL;

	ocalloc_size += (port != NULL && sgx_is_within_enclave(port, _len_port)) ? _len_port : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_beginthread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_beginthread_t));

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
	status = sgx_ocall(46, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_endthread()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(47, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_PostQueuedCompletionStatus(int* retval, int p, unsigned int n, unsigned int key, void* o, int o_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_o = o_len;

	ms_ocall_sgx_PostQueuedCompletionStatus_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_PostQueuedCompletionStatus_t);
	void *__tmp = NULL;

	ocalloc_size += (o != NULL && sgx_is_within_enclave(o, _len_o)) ? _len_o : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_PostQueuedCompletionStatus_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_PostQueuedCompletionStatus_t));

	ms->ms_p = p;
	ms->ms_n = n;
	ms->ms_key = key;
	if (o != NULL && sgx_is_within_enclave(o, _len_o)) {
		ms->ms_o = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_o);
		memcpy(ms->ms_o, o, _len_o);
	} else if (o == NULL) {
		ms->ms_o = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_o_len = o_len;
	status = sgx_ocall(48, ms);

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
	status = sgx_ocall(49, ms);


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
	status = sgx_ocall(50, ms);

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
	status = sgx_ocall(51, ms);

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
	status = sgx_ocall(52, ms);

	if (retval) *retval = ms->ms_retval;
	if (timep) memcpy((void*)timep, ms->ms_timep, _len_timep);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ucheck_recv(int* retval, int s, char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_ucheck_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ucheck_recv_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ucheck_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ucheck_recv_t));

	ms->ms_s = s;
	ms->ms_buf = SGX_CAST(char*, buf);
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(53, ms);

	if (retval) *retval = ms->ms_retval;

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
	status = sgx_ocall(54, ms);

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
	status = sgx_ocall(55, ms);

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
	status = sgx_ocall(56, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_ucheck_send(int* retval, int s, const char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_ucheck_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_ucheck_send_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_ucheck_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_ucheck_send_t));

	ms->ms_s = s;
	ms->ms_buf = SGX_CAST(char*, buf);
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(57, ms);

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
	status = sgx_ocall(58, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_WSAGetLastError(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_WSAGetLastError_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_WSAGetLastError_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_WSAGetLastError_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_WSAGetLastError_t));

	status = sgx_ocall(59, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_SetLastError(int e)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_SetLastError_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_SetLastError_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_SetLastError_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_SetLastError_t));

	ms->ms_e = e;
	status = sgx_ocall(60, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_WSASetLastError(int e)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_WSASetLastError_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_WSASetLastError_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_WSASetLastError_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_WSASetLastError_t));

	ms->ms_e = e;
	status = sgx_ocall(61, ms);


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

sgx_status_t SGX_CDECL ocall_sgx_chsize(int* retval, int fd, long int val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_chsize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_chsize_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_chsize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_chsize_t));

	ms->ms_fd = fd;
	ms->ms_val = val;
	status = sgx_ocall(65, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_closesocket(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_closesocket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_closesocket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_closesocket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_closesocket_t));

	ms->ms_fd = fd;
	status = sgx_ocall(66, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd)
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
	status = sgx_ocall(67, ms);

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
	status = sgx_ocall(68, ms);


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
	status = sgx_ocall(69, ms);

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
	status = sgx_ocall(70, ms);

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
	status = sgx_ocall(71, ms);

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
	status = sgx_ocall(72, ms);

	if (retval) *retval = ms->ms_retval;

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
	status = sgx_ocall(74, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_locking(int* retval, int fd, int mode, long int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_locking_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_locking_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_locking_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_locking_t));

	ms->ms_fd = fd;
	ms->ms_mode = mode;
	ms->ms_num = num;
	status = sgx_ocall(75, ms);

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
	status = sgx_ocall(76, ms);

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
	status = sgx_ocall(77, ms);

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
	status = sgx_ocall(78, ms);

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
	status = sgx_ocall(79, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetNetworkParams(unsigned long int* retval, void* fixed, unsigned long int fixed_sz, unsigned long int* fixed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fixed = fixed_sz;
	size_t _len_fixed_size = 4;

	ms_ocall_sgx_GetNetworkParams_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetNetworkParams_t);
	void *__tmp = NULL;

	ocalloc_size += (fixed != NULL && sgx_is_within_enclave(fixed, _len_fixed)) ? _len_fixed : 0;
	ocalloc_size += (fixed_size != NULL && sgx_is_within_enclave(fixed_size, _len_fixed_size)) ? _len_fixed_size : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetNetworkParams_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetNetworkParams_t));

	if (fixed != NULL && sgx_is_within_enclave(fixed, _len_fixed)) {
		ms->ms_fixed = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fixed);
		memset(ms->ms_fixed, 0, _len_fixed);
	} else if (fixed == NULL) {
		ms->ms_fixed = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fixed_sz = fixed_sz;
	if (fixed_size != NULL && sgx_is_within_enclave(fixed_size, _len_fixed_size)) {
		ms->ms_fixed_size = (unsigned long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fixed_size);
		memcpy(ms->ms_fixed_size, fixed_size, _len_fixed_size);
	} else if (fixed_size == NULL) {
		ms->ms_fixed_size = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(80, ms);

	if (retval) *retval = ms->ms_retval;
	if (fixed) memcpy((void*)fixed, ms->ms_fixed, _len_fixed);
	if (fixed_size) memcpy((void*)fixed_size, ms->ms_fixed_size, _len_fixed_size);

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
	status = sgx_ocall(81, ms);

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
	
	status = sgx_ocall(82, ms);

	if (retval) *retval = ms->ms_retval;
	if (msg) memcpy((void*)msg, ms->ms_msg, _len_msg);
	if (fr) memcpy((void*)fr, ms->ms_fr, _len_fr);
	if (in_len) memcpy((void*)in_len, ms->ms_in_len, _len_in_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_SHGetSpecialFolderPathA(int* retval, HWND hwnd, char* path, int path_len, int csidl, int fCreate)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path_len;

	ms_ocall_sgx_SHGetSpecialFolderPathA_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_SHGetSpecialFolderPathA_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_SHGetSpecialFolderPathA_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_SHGetSpecialFolderPathA_t));

	ms->ms_hwnd = hwnd;
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memset(ms->ms_path, 0, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_path_len = path_len;
	ms->ms_csidl = csidl;
	ms->ms_fCreate = fCreate;
	status = sgx_ocall(83, ms);

	if (retval) *retval = ms->ms_retval;
	if (path) memcpy((void*)path, ms->ms_path, _len_path);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fputs(int* retval, const char* str, FILE* stream, int stream_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;
	size_t _len_stream = stream_size;

	ms_ocall_sgx_fputs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fputs_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;
	ocalloc_size += (stream != NULL && sgx_is_within_enclave(stream, _len_stream)) ? _len_stream : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fputs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fputs_t));

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
	
	if (stream != NULL && sgx_is_within_enclave(stream, _len_stream)) {
		ms->ms_stream = (FILE*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_stream);
		memcpy(ms->ms_stream, stream, _len_stream);
	} else if (stream == NULL) {
		ms->ms_stream = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_stream_size = stream_size;
	status = sgx_ocall(84, ms);

	if (retval) *retval = ms->ms_retval;
	if (stream) memcpy((void*)stream, ms->ms_stream, _len_stream);

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
	status = sgx_ocall(85, ms);

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
	status = sgx_ocall(86, ms);

	if (retval) *retval = ms->ms_retval;
	if (st) memcpy((void*)st, ms->ms_st, _len_st);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_mkdir(int* retval, const char* path)
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
	
	status = sgx_ocall(87, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_UnmapViewOfFile(int* retval, unsigned long long lpBaseAddress)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_UnmapViewOfFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_UnmapViewOfFile_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_UnmapViewOfFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_UnmapViewOfFile_t));

	ms->ms_lpBaseAddress = lpBaseAddress;
	status = sgx_ocall(88, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_MapViewOfFile(void** retval, int hFileMappingObject, unsigned long int dwDesiredAccess, unsigned long int dwFileOffsetHigh, unsigned long int dwFileOffsetLow, unsigned long long dwNumberOfBytesToMap)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_MapViewOfFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_MapViewOfFile_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_MapViewOfFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_MapViewOfFile_t));

	ms->ms_hFileMappingObject = hFileMappingObject;
	ms->ms_dwDesiredAccess = dwDesiredAccess;
	ms->ms_dwFileOffsetHigh = dwFileOffsetHigh;
	ms->ms_dwFileOffsetLow = dwFileOffsetLow;
	ms->ms_dwNumberOfBytesToMap = dwNumberOfBytesToMap;
	status = sgx_ocall(89, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CreateFileMapping(int* retval, int hFile, void* _null, unsigned long int flProtect, unsigned long int dwMaximumSizeHigh, unsigned long int dwMaximumSizeLow, const char* lpName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__null = 0;
	size_t _len_lpName = lpName ? strlen(lpName) + 1 : 0;

	ms_ocall_sgx_CreateFileMapping_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CreateFileMapping_t);
	void *__tmp = NULL;

	ocalloc_size += (_null != NULL && sgx_is_within_enclave(_null, _len__null)) ? _len__null : 0;
	ocalloc_size += (lpName != NULL && sgx_is_within_enclave(lpName, _len_lpName)) ? _len_lpName : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CreateFileMapping_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CreateFileMapping_t));

	ms->ms_hFile = hFile;
	if (_null != NULL && sgx_is_within_enclave(_null, _len__null)) {
		ms->ms__null = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__null);
		memcpy(ms->ms__null, _null, _len__null);
	} else if (_null == NULL) {
		ms->ms__null = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flProtect = flProtect;
	ms->ms_dwMaximumSizeHigh = dwMaximumSizeHigh;
	ms->ms_dwMaximumSizeLow = dwMaximumSizeLow;
	if (lpName != NULL && sgx_is_within_enclave(lpName, _len_lpName)) {
		ms->ms_lpName = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpName);
		memcpy((void*)ms->ms_lpName, lpName, _len_lpName);
	} else if (lpName == NULL) {
		ms->ms_lpName = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(90, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_GetFileSize(unsigned long int* retval, int hFile, unsigned long int* lpFileSizeHigh)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lpFileSizeHigh = 4;

	ms_ocall_sgx_GetFileSize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_GetFileSize_t);
	void *__tmp = NULL;

	ocalloc_size += (lpFileSizeHigh != NULL && sgx_is_within_enclave(lpFileSizeHigh, _len_lpFileSizeHigh)) ? _len_lpFileSizeHigh : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_GetFileSize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_GetFileSize_t));

	ms->ms_hFile = hFile;
	if (lpFileSizeHigh != NULL && sgx_is_within_enclave(lpFileSizeHigh, _len_lpFileSizeHigh)) {
		ms->ms_lpFileSizeHigh = (unsigned long int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpFileSizeHigh);
		memset(ms->ms_lpFileSizeHigh, 0, _len_lpFileSizeHigh);
	} else if (lpFileSizeHigh == NULL) {
		ms->ms_lpFileSizeHigh = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(91, ms);

	if (retval) *retval = ms->ms_retval;
	if (lpFileSizeHigh) memcpy((void*)lpFileSizeHigh, ms->ms_lpFileSizeHigh, _len_lpFileSizeHigh);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_CreateFile(HANDLE* retval, const char* lpFileName, unsigned long int dwDesiredAccess, unsigned long int dwShareMode, void* _null, unsigned long int dwCreationDisposition, unsigned long int dwFlagsAndAttributes, int hTemplateFile)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lpFileName = lpFileName ? strlen(lpFileName) + 1 : 0;
	size_t _len__null = 0;

	ms_ocall_sgx_CreateFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_CreateFile_t);
	void *__tmp = NULL;

	ocalloc_size += (lpFileName != NULL && sgx_is_within_enclave(lpFileName, _len_lpFileName)) ? _len_lpFileName : 0;
	ocalloc_size += (_null != NULL && sgx_is_within_enclave(_null, _len__null)) ? _len__null : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_CreateFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_CreateFile_t));

	if (lpFileName != NULL && sgx_is_within_enclave(lpFileName, _len_lpFileName)) {
		ms->ms_lpFileName = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_lpFileName);
		memcpy((void*)ms->ms_lpFileName, lpFileName, _len_lpFileName);
	} else if (lpFileName == NULL) {
		ms->ms_lpFileName = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dwDesiredAccess = dwDesiredAccess;
	ms->ms_dwShareMode = dwShareMode;
	if (_null != NULL && sgx_is_within_enclave(_null, _len__null)) {
		ms->ms__null = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__null);
		memcpy(ms->ms__null, _null, _len__null);
	} else if (_null == NULL) {
		ms->ms__null = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dwCreationDisposition = dwCreationDisposition;
	ms->ms_dwFlagsAndAttributes = dwFlagsAndAttributes;
	ms->ms_hTemplateFile = hTemplateFile;
	status = sgx_ocall(92, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_clock(long long* retval)
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

	status = sgx_ocall(93, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_fdopen(unsigned long long* retval, int fd, const char* format)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_sgx_fdopen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_fdopen_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_fdopen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_fdopen_t));

	ms->ms_fd = fd;
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(94, ms);

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
	status = sgx_ocall(95, ms);

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
	status = sgx_ocall(96, ms);

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
	status = sgx_ocall(97, ms);

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
	status = sgx_ocall(98, ms);

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
	status = sgx_ocall(99, ms);

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
	status = sgx_ocall(100, ms);

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
	status = sgx_ocall(101, ms);

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
	status = sgx_ocall(102, ms);

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
	status = sgx_ocall(103, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
