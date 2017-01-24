#include "Enclave_t.h"
#include "Enclave.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "orconfig.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctime>
#include <string.h>
#include <string>
#include <ctype.h>
#include <map>
#include "tor_main.h"
#include "tor-gencert.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "service_provider.h"
#include "network_ra.h"
#include "sgx_thread.h"
#include <list>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning ( disable:4127 )
#endif

using namespace std;

//OSVERSIONINFOA version_info;
int *out_errno = NULL;
char ***out_environ = NULL;
char *conf_root = NULL;
char *torrc = NULL;
char *out_system_dir = NULL;
//MEMORYSTATUSEX *out_mse = NULL;
//SYSTEM_INFO *out_info = NULL;

map<string, int> sgx_fileNMap;
map<int, sgx_file*> sgx_fileFMap;
int max_fd = 3;

// For eval
//#define EVAL_OCALL_COUNT
//#define EVAL_REMOTE_ATTEST_COUNT
//#define EVAL_REMOTE_ATTEST_TIME

#ifdef EVAL_REMOTE_ATTEST_COUNT
//bool is_remote_attest_start; // need modification!
int send_cnt;
int recv_cnt;
int send_byte;
int recv_byte;
#endif

#ifdef EVAL_REMOTE_ATTEST_TIME
long start_time, end_time;
double diff;
bool is_remote_attest_start;
#endif

#ifdef EVAL_OCALL_COUNT
int ocall_num;
#endif

/*
void StartTorSGX(int argc, char **argv, int argv_len, void *version, int version_size, 
		 unsigned long long  app_errno, unsigned long long app_environ,
   	 	 const char *app_conf_root, const char *app_torrc, const char *app_system_dir,								     MEMORYSTATUSEX *app_mse, SYSTEM_INFO *app_info)
*/
void StartTorSGX(int argc, char **argv, int argv_len, 
		 unsigned long long  app_errno, unsigned long long app_environ, const char *app_torrc)
{
//	memcpy(&version_info, (OSVERSIONINFOA *)version, sizeof(OSVERSIONINFOAa));
	out_errno = (int *)app_errno;
	out_environ = (char ***)app_environ;
/*
	if (app_conf_root != NULL) {
		conf_root = (char *)calloc(1, strlen(app_conf_root)+1);
		memcpy(conf_root, app_conf_root, strlen(app_conf_root)+1);
	}
*/
	if (app_torrc != NULL) {
		printf("length = %d\n", strlen(app_torrc));
		torrc = (char *)calloc(1, strlen(app_torrc)+1);
		memcpy(torrc, app_torrc, strlen(app_torrc)+1);
	}
/*
	if (app_system_dir != NULL) {
		out_system_dir = (char *)calloc(1, strlen(app_system_dir)+1);
		memcpy(out_system_dir, app_system_dir, strlen(app_system_dir)+1);
	}	

	if(app_mse != NULL) {
		out_mse = (MEMORYSTATUSEX *)calloc(1, sizeof(MEMORYSTATUSEX));
		memcpy(out_mse, app_mse, sizeof(MEMORYSTATUSEX));
	}
	if(app_info != NULL) {
		out_info = (SYSTEM_INFO *)calloc(1, sizeof(SYSTEM_INFO));
		memcpy(out_info, app_info, sizeof(SYSTEM_INFO));
	}	
*/
	printf("out_environ = %p\n", out_environ);
//	printf("conf_root = %s\n", conf_root);
//	printf("out_system_dir = %s\n", out_system_dir);

	main(argc, argv);
}

void  sgx_start_gencert(char * tor_cert, unsigned long long  app_errno, const char *month, const char *address)
{
	char *retv;
	out_errno = (int *)app_errno;
	retv = start_gencert(month, address);
	memcpy(tor_cert, retv, strlen(retv)+1);
	free(retv);
}

/*
void sgx_start_fingerprint(char *fingerprint, char *data_dir, const char *app_torrc, unsigned long long app_errno,
													 MEMORYSTATUSEX *app_mse)
*/
void sgx_start_fingerprint(char *fingerprint, char *data_dir, const char *app_torrc, unsigned long long app_errno)
//													 MEMORYSTATUSEX *app_mse)
{
	char *retv;
	out_errno = (int *)app_errno;
/*
	if(app_mse != NULL) {
		out_mse = (MEMORYSTATUSEX *)calloc(1, sizeof(MEMORYSTATUSEX));
		memcpy(out_mse, app_mse, sizeof(MEMORYSTATUSEX));
	}
*/
	torrc = (char *)calloc(1, strlen(app_torrc)+1);
	memcpy(torrc, app_torrc, strlen(app_torrc)+1);
	retv = start_do_list_fingerprint(data_dir);
	memcpy(fingerprint, retv, strlen(retv)+1);
	free(torrc);
	free(retv);
//	free(out_mse);
}

void sgx_seal_files(char *fname, void *fcont)
{
	int fd;
	sgx_file *f;
	sgx_status_t retv;
	uint32_t sealed_data_size;
	char *content;
	uint32_t content_len = 8192;
	fd = sgx_fileNMap[fname];
	f = sgx_fileFMap[fd]; 
	content = (char *)calloc(1, f->content_len);
	memcpy(content, f->content, f->content_len);
	//printf("Seal %s: %s\n", fname, content);
	sealed_data_size = sgx_calc_sealed_data_size(0, f->content_len); 

	if((retv = sgx_seal_data(0, NULL, f->content_len, (const uint8_t *)content, sealed_data_size, (sgx_sealed_data_t *)fcont)) != SGX_SUCCESS) {
		printf("Error sgx_seal_data! retv = %d\n", retv); 
	}
}

void sgx_unseal_files(char *fname, void *fcont)
{
	uint32_t content_len;
	sgx_file *new_file;
	char *content;
	content_len = 8192; 
	content = (char *)calloc(1, content_len); 
	sgx_unseal_data((const sgx_sealed_data_t *)fcont, NULL, 0, (uint8_t *)content, &content_len); 
	sgx_fileNMap[fname] = max_fd; 
	new_file = (sgx_file *)calloc(1, sizeof(sgx_file)); 
	new_file->content = (char *)realloc(content, content_len); 
	new_file->content_len = content_len; 
	new_file->seek = 0; 
	new_file->mtime = time(NULL); 
	sgx_fileFMap[max_fd] = new_file; 
	max_fd += 1;	
	//printf("Unseal %s: %s\n", fname, new_file->content);
}

// Just for debug SGX-Tor, to run faster
void test_sgx_put_gencert(char *fname, char *fcont, int fcont_len)
{
	sgx_file *new_file;
	char *content;
	content = (char *)calloc(1, fcont_len);
	memcpy(content, fcont, fcont_len);
	sgx_fileNMap[fname] = max_fd;
	new_file = (sgx_file *)calloc(1, sizeof(sgx_file));
	new_file->content = content;
	new_file->content_len = fcont_len;
	new_file->seek = 0;
	new_file->mtime = time(NULL);
	sgx_fileFMap[max_fd] = new_file;
	max_fd += 1;
	//printf("load %s len = %d\n%s\n", fname, fcont_len, content);
}

/* Remote attestation Start */
list<unsigned long *> remote_accept_list;
sgx_thread_mutex_t remote_mutex;
static sgx_thread_mutexattr_t attr_recursive;
SSL_CTX *g_ctx = NULL;
char dest_url[] = "https://test-as.sgx.trustedservices.intel.com";

int SEND(int s, void *msg, int size)
{
	int n, e;
	n = send(s, (const char *)msg, size, 0);
/*
	if (n < 0) {
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e);
		if (e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
//			sgx_Sleep(1000);
			return SEND(s, msg, size);
		}
		else {
			abort();
		}
	}
*/
	return n;
}

int RECV(int s, void *msg, int size)
{
	int n, e;
	n = recv(s, (char *)msg, size, 0);
/*
	if (n < 0) {
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e);
		if (e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
//			sgx_Sleep(1000);
			return RECV(s, msg, size);
		}
		else {
			abort();
		}
	}
*/
	return n;
}

int set_cert_key_stuff(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key,	STACK_OF(X509) *chain, int build_chain)
{
	int chflags = chain ? SSL_BUILD_CHAIN_FLAG_CHECK : 0;
	if (cert == NULL)
		return 1;
	if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
		printf("error setting certificate\n");
		return 0;
	}
	if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
		printf("error setting private key\n");
		return 0;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key\n");
		return 0;
	}
	if (chain && !SSL_CTX_set1_chain(ctx, chain)) {
		printf("error setting certificate chain\n");
		return 0;
	}
	if (build_chain && !SSL_CTX_build_cert_chain(ctx, chflags)) {
		printf("error building certificate chain\n");
		return 0;
	}
	return 1;
}

void get_ssl_context(void *sgx_cert_cont, int sgx_cert_size, void *sgx_pkey_cont, int sgx_pkey_size)
{
	const SSL_METHOD *method;

	OpenSSL_add_all_algorithms();

	if (SSL_library_init() < 0)
		printf("Could not initialize the OpenSSL library !\n");

	method = SSLv23_client_method();

	if ((g_ctx = SSL_CTX_new(method)) == NULL)
		printf("Unable to create a new SSL context structure.\n");

	BIO *tmp_cert = BIO_new_mem_buf((void *)sgx_cert_cont, sgx_cert_size);
	X509 *sgx_cert = PEM_read_bio_X509_AUX(tmp_cert, NULL, (pem_password_cb *)NULL, NULL);
	BIO_free(tmp_cert);
	if (sgx_cert == NULL) {
		printf("x is NULL\n");
		abort();
	}

	BIO *tmp_pkey = BIO_new_mem_buf((void *)sgx_pkey_cont, sgx_pkey_size);
	EVP_PKEY *sgx_pkey = PEM_read_bio_PrivateKey(tmp_pkey, NULL, (pem_password_cb *)NULL, NULL);
	BIO_free(tmp_pkey);
	if (sgx_pkey == NULL) {
		printf("unable to load key\n");
		abort();
	}

	if (!set_cert_key_stuff(g_ctx, sgx_cert, sgx_pkey, NULL, 0)) {
		printf("set_cert_key_stuff error\n");
		abort();
	}
	
	SSL_CTX_set_options(g_ctx, SSL_OP_NO_SSLv2);
}

//SOCKET create_socket(char url_str[]) {
int create_socket(char url_str[]) {
	int sockfd;
//	SOCKET sockfd;
	char hostname[256] = "";
	char    portnum[6] = "443";
	char      proto[6] = "";
	char      *tmp_ptr = NULL;
	int           port;
	struct hostent *host;
	struct sockaddr_in dest_addr;

	if (url_str[strlen(url_str)] == '/')
		url_str[strlen(url_str)] = '\0';
	strncpy(proto, url_str, (strchr(url_str, ':') - url_str));
	strncpy(hostname, strstr(url_str, "://") + 3, sizeof(hostname));
	if (strchr(hostname, ':')) {
		tmp_ptr = strchr(hostname, ':');
		strncpy(portnum, tmp_ptr + 1, sizeof(portnum));
		*tmp_ptr = '\0';
	}
	port = atoi(portnum);

	if ((host = sgx_gethostbyname(hostname)) == NULL) {
		printf("Error: Cannot resolve hostname %s.\n", hostname);
		abort();
	}

	sockfd = sgx_socket(AF_INET, SOCK_STREAM, 0);
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(port);
	dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
	memset(&(dest_addr.sin_zero), '\0', 8);

	if (sgx_connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printf("Error: Cannot connect to host %s on port %d.\n", hostname, port);
	}

	return sockfd;
}

SSL * s_connect(int sock, char * dest_url)
{
	SSL *ssl;
	int server = 0;
	if (g_ctx == NULL) {
		puts("SSL_CTX is NULL!");
		abort();
	}
	ssl = SSL_new(g_ctx);
	SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) != 1) {
		printf("Error: Could not build a SSL session to: %s.\n", dest_url);
	}
	else {
		//printf("Successfully enabled SSL/TLS session to: %s.\n", dest_url);
	}
	//printf("Finished SSL/TLS connection with server: %s.\n", dest_url);
	return ssl;
}

int get_sigrl(ra_samp_request_header_t * p_msg1_full)
{
	SSL * ssl;
	int k;
	int ret = 1;
//	SOCKET sock;
	int sock;
	char send_buf[8192], recv_buf[8192];
	sock = create_socket(dest_url);
	ssl = s_connect(sock, dest_url);
	memset(send_buf, 0, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));
	snprintf(send_buf, sizeof(send_buf), "GET /attestation/sgx/v1/sigrl/%02X%02X%02X%02X\r\n\r\n", p_msg1_full->body[67], p_msg1_full->body[66], p_msg1_full->body[65], p_msg1_full->body[64]);
	k = SSL_write(ssl, send_buf, strlen(send_buf));
	if (k < 0) {
		printf("Error!\n");
		abort();
	}
	k = SSL_read(ssl, recv_buf, 8192);
	if (k < 0) {
		printf("Error!\n");
		abort();
	}
	//printf("Received buffer = %s\n", recv_buf);

	if (strstr(recv_buf, "200 OK") != NULL) {
		//printf("Get SigRL Success!\n");
		ret = 0;
	}
	else{
		printf("Invalid EPID\n");
		ret = -1;
	}
	SSL_free(ssl);
	real_sgx_close(sock);
//	sgx_closesocket(sock);
	return ret;
}

int sgx_process_msg_all(const ra_samp_request_header_t *p_req, int p_req_size, ra_samp_response_header_t **p_resp, uint32_t p_resp_size) {
	int ret = -1;
	sgx_status_t sgx_retv;
	ra_samp_response_header_t *tmp_resp;
	if ((sgx_retv = ocall_sgx_process_msg_all(&ret, (void *)p_req, p_req_size, (void **)&tmp_resp)) != SGX_SUCCESS)	{
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
		return -1;
	}
	if (p_resp_size != 0) {
		*p_resp = (ra_samp_response_header_t *)calloc(1, p_resp_size);
		memcpy(*p_resp, tmp_resp, p_resp_size);
	}
	if ((sgx_retv = ocall_sgx_ra_free_network_response_buffer((void **)&tmp_resp)) != SGX_SUCCESS)	{
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
		return -1;
	}
	return ret;
}

void build_msg2(ra_samp_request_header_t *p_msg1_full, uint32_t msg1_full_size, ra_samp_response_header_t **p_msg2_full_return, uint32_t msg2_size)
{
	int ret = 0;

	if (NULL == p_msg1_full) {
		abort();
	}
	ret = sgx_process_msg_all(p_msg1_full, msg1_full_size, p_msg2_full_return, msg2_size);
	if (ret != 0) {
		puts("Error, process_msg_all for msg0 failed.");
		abort();
	}
	if (TYPE_RA_MSG2 != (*p_msg2_full_return)->type) {
		puts("Error, didn't get MSG2 in response to MSG1.");
		abort();
	}
}

void base64_encode(const byte* in, size_t in_len,
	char** out, size_t* out_len) {
	BIO *buff, *b64f;
	BUF_MEM *ptr;

	b64f = BIO_new(BIO_f_base64());
	buff = BIO_new(BIO_s_mem());
	buff = BIO_push(b64f, buff);

	BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
	BIO_set_close(buff, BIO_CLOSE);
	BIO_write(buff, in, in_len);
	BIO_flush(buff);

	BIO_get_mem_ptr(buff, &ptr);
	(*out_len) = ptr->length;
	(*out) = (char *)malloc(((*out_len) + 1) * sizeof(char));
	memcpy(*out, ptr->data, (*out_len));
	(*out)[(*out_len)] = '\0';

	BIO_free_all(buff);
}

int post_quote(ra_samp_request_header_t * p_msg3_full)
{
	SSL * ssl;
//	SOCKET sock;
	int sock;
	int k = -1, ret = -1;
	sock = create_socket(dest_url);
	ssl = s_connect(sock, dest_url);
	sample_ra_msg3_t *p_msg3 = (sample_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t));
	sample_quote_t *p_quote = (sample_quote_t *)p_msg3->quote;
	size_t quote_size = sizeof(sample_quote_t)+p_quote->signature_len;
	char *base64str;
	size_t base64strlen;
	char send_buf[8192], recv_buf[8192];
	char isvEnclaveQuote[4096];
	memset(send_buf, 0, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));
	memset(isvEnclaveQuote, 0, sizeof(isvEnclaveQuote));

	base64_encode((const byte *)p_quote, quote_size, &base64str, &base64strlen);
	memset(send_buf, 0, sizeof(send_buf));

	snprintf(isvEnclaveQuote, sizeof(isvEnclaveQuote), "{\"isvEnclaveQuote\":\"%s\"}", base64str);
	free(base64str);
	snprintf(send_buf, sizeof(send_buf),
		"POST /attestation/sgx/v1/report\r\n"
		"Content-Type:application/json\r\n"
		"Content-Length:%d\r\n\r\n"
		"%s"
		"\r\n\r\n",
		(int)strlen(isvEnclaveQuote), isvEnclaveQuote);
	//printf("send_buf = %s\n", send_buf);
	k = SSL_write(ssl, send_buf, strlen(send_buf));
	if (k < 0) {
		printf("Error! SSL_write\n");
		abort();
	}
	memset(recv_buf, 0, sizeof(recv_buf));
	k = SSL_read(ssl, recv_buf, 8192);
	if (k < 0) {
		printf("Error! SSL_read\n");
		abort();
	}
	//printf("QUOTE response = %s\n", recv_buf);
	if (strstr(recv_buf, "201 Created") != NULL) {
		//printf("Remote attestation success!\n");
		ret = 0;
	}
	else{
		printf("Invalid EPID\n");
		ret = -1;
	}
	SSL_free(ssl);

	real_sgx_close(sock);
//	sgx_closesocket(sock);
	return ret;
}

void build_msg4(ra_samp_request_header_t *p_msg3_full, uint32_t msg3_full_size, ra_samp_response_header_t **p_att_result_msg_full_return, uint32_t att_result_msg_size)
{
	int ret;
	sample_ra_msg3_t *p_msg3 = (sample_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t));
	sample_quote_t *p_quote = (sample_quote_t *)p_msg3->quote;
	sgx_status_t sgx_retv;
	ret = sgx_process_msg_all(p_msg3_full, msg3_full_size, p_att_result_msg_full_return, att_result_msg_size);
	if(ret != 0) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	//printf("build msg4 complete \n");
}

int remote_attest_server_port = -1;

void sgx_start_remote_attestation_server(int remote_server_port, void *sgx_cert_cont, int sgx_cert_size, 
	void *sgx_pkey_cont, int sgx_pkey_size, unsigned long given_my_ip)
{
//	SOCKET server_fd, client_fd;
	int server_fd, client_fd;
	struct sockaddr_in server_addr, client_addr;
	int client_addr_size;
	int n, ret, is_ok = 0;
	ra_samp_request_header_t *p_msg0_full = NULL;
	ra_samp_response_header_t *p_msg0_resp_full = NULL;
	ra_samp_request_header_t *p_msg1_full = NULL;
	ra_samp_response_header_t *p_msg2_full = NULL;
	ra_samp_response_header_t *p_att_result_msg_full = NULL;
	ra_samp_request_header_t *p_msg3_full = NULL;
	unsigned long *accept_ip;
	int r;
	sgx_status_t sgx_retv;

	sgx_thread_mutex_init(&remote_mutex, &attr_recursive);
	unsigned long *my_ip, *loop_back_ip;

	my_ip = (unsigned long *)calloc(1, sizeof(unsigned long));
	memcpy(my_ip, &given_my_ip, sizeof(unsigned long));
	loop_back_ip = (unsigned long *)calloc(1, sizeof(unsigned long));
	given_my_ip = 16777343; // 127.0.0.1
	memcpy(loop_back_ip, &given_my_ip, sizeof(unsigned long)); // 127.0.0.1

	sgx_thread_mutex_lock(&remote_mutex);
	remote_accept_list.push_back(my_ip);
	remote_accept_list.push_back(loop_back_ip);
	sgx_thread_mutex_unlock(&remote_mutex);

	server_fd = sgx_socket(AF_INET, SOCK_STREAM, 0);
//	if (server_fd == INVALID_SOCKET){
	if (server_fd == -1){
		puts("*** Error, invalid socket");
		abort();
	}
	remote_attest_server_port = remote_server_port;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(remote_attest_server_port);
//	if (sgx_bind(server_fd, (sockaddr *)&server_addr, sizeof (server_addr)) == SOCKET_ERROR){
	if (sgx_bind(server_fd, (sockaddr *)&server_addr, sizeof (server_addr)) == -1){
		puts("*** Error, connect");
//		sgx_closesocket(server_fd);
		real_sgx_close(server_fd);
		abort();
	}
//	if (sgx_listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
	if (sgx_listen(server_fd, SOMAXCONN) == -1) {
//		printf("listen function failed with error: %d\n", WSAGetLastError());
//		sgx_closesocket(server_fd);
		real_sgx_close(server_fd);
		abort();
	}
	printf("Listening to client connection... \n");

	while (1) {
		client_addr_size = sizeof(struct sockaddr_in);
		memset(&client_addr, 0, sizeof(client_addr));
		client_fd = sgx_accept(server_fd, (sockaddr *)&client_addr, &client_addr_size);		
		printf("Server Remote Attestation Start!\n");
		printf("Client %d is accepted!\n", ntohs(client_addr.sin_port));
#ifdef EVAL_REMOTE_ATTEST_COUNT
		is_remote_attest_start = true;
		send_cnt = 0;
		recv_cnt = 0;
		send_byte = 0;
		recv_byte = 0;
#endif
#ifdef EVAL_REMOTE_ATTEST_TIME
		is_remote_attest_start = true;
		diff = 0;
		start_time = sgx_clock();
#endif
		uint32_t msg0_full_size = sizeof(ra_samp_request_header_t)+sizeof(uint32_t);
		p_msg0_full = (ra_samp_request_header_t*)calloc(1, msg0_full_size);
		RECV(client_fd, p_msg0_full, msg0_full_size);
		ret = sgx_process_msg_all(p_msg0_full, msg0_full_size, &p_msg0_resp_full, 0);
		if (ret != 0)
		{
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
		if (ret != 0) {
			puts("Error, process_msg_all for msg0 failed.");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			//printf("\nMSG0 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}
{
		uint32_t msg1_full_size = sizeof(ra_samp_request_header_t)+sizeof(sgx_ra_msg1_t);
		uint32_t msg2_size = 168;
		uint32_t msg2_full_size;
		p_msg1_full = (ra_samp_request_header_t*)calloc(1, msg1_full_size);
		RECV(client_fd, p_msg1_full, msg1_full_size);
		get_ssl_context(sgx_cert_cont, sgx_cert_size, sgx_pkey_cont, sgx_pkey_size);
		
		ret = get_sigrl(p_msg1_full);
		if (ret != 0) {
			puts("Error, process_msg_all for msg1 failed.");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			//printf("\nMSG1 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}

		msg2_full_size = sizeof(ra_samp_response_header_t)+msg2_size;
		build_msg2(p_msg1_full, msg1_full_size, &p_msg2_full, msg2_full_size);
		SEND(client_fd, &msg2_full_size, sizeof(uint32_t));
		SEND(client_fd, p_msg2_full, msg2_full_size);
}

{
		uint32_t msg3_size = 0;
		uint32_t msg3_full_size;
		uint32_t att_result_msg_size;
		uint32_t msg4_size;

		RECV(client_fd, &msg3_size, sizeof(uint32_t));
		msg3_full_size = sizeof(ra_samp_request_header_t)+msg3_size;
		p_msg3_full = (ra_samp_request_header_t*)calloc(1, msg3_full_size);
		RECV(client_fd, p_msg3_full, sizeof(ra_samp_request_header_t)+msg3_size);
		ret = post_quote(p_msg3_full);
		if (ret != 0){
			printf("invalid quote \n");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			//printf("MSG4 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}

		att_result_msg_size = sizeof(sample_ra_att_result_msg_t);
		msg4_size = att_result_msg_size + sizeof(ra_samp_response_header_t)+8;
		build_msg4(p_msg3_full, msg3_full_size, &p_att_result_msg_full, att_result_msg_size);
		SEND(client_fd, p_att_result_msg_full, msg4_size);

		// Append to accept list if success
		accept_ip = (unsigned long *)calloc(1, sizeof(unsigned long));
		memcpy(accept_ip, &client_addr.sin_addr.s_addr, sizeof(unsigned long));

		sgx_thread_mutex_lock(&remote_mutex);
		remote_accept_list.push_back(accept_ip);
		sgx_thread_mutex_unlock(&remote_mutex);
}
	err:
		if(p_msg0_full != NULL)		sgx_free(p_msg0_full);
		if(p_msg0_resp_full != NULL)	sgx_free(p_msg0_resp_full);
		if(p_msg1_full != NULL)		sgx_free(p_msg1_full);
		if(p_msg2_full != NULL)		sgx_free(p_msg2_full);
		if(p_msg3_full != NULL)		sgx_free(p_msg3_full);
		if(p_att_result_msg_full != NULL)	sgx_free(p_att_result_msg_full);


		if (g_ctx != NULL) {
			SSL_CTX_free(g_ctx);
			g_ctx = NULL;
		}
		real_sgx_close(client_fd);
//		sgx_closesocket(client_fd);	
		#ifdef EVAL_REMOTE_ATTEST_TIME
				is_remote_attest_start = false;
				if (is_remote_attest_start) {
					end_time = sgx_clock();
					diff += (end_time - start_time) / (double)1000;
				}
				printf("Time for remote attestation : %lf\n", diff);
		#endif
		#ifdef EVAL_REMOTE_ATTEST_COUNT
				is_remote_attest_start = false;
				printf("Count: send = %d, recv = %d\nBytes: send = %d bytes, recv = %d bytes\n", send_cnt, recv_cnt, send_byte, recv_byte);
		#endif
	}
	sgx_thread_mutex_destroy(&remote_mutex);

	real_sgx_close(server_fd);
//	sgx_closesocket(server_fd);

}

/*
unsigned sgx_GetSystemDirectory(char *lpBuffer, unsigned int uSize)
{
	unsigned retv = strlen(out_system_dir);
	memcpy(lpBuffer, out_system_dir, retv+1);
	return retv;
}

int sgx_SHGetSpecialFolderPathA(HWND hwnd, char *path, int csidl, int fCreate)
{
	memcpy(path, out_system_dir, strlen(out_system_dir)+1);
	return 1;
}

int sgx_GlobalMemoryStatusEx(MEMORYSTATUSEX *mse)
{
	int retv = 0;
	if(out_mse == NULL) {
		printf("Error! app_mse is NULL!\n");
		abort();
	}
	memcpy(mse, out_mse, sizeof(MEMORYSTATUSEX));
	retv = 1;
	return retv;
}

unsigned long sgx_GetVersion(void)
{
	unsigned long retv;
	retv = version_info.dwBuildNumber << 16 | version_info.dwMinorVersion << 8 | version_info.dwMajorVersion;
	return retv;
}

int sgx_GetVersionEx(OSVERSIONINFOA* info)
{
	memcpy(info, &version_info, sizeof(OSVERSIONINFOA));
	return 1;
}
*/

// Not OCALL, but multi_thread uses multiple errno address, how to handle this?
// However, Tor seems only call errno from main thread.
int * _errno(void)
{
	return out_errno;
}

char ***sgx_environ(void)
{
	return out_environ;
}

int sscanf(const char *str, const char *format, ...)
{
	int val_cnt = 0;
	va_list args;
	va_start(args, format);
	for ( ; *format != '\0'; format++) {
		if (*format == '%' && format[1] == 'd') {
			int positive;
			int value;
			int *valp;
			
			if (*str == '-') {
				positive = 0;
				str++;
			} else
				positive = 1;
			if (!isdigit(*str))
				break;
			value = 0;
			do {
				value = (value * 10) - (*str - '0');
				str++;
			} while (isdigit(*str));
			if (positive)
				value = -value;
			valp = va_arg(args, int *);
			val_cnt++;
			*valp = value;
			format++;
		} 
		else if (*format == '%' && format[1] == 'c') {
			char value;
			char *valp;

			if (!isalpha(*str))
				break;
			value = *str;
			str++;
			valp = va_arg(args, char *);
			val_cnt++;
			*valp = value;
			format++;
		} 
		else if (*format == *str) {
			str++;
		}
		else {
			break;
		}
	}
	va_end(args);
	return val_cnt;
}

int sgx_vsnprintf(char *s1, size_t n, const char *s2, __va_list v)
{
	vsnprintf(s1,n,s2,v);
	return 0;
}

char *sgx_get_windows_conf_root(void)
{
	return conf_root;
}

/*
char *strdup(const char *str)
{
	char *retv = strndup(str, strlen(str));
	if (retv == NULL)
	{
		printf("Error: strdup, errno = %d\n", sgx_errno);
	}
	return retv;
}
*/

/*
char *real_strdup(const char *str)
{
  char *retv;
  ocall_sgx_strdup(&retv, str);
  return retv;
}
*/

char *_strdup(const char* s)
{
	return strdup(s);
}

/* strcasecmp, strncasecmp: from apple */
typedef unsigned char u_char;
static const u_char charmap[] = {
	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
	'\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
	'\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
	'\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
	'\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
	'\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
	'\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
	'\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
	'\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
	'\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
};

int
strcasecmp(const char *s1, const char *s2)
{
	register const u_char *cm = charmap,
			*us1 = (const u_char *)s1,
			*us2 = (const u_char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*--us2]);
}

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (n != 0) {
		register const u_char *cm = charmap,
				*us1 = (const u_char *)s1,
				*us2 = (const u_char *)s2;

		do {
			if (cm[*us1] != cm[*us2++])
				return (cm[*us1] - cm[*--us2]);
			if (*us1++ == '\0')
				break;
		} while (--n != 0);
	}
	return (0);
}

long sgx_rand(void)
{
	long retv;
	sgx_read_rand((unsigned char*)&retv, sizeof(retv));
	return retv;
}

char *sgx_get_torrc(void)
{
	return torrc;
}

/*
int sgx_WSAIoctl(int s, unsigned long dwIoControlCode,
	void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer,
	unsigned long cbOutBuffer, unsigned long *lpcbBytesReturned,
	void *lpOverlapped, void *LPWSAOVERLAPPED_COMPLETION_ROUTINE)
{
	// This function not never called? (LibEvent)
	abort(); // For debug purpose
	return 0;
}
*/

sgx_file *sgx_get_file(const char *pathname)
{
	int fd;
	if(sgx_fileNMap.find(pathname) == sgx_fileNMap.end()) {
		printf("sgx_get_file: Error! %s not exist!\n", pathname);
		errno = ENOENT;
		return NULL;
	}
	fd = sgx_fileNMap[pathname];
	if(sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		printf("sgx_get_file: Error! %s not exist!\n", pathname);
		errno = ENOENT;
		return NULL;
	}
	return sgx_fileFMap[fd];
}

sgx_file *sgx_fdopen(int fd, const char *format)
{
	// format is "a" or "ba"
	sgx_file *f = NULL;
	if(sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		printf("sgx_fdopen: Error! file (map) not exist!\n");
		abort();
	}
	else {
		f = sgx_fileFMap[fd];
		f->seek = f->content_len;
	}
	return f;
}

int sgx_fputs(const char *str, sgx_file *f)
{
	if(f == NULL || str == NULL) {
		printf("sgx_fputs: Error! sgx_fputs: wrong arguments (NULL)\n");
		return -1;
	}
	int retv = -1;
	long seek = f->seek;
	long content_len = f->content_len;
	long n = strlen(str);
	long mem_size = f->content_len > n + seek ? f->content_len : n + seek;	
	char *new_cont = (char *)sgx_calloc(1, mem_size);
	if (f->content != NULL) {
		int remain = content_len - seek - n;
		remain = remain > 0 ? remain : 0;
		memcpy(new_cont, f->content, seek);
		memcpy(new_cont+seek, str, n);			
		memcpy(new_cont+seek+n, f->content, remain);
		f->content_len = seek+n+remain;	
		f->seek = seek+n;
		sgx_free(f->content);
		f->content = new_cont;
	}
	else {
		memcpy(new_cont, str, n);
		f->content_len = n;
		f->seek = n;
		f->content = new_cont;
	}	
	f->mtime = time(NULL);
	retv = n;
	return retv;
}

sgx_file *sgx_fopen(const char *fname, const char *mode)
{
	// mode is always "r"
	if(sgx_fileNMap.find(fname) == sgx_fileNMap.end()) {
		printf("sgx_fopen: Error! %s not exist!\n", fname);
		errno = ENOENT;
		return NULL;
	}
	if(strcmp(mode, "r") != 0) {
		printf("Error! unexpected mdoe! => %s (not implement other modes)\n", mode);
		return NULL;
	}
	int fd = sgx_fileNMap[fname];
	sgx_file *f = sgx_fileFMap[fd];
	return f;
}

int sgx_fclose(sgx_file *f)
{
	f->seek = 0;
	return 0;
}

int sgx_open(const char *pathname, int flags, unsigned mode)
{
	int is_create = flags & O_CREAT, is_append = flags & O_APPEND, is_trunc = flags & O_TRUNC;
	int retv = -1;
	int is_private = mode > 0 ? 0 : 1;
	
	printf("TRY open: fname: %s is private? %d\n", pathname, is_private);
	
	if(sgx_fileNMap.find(pathname) == sgx_fileNMap.end()) {
		if (is_create) {
			sgx_fileNMap[pathname] = max_fd;
			sgx_file *new_file = (sgx_file *)calloc(1, sizeof(sgx_file));
			new_file->content = NULL;
			new_file->content_len = 0;
			new_file->seek = 0;
			new_file->mtime = time(NULL);
			new_file->is_private = is_private;
			sgx_fileFMap[max_fd] = new_file;
			retv = max_fd;
			max_fd += 1;	
			printf("******* max_fd = %d *******\n", max_fd);
			if (!is_private) {
				printf("non private file!\n");
			}
		}
		else {
			printf("sgx_open: Error! %s not exist!\n", pathname);
			errno = ENOENT;
			return -1;
		}
	}
	else {
		retv = sgx_fileNMap[pathname];
		sgx_file *f = sgx_fileFMap[retv];
		if (is_trunc) {
			sgx_free(f->content);
			f->content = NULL;
			f->content_len = 0;
			f->seek = 0;
			f->mtime = time(NULL);
			f->is_private = is_private;
		}
		if (is_append) {
			f->seek = f->content_len;
		}
		else {
			f->seek = 0;
		}
	}
	printf("Success! file opend!\n");
	return retv;
}

off_t sgx_lseek(int fildes, off_t offset, int whence)
{
	off_t retv = -1;
	if(sgx_fileFMap.find(fildes) == sgx_fileFMap.end()) {
		printf("sgx_lseek: Error! file (map) not exist!\n");
		abort();
	}
	else {
		sgx_file *f = sgx_fileFMap[fildes];
		switch(whence) {
			case SEEK_SET:
				f->seek = offset;
				break;
			case SEEK_CUR:
				f->seek += offset;
				break;
			case SEEK_END:
				f->seek = f->content_len + offset;
				break;
			default:
				printf("sgx_lseek: Error! unknown flag\n");
				abort();
				break;
		}
		retv = f->seek;
	}
	return retv;
}

int sgx_write(int fd, const void *buf, int n)
{
	int retv = -1;
	if (buf == NULL){
		printf("sgx_write: Error write!: buf == NULL!!, n = %d\n", n);
		abort();
	}
	if(fd == 1 || fd == 2) {
		printf("%s", buf);
		return n;
	}
	if(sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		printf("sgx_write: Error! file (map) not exist!\n");
		abort();
	}
	else {
		sgx_file *f = sgx_fileFMap[fd];
		long seek = f->seek;
		long content_len = f->content_len;
		long mem_size = f->content_len > n + seek ? f->content_len : n + seek;
		printf("~~WRITE~~ private? %d, memsize = %d\n", f->is_private, mem_size);
		char *new_cont;
		if(f->is_private) {
			new_cont = (char *)calloc(1, mem_size);
		}
		else {
			new_cont = (char *)sgx_calloc(1, mem_size);
		}
		if (f->content != NULL) {
			int remain = content_len - seek - n;
			remain = remain > 0 ? remain : 0;
			memcpy(new_cont, f->content, seek);
			memcpy(new_cont+seek, buf, n);			
			memcpy(new_cont+seek+n, f->content, remain);
			f->content_len = seek+n+remain;	
			f->seek = seek+n;
			sgx_free(f->content);
			f->content = new_cont;
		}
		else {
			memcpy(new_cont, buf, n);
			f->content_len = n;
			f->seek = n;
			f->content = new_cont;
		}	
		f->mtime = time(NULL);		
		retv = n;
	}
	return retv;
}

int sgx_read(int fd, void *buf, int n)
{
	int retv = -1;
	if(sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		printf("sgx_read: Error! file (map) not exist!\n");
		abort();
	}
	else {
		sgx_file *f = sgx_fileFMap[fd];
		if (f->content != NULL) {
			memcpy(buf, f->content+f->seek, n);
		}
		else {
			printf("sgx_read: Error read!: content == NULL!!\n");
			abort();
		}
		retv = n;
	}
	return retv;
}

int sgx_stat(const char * _Filename, struct stat * _Stat)
{
	int fd;
	if (sgx_fileNMap.find(_Filename) == sgx_fileNMap.end()) {
		printf("sgx_stat: Error! %s not exist!\n", _Filename);
		errno = ENOENT;
		return -1;
	}

	fd = sgx_fileNMap[_Filename];
	sgx_file *f = sgx_fileFMap[fd];
	_Stat->st_mtime = f->mtime;
	_Stat->st_size = f->content_len;
	_Stat->st_mode = _S_IFREG;

	return 0;
}

int sgx_fstat(int fd, struct stat *_Stat)
{
	if (sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		printf("sgx_fstat: Error! file (map) not exist!\n");
		abort();
	}

	sgx_file *f = sgx_fileFMap[fd];
	_Stat->st_mtime = f->mtime;
	_Stat->st_size = f->content_len;
	_Stat->st_mode = _S_IFREG;

	return 0;
}

int sgx_rename(const char *from, const char *to)
{
	int fd;
	if (sgx_fileNMap.find(from) == sgx_fileNMap.end()) {
		printf("sgx_rename: Error! %s not exist!\n", from);
		errno = ENOENT;
		return -1;
	}
	if (sgx_fileNMap.find(to) != sgx_fileNMap.end()) {
		printf("sgx_rename: Error! %s not exist!\n", to);
		errno = ENOENT;
		return -1;
	}

	fd = sgx_fileNMap[from];
	sgx_fileNMap.erase(from);
	sgx_fileNMap[to] = fd;

	return 0;
}

int sgx_unlink(const char *to)
{
	int fd;
	if (sgx_fileNMap.find(to) == sgx_fileNMap.end()) {
		printf("sgx_unlink: Error! %s not exist!\n", to);
		errno = ENOENT;
		return -1;
	}
	fd = sgx_fileNMap[to];
	sgx_file *f = sgx_fileFMap[fd];
	sgx_fileFMap.erase(fd);
	sgx_fileNMap.erase(to);
	if(f->content != NULL)
		sgx_free(f->content);
	f->content = NULL;
	free(f);
	return 0;
}

/*
int sgx_locking(int _FileHandle, int _LockMode, long _NumOfBytes)
{
	// Do nothing
	return 0;
}
*/

int sgx_close(int fd)
{
	if (sgx_fileFMap.find(fd) == sgx_fileFMap.end()) {
		return -1;
	}
	sgx_file *f = sgx_fileFMap[fd];
	f->seek = 0;
	return 0;
}

#if BYTE_ORDER == BIG_ENDIAN

#define HTONS(n) (n)
#define NTOHS(n) (n)
#define HTONL(n) (n)
#define NTOHL(n) (n)

#else

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif

unsigned short sgx_htons(unsigned short hostshort)
{
	return HTONS(hostshort);
}

unsigned long sgx_htonl(unsigned long hostlong)
{
	return HTONL(hostlong);
}

unsigned short sgx_ntohs(unsigned short netshort)
{
	return NTOHS(netshort);
}

unsigned long sgx_ntohl(unsigned long netlong)
{
	return NTOHL(netlong);
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define X(x) x
#else
#define X(x) (((x)/256 | (x)*256) % 65536)
#endif

static const unsigned short table[] = {
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
X(0x200),X(0x320),X(0x220),X(0x220),X(0x220),X(0x220),X(0x200),X(0x200),
X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
X(0x160),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),
X(0x8d8),X(0x8d8),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
X(0x4c0),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8c5),
X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
X(0x8c5),X(0x8c5),X(0x8c5),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
X(0x4c0),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8c6),
X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
X(0x8c6),X(0x8c6),X(0x8c6),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x200),
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static const unsigned short *const ptable = table+128;

const unsigned short **__ctype_b_loc(void)
{
	return (const unsigned short **)&ptable;
//	return (void *)&ptable;
}

static const int32_t table2[] = {
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
64,
'a','b','c','d','e','f','g','h','i','j','k','l','m',
'n','o','p','q','r','s','t','u','v','w','x','y','z',
91,92,93,94,95,96,
'a','b','c','d','e','f','g','h','i','j','k','l','m',
'n','o','p','q','r','s','t','u','v','w','x','y','z',
123,124,125,126,127,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static const int32_t *const ptable2 = table2+128;

const int32_t **__ctype_tolower_loc(void)
{
    return (const int32_t **)&ptable2;
}

void *chk_fail_buf[256] __attribute__((aligned (16)));
volatile int chk_fail_allowed, chk_calls;
volatile int memcpy_disallowed, mempcpy_disallowed, memmove_disallowed;
volatile int memset_disallowed, strcpy_disallowed, stpcpy_disallowed;
volatile int strncpy_disallowed, strcat_disallowed, strncat_disallowed;
volatile int sprintf_disallowed, vsprintf_disallowed;
volatile int snprintf_disallowed, vsnprintf_disallowed;

void __attribute__((noreturn))
__chk_fail (void)
{
  if (chk_fail_allowed)
    __builtin_longjmp (chk_fail_buf, 1);
  abort ();
}

long int
__fdelt_chk (long int d)
{
  if (d < 0 || d >= FD_SETSIZE)
    __chk_fail ();
  return d / __NFDBITS;
}

void *
__memcpy_chk (void *__restrict__ dest, const void *__restrict__ src,
              size_t len, size_t slen)
{
  if (len > slen)
    __chk_fail ();
  return memcpy (dest, src, len);
}

void *
__memset_chk (void *dest, int val, size_t len, size_t slen)
{
  if (len > slen)
    __chk_fail ();
  return memset (dest, val, len);
}

/*
static inline uint32_t __builtin_bswap32(uint32_t x)
{
	return ((x << 24) & 0xff000000) |
	       ((x <<  8) & 0x00ff0000) |
	       ((x >>  8) & 0x0000ff00) |
	       ((x >> 24) & 0x000000ff);
}

#define __bswap_16(x) ((unsigned short)(__builtin_bswap32(x) >> 16))
#define __bswap_32(x) ((unsigned int)__builtin_bswap32(x))

unsigned short sgx_htons(unsigned short hostshort)
{
#if BYTE_ORDER == BIG_ENDIAN
	return hostshort;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return __bswap_16(hostshort);
#endif
}

unsigned long sgx_htonl(unsigned long hostlong)
{
#if BYTE_ORDER == BIG_ENDIAN
	return hostlong;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return __bswap_32(hostlong);
#endif
}

unsigned short sgx_ntohs(unsigned short netshort)
{
#if BYTE_ORDER == BIG_ENDIAN
	return netshort;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return __bswap_16(netshort);
#endif
}

unsigned long sgx_ntohl(unsigned long netlong)
{
#if BYTE_ORDER == BIG_ENDIAN
	return netlong;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return __bswap_32(netlong);
#endif
}
*/

/*
void sgx_GetSystemInfo(SYSTEM_INFO *info)
{
	memcpy(info, out_info, sizeof(SYSTEM_INFO));
}
*/

char *sgx_getenv(const char *env)
{
	// SGX: LibEvent checks env in "evutil_getenv", but we will not support this.
	return NULL;
}

/*
void sgx_endthread(void)
{
	// Do nothing
}
*/

void sgx_pthread_exit(void *retval)
{
	// Do nothing
}

void sgx_exit(int exit_status)
{
	printf("sgx_exit: exit(%d) called!\n",exit_status);
	abort(); // SGX: just for debug purpose.
	//ocall_sgx_exit(exit_status);
}

int sgx_epoll_create(int size)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_epoll_create(&retv, size)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_epoll_ctl(int epfd, int op, int fd, void *event)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_epoll_ctl(&retv, epfd, op, fd, event, sizeof(struct epoll_event))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;

}

int sgx_epoll_wait(int epfd, void *events, int maxevents, int timeout)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_epoll_wait(&retv, epfd, events, sizeof(struct epoll_event), maxevents, timeout)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

// ------------------------------------------------------------------------//
//  ------------------------- Necessary OCALL START  --------------------- //
// ------------------------------------------------------------------------//
//1
/*
unsigned long sgx_TlsAlloc(void)
{
	unsigned long retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_TlsAlloc(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/
//2
/*
int sgx_CryptAcquireContext(void *prov, void *container, void *provider, unsigned long provtype, unsigned long dwflags)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_CryptAcquireContext(&retv, prov, container, provider, provtype, dwflags)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//3
int sgx_CryptGenRandom(unsigned long long prov, int buf_len, unsigned char *buf)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_CryptGenRandom(&retv, prov, buf_len, buf)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/
//37
/*
int sgx_CryptReleaseContext(unsigned long long hProv, unsigned long dwFlags)
{
	int retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_CryptReleaseContext(&retv, hProv, dwFlags)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/
static void (* cur_fn) (void *) = NULL;
//4
// OCALL make thread and call enclave function

int sgx_pthread_create(void (*fn)(void *), int num, void *port, int port_len)
{
	int retv;
	cur_fn = fn;
	sgx_status_t sgx_retv;

	if((sgx_retv = ocall_sgx_pthread_create(&retv, port, port_len)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

/*
unsigned long long sgx_beginthread(void (*fn)(void *), int num, void *port, int port_len)
{
	unsigned long long th;
	cur_fn = fn;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_beginthread(&th, port, port_len)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return th;
}
*/
// ECALL make thread and call enclave function
void enclave_func_caller(void *args, int args_len)
{
	if(cur_fn != NULL) {
		cur_fn(args);
	}
	else {
		printf("enclave_func_caller: cur_fn is NULL!!\n");
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
}
//5
/*
unsigned long sgx_GetAdaptersAddresses(unsigned long family, unsigned long flags, 
				IP_ADAPTER_ADDRESSES * addresses, unsigned long *psize)
{
	unsigned long retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_GetAdaptersAddresses(&retv, family, flags, (void *)addresses, *psize, psize)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return retv;
}
*/
//6
/*
unsigned long sgx_GetNetworkParams(void *fixed, unsigned long *fixed_size)
{
	unsigned long retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_GetNetworkParams(&retv, fixed, *fixed_size, fixed_size)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	if(retv != ERROR_SUCCESS) {
		return retv;
	}	
	IP_ADDR_STRING *ns = &(((FIXED_INFO *)fixed)->DnsServerList);
	if(ns->Next != NULL) {
		IP_ADDR_STRING *head = (IP_ADDR_STRING *)calloc(1, sizeof(IP_ADDR_STRING));
		IP_ADDR_STRING *cur = head;	
		while((ns = ns->Next) != NULL)
		{
			memcpy(cur, ns, sizeof(IP_ADDR_STRING));
			if(ns->Next != NULL) {
				cur->Next = (IP_ADDR_STRING *)calloc(1, sizeof(IP_ADDR_STRING));
				cur = cur->Next;
			}
		}	
		ns = &(((FIXED_INFO *)fixed)->DnsServerList);
		ns->Next = head;
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/

//7
int sgx_socket(int af, int type, int protocol)
{
		int retv;
		sgx_status_t sgx_retv;
		if((sgx_retv = ocall_sgx_socket(&retv, af, type, protocol)) != SGX_SUCCESS){
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

		return retv;
}

int sgx_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_clock_gettime(&retv, clk_id, tp, sizeof(struct timespec))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_gettimeofday(struct timeval *tv)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_gettimeofday(&retv, tv, sizeof(struct timeval))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//8
int sgx_select(int nfds, void *rfd, void *wfd,  void *efd, int fd_size, struct timeval *timeout)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_select(&retv, nfds, rfd, wfd, efd, fd_size, timeout, sizeof(struct timeval))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_poll(void *fds, int fd_size, int nfds, int timeout)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_poll(&retv, fds, fd_size, nfds, timeout)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//9
//int sgx_accept(int s, struct sockaddr *addr, int *addrlen)
int sgx_accept(int s, struct sockaddr *addr, int *addrlen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_accept(&retv, s, addr, sizeof(struct sockaddr), addrlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	sockaddr_in *addr_in = (sockaddr_in *)addr;

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//10
int sgx_bind(int s, const struct sockaddr *addr, int addrlen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_bind(&retv, s, addr, addrlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//11
int sgx_listen(int s, int backlog)
{
		int retv;
		sgx_status_t sgx_retv;
		if((sgx_retv = ocall_sgx_listen(&retv, s, backlog)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

		return retv;
}
//12
int sgx_connect(int s, const struct sockaddr *addr, int addrlen)
{
	int retv;
	sgx_status_t sgx_retv;
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		end_time = sgx_clock();
		diff += (end_time - start_time) / (double)1000;
	}
#endif
	if((sgx_retv = ocall_sgx_connect(&retv, s, addr, addrlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		start_time = sgx_clock();
	}
#endif
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//13
/*
int sgx_ioctlsocket(int s, long cmd, unsigned long *argp)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_ioctlsocket(&retv, s, cmd, argp, sizeof(unsigned long))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/

int sgx_getaddrinfo(const char *node, const char *service, const void *hints, void **res)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getaddrinfo(&retv, node, service, hints, sizeof(struct addrinfo), res, sizeof(struct addrinfo *))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

void sgx_freeaddrinfo(void *res)
{
}

//14
int sgx_getsockname(int s,  struct sockaddr *name, int *namelen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getsockname(&retv, s, name, *namelen, namelen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_socketpair(int domain, int type, int protocol, int *sv)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_socketpair(&retv, domain, type, protocol, sv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//15
//int sgx_getsockopt(int s, int level, int optname, char *optval, int* optlen)
int sgx_getsockopt(int s, int level, int optname, char *optval, int* optlen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getsockopt(&retv, s, level, optname, optval, *optlen, optlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//16
int sgx_setsockopt(int s, int level, int optname, const char *optval, int optlen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setsockopt(&retv, s, level, optname, optval, optlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//17
int sgx_recv(int s, char *buf, int len, int flags)
{	
	int retv;
	sgx_status_t sgx_retv;
	/* // TEST
	if (sgx_is_within_enclave(buf, len) == 0) { // App memory
		char *tmp_buf = (char *)calloc(1, len);
		if (tmp_buf == NULL) {
			printf("Out of memory: sgx_recv\n");
			abort();
		}
		memcpy(tmp_buf, buf, len);
		if ((sgx_retv = ocall_sgx_recv(&retv, s, tmp_buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
		memcpy(buf, tmp_buf, len);
		free(tmp_buf);
	}
	*/
	if (sgx_is_within_enclave(buf, len) == 0) { // App memory
		if ((sgx_retv = ocall_sgx_direct_recv(&retv, s, (unsigned long long)buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
	}
	else {
#ifdef EVAL_REMOTE_ATTEST_TIME
		if (is_remote_attest_start) {
			end_time = sgx_clock();
			diff += (end_time - start_time) / (double)1000;
		}
#endif
		if ((sgx_retv = ocall_sgx_recv(&retv, s, buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
#ifdef EVAL_REMOTE_ATTEST_COUNT
		if (is_remote_attest_start) {
			recv_cnt++;
			recv_byte += retv;
		}
#endif
#ifdef EVAL_REMOTE_ATTEST_TIME
		if (is_remote_attest_start) {
			start_time = sgx_clock();
		}
#endif
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//18
int sgx_send(int s, const char *buf, int len, int flags)
{
	int retv;
	sgx_status_t sgx_retv;
	/*
	if (sgx_is_within_enclave(buf, len) == 0) { // App memory
		char *tmp_buf = (char *)calloc(1, len);
		if (tmp_buf == NULL) {
			printf("Out of memory: sgx_send\n");
			abort();
		}
		memcpy(tmp_buf, buf, len);
		if ((sgx_retv = ocall_sgx_send(&retv, s, tmp_buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
		free(tmp_buf);
	}
*/
	if (sgx_is_within_enclave(buf, len) == 0) { // App memory
		if ((sgx_retv = ocall_sgx_direct_send(&retv, s, (unsigned long long)buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
	}
	else {
#ifdef EVAL_REMOTE_ATTEST_TIME
		if (is_remote_attest_start) {
			end_time = sgx_clock();
			diff += (end_time - start_time) / (double)1000;
		}
#endif
		if ((sgx_retv = ocall_sgx_send(&retv, s, buf, len, flags)) != SGX_SUCCESS) {
			printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
			abort();
		}
#ifdef EVAL_REMOTE_ATTEST_COUNT
		if (is_remote_attest_start) {
			send_cnt++;
			send_byte += retv;
		}
#endif
#ifdef EVAL_REMOTE_ATTEST_TIME
		if (is_remote_attest_start) {
			start_time = sgx_clock();
		}
#endif
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//19
int sgx_sendto(int s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sendto(&retv, s, msg, len, flags, to, tolen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//20
//int sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int *in_len)
int sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int *in_len)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_recvfrom(&retv, s, msg, len, flags, fr, *in_len, in_len)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//21
/*
int sgx_closesocket(int s)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_closesocket(&retv, s)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
*/
//22
/*
int sgx_GetLastError(void)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_GetLastError(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//23
void sgx_SetLastError(int e)
{
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_SetLastError(e)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

}
//24
int sgx_WSAGetLastError(void)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_WSAGetLastError(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//25
void sgx_WSASetLastError(int e)
{
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_WSASetLastError(e)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

}
*/

unsigned int sgx_getegid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getegid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

unsigned int sgx_geteuid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_geteuid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//26
unsigned int sgx_getgid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getgid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//26
unsigned int sgx_getuid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getuid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_dup2(int oldfd, int newfd)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_dup2(&retv, oldfd, newfd)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_setgroups(size_t size, const unsigned int *list, int list_num)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setgroups(&retv, size, list, list_num)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_getgroups(int size, unsigned int *list, int list_num)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getgroups(&retv, size, list, list_num)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

unsigned int sgx_waitpid(unsigned int pid, int *_status, int status_len, int options)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_waitpid(&retv, pid, _status, status_len, options)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_setegid(unsigned int gid)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setegid(&retv, gid)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_setgid(unsigned int gid)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setgid(&retv, gid)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_seteuid(unsigned int uid)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_seteuid(&retv, uid)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_setuid(unsigned int uid)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setuid(&retv, uid)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

unsigned int sgx_setsid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_setsid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//26
unsigned int sgx_getpid(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_getpid(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//27
int sgx_gethostname(char *name, size_t namelen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_gethostname(&retv, name, namelen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//28
time_t sgx_time(time_t *timep)
{
	time_t retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_get_time(&retv, timep, sizeof(time_t))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//29
struct tm * sgx_localtime(const time_t *timep)
{
	struct tm* retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_localtime(&retv, timep, sizeof(time_t))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//30
struct tm * sgx_gmtime(const time_t *timep)
{
	struct tm* retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_gmtime(&retv, timep, sizeof(time_t))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//31
time_t sgx_mktime(struct tm *timeptr)
{
	time_t r;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_mktime(&r, timeptr, sizeof(struct tm))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return r;
}
//32
//void sgx_ftime(struct _timeb *tb, int sizetb)
void sgx_ftime(struct timeb *tb, int sizetb)
{
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_ftime(tb, sizetb)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

}
//33
/*
void sgx_GetSystemTimeAsFileTime(FILETIME *ft)
{
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_GetSystemTimeAsFileTime(ft, sizeof(FILETIME))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

}
*/

//34
struct hostent *sgx_gethostbyname(const char *name)
{
	struct hostent *ent;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_gethostbyname(&ent, name)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return ent;
}

//36
void sgx_free(void *ptr)
{
	if(sgx_is_outside_enclave(ptr, 1))
		ocall_sgx_free((unsigned long long)ptr);
	else {
		free(ptr);
	}	

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

}

int sgx_check_remote_accept_list(unsigned long ip)
{
	int found = -1, cnt = 1;
	unsigned long cur_ip;
	if (remote_attest_server_port == -1) {
		// Remote attestation not set. Return true
		return 0;
	}
	sgx_thread_mutex_lock(&remote_mutex);
	if (remote_accept_list.empty()) {
		printf("Remote accept list is empty!\n");
	}
	else {
		printf("Searching IP = %u.%u.%u.%u\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
		list<unsigned long *>::iterator iter;
		for (iter = remote_accept_list.begin(); iter != remote_accept_list.end(); iter++) {
			cur_ip = **iter;
			printf("IP list[%d] = %u.%u.%u.%u\n", cnt++, cur_ip & 0xFF, (cur_ip >> 8) & 0xFF, (cur_ip >> 16) & 0xFF, (cur_ip >> 24) & 0xFF);
			if (cur_ip == ip) {
				printf("Found in remote accept list!\n");
				found = 0;
				break;
			}
		}
	}
	sgx_thread_mutex_unlock(&remote_mutex);
	return found;
}

// For eval, clock
long sgx_clock(void)
{
	long retv;
	ocall_sgx_clock(&retv);
	return retv;
}

void sgx_get_current_time(struct timeval *t)
{
	struct timeval tt;
	sgx_gettimeofday(&tt);

	t->tv_sec = tt.tv_sec;
	t->tv_usec = tt.tv_usec;
}

#if 0
/* Not need new OCALL, just use "sgx_GetSystemTimeAsFileTime" */
void sgx_get_current_time(struct timeval *t)
{
// [Notice] (tor_gettimeofday) used by OpenSSL  function
#define U64_LITERAL(n) (n ## ui64)
#define EPOCH_BIAS U64_LITERAL(116444736000000000)
#define UNITS_PER_SEC U64_LITERAL(10000000)
#define USEC_PER_SEC U64_LITERAL(1000000)
#define UNITS_PER_USEC U64_LITERAL(10)
  union {
    uint64_t ft_64;
    FILETIME ft_ft;
  } ft;
  /* number of 100-nsec units since Jan 1, 1601 */
  sgx_GetSystemTimeAsFileTime(&ft.ft_ft);
  if (ft.ft_64 < EPOCH_BIAS) {
    log_err(LD_GENERAL,"System time is before 1970; failing.");
    exit(1);
  }
  ft.ft_64 -= EPOCH_BIAS;
  t->tv_sec = (unsigned) (ft.ft_64 / UNITS_PER_SEC);
  t->tv_usec = (unsigned) ((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
}
#endif

// ------------------------------------------------------------------------//
//  ------------------- For Debug Purpose OCALL START  ------------------- //
// ------------------------------------------------------------------------//

void *sgx_malloc(int m_size)
{
	unsigned long long retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_malloc(&retv, m_size)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return (void *)retv;
}

void *sgx_calloc(int m_cnt, int m_size)
{
	void *retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_calloc(&retv, m_cnt, m_size)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

void *sgx_realloc(void *old_mem, int m_size)
{
	void *retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_realloc(&retv, (unsigned long long)old_mem, m_size)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_fileno_stdout()
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_fileno_stdout(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
int real_sgx_open(const char *pathname, int flags, unsigned mode)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_open(&retv, pathname, flags, mode)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
int real_sgx_write(int fd, const void *buf, int n)
{
	int retv;
	sgx_status_t sgx_retv;
  if (sgx_is_within_enclave(buf, n) == 0) { // App memory
    if ((sgx_retv = ocall_sgx_direct_write(&retv, fd, (unsigned long long)buf, n)) != SGX_SUCCESS) {
      printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
      abort();
    }
  }
  else {
	  if((sgx_retv =	ocall_sgx_write(&retv, fd, buf, n)) != SGX_SUCCESS) {
		  printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		  abort();
	  }
  }
	return retv;
}

int real_sgx_read(int fd, void *buf, int n)
{
	int retv;
	sgx_status_t sgx_retv;
  if (sgx_is_within_enclave(buf, n) == 0) { // App memory
    if ((sgx_retv = ocall_sgx_direct_read(&retv, fd, (unsigned long long)buf, n)) != SGX_SUCCESS) {
      printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
      abort();
    }
  }
  else {
	  if((sgx_retv = ocall_sgx_read(&retv, fd, buf, n)) != SGX_SUCCESS) {
		  printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		  abort();
	  }
  }
	return retv;
}

off_t real_sgx_lseek(int fildes, off_t offset, int whence)
{
	off_t retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_lseek(&retv, fildes, offset, whence)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

/*
int real_sgx_locking(int fd, int mode, long num)
{
	int retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_locking(&retv, fd, mode, num)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
*/

int real_sgx_close(int fd)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_close(&retv, fd)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_fclose(FILE * file)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_fclose(&retv, file, sizeof(FILE))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_unlink(const char *filename) 
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_unlink(&retv, filename)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_stat(const char *filename, struct stat *st) 
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_stat(&retv, filename, st, sizeof(struct stat))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_mkdir(const char *path, int mode)
{
	int retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_mkdir(&retv, path, mode)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
/*
int real_sgx_mkdir(const char *path)
{
	int retv;
	sgx_status_t sgx_retv;
	if ((sgx_retv = ocall_sgx_mkdir(&retv, path)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
*/

/*
int real_sgx_UnmapViewOfFile(const void* lpBaseAddress)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_UnmapViewOfFile(&retv, (unsigned long long)lpBaseAddress)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

void *real_sgx_MapViewOfFile(
    int hFileMappingObject,
    unsigned long dwDesiredAccess,
    unsigned long dwFileOffsetHigh,
    unsigned long dwFileOffsetLow,
    unsigned long long dwNumberOfBytesToMap
    )
{
	void *retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_MapViewOfFile(&retv, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_CreateFileMapping(
    int hFile,
    void *_null,
    unsigned long flProtect,
    unsigned long dwMaximumSizeHigh,
    unsigned long dwMaximumSizeLow,
    const char* lpName
    )
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_CreateFileMapping(&retv, hFile, _null, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

unsigned long real_sgx_GetFileSize(int hFile, unsigned long *lpFileSizeHigh)
{
	unsigned long retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_GetFileSize(&retv, hFile, lpFileSizeHigh)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

HANDLE real_sgx_CreateFile(
				const char *lpFileName,
				DWORD dwDesiredAccess,
				DWORD dwShareMode,
				void *_null,
				DWORD dwCreationDisposition,
				DWORD dwFlagsAndAttributes,
				HANDLE hTemplateFile)
{
	HANDLE retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_CreateFile(&retv, lpFileName, dwDesiredAccess, dwShareMode, _null,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
*/

int real_sgx_rename(const char *from_str, const char *to_str)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_rename(&retv, from_str, to_str)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_fstat(int fd, struct stat *buf)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_fstat(&retv, fd, buf, sizeof(struct stat))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int real_sgx_ftruncate(int fd, off_t length)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_ftruncate(&retv, fd, length)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

/*
int real_sgx_chsize(int fd, long val)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv =	ocall_sgx_chsize(&retv, fd, val)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

int sgx_CloseHandle(int hObject)
{
	int retv;
	ocall_sgx_CloseHandle(&retv, hObject);
	return retv;
}
*/

// ------------------------------------------------------------------------//
//  ----------------------- Non called OCALL START  ----------------------- //
// ------------------------------------------------------------------------//

void *sgx_pthread_getspecific(pthread_key_t key)
{
	void *retv;
	ocall_sgx_pthread_getspecific(&retv, key);
	return retv;
}

int sgx_pthread_setspecific(pthread_key_t key, const void *value)
{
	int retv;
	ocall_sgx_pthread_setspecific(&retv, key, value);
	return retv;
}

/*
void *sgx_TlsGetValue(unsigned long index)
{
	void *retv;
	ocall_sgx_TlsGetValue(&retv, index);
	return retv;
}

int sgx_TlsSetValue(unsigned long index, void *val)
{
	int retv;
	ocall_sgx_TlsSetValue(&retv, index, val);
	return retv;
}
*/
/*
void sgx_Sleep(unsigned long ms)
{
	ocall_sgx_Sleep(ms);
}
*/

void sgx_sleep(unsigned int s)
{
	ocall_sgx_sleep(s);
}

void sgx_getservbyname(const char *name, int name_len, const char *proto, int proto_len, void *serv_ptr, int serv_len)
{
	ocall_sgx_getservbyname(name, name_len, proto, proto_len, serv_ptr, serv_len);
}

void sgx_getprotobynumber(int number, void *proto, int proto_len, char *proto_name, int proto_name_len)
{
	ocall_sgx_getprotobynumber(number, proto, proto_len, proto_name, proto_name_len);
}

static map<int, void(*)(int)> func_map;
static int max_f_id = 1;

int sgx_eventfd(unsigned int initval, int flags)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_eventfd(&retv, initval, flags)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

void (*sgx_signal(int signum, void(*_Func)(int)))(int)
{
	int cur_f_id = max_f_id;
	func_map[cur_f_id] = _Func;	
	ocall_sgx_signal(signum, cur_f_id);
	max_f_id++;
//	return (void (__cdecl *)(int))0;
	return (void (*)(int))0;
}

unsigned int sgx_fork(void)
{
	unsigned int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_fork(&retv)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_sysctl(int *name, int nlen, void *oldval, int oldval_len, size_t *oldlenp, void *newval, size_t newlen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sysctl(&retv, name, nlen, oldval, oldval_len, oldlenp, newval, newlen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
}

int sgx_pipe(int pipefd[2])
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_pipe(&retv, (int *)pipefd)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_chdir(const char *path)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_chdir(&retv, path)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_chmod(const char *pathname, int mode)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_chmod(&retv, pathname, mode)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int real_sgx_fcntl2(int fd, int cmd, void *lock)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_fcntl2(&retv, fd, cmd, lock, sizeof(struct flock))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int real_sgx_fcntl(int fd, int cmd, long arg)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_fcntl(&retv, fd, cmd, arg)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}


int sgx_sigemptyset(void *set)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sigemptyset(&retv, set, sizeof(sigset_t))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

int sgx_sigfillset(void *set)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sigfillset(&retv, set, sizeof(sigset_t))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

//int sgx_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
int sgx_sigaction(int signum, const void *act, void *oldact)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sigaction(&retv, signum, act, sizeof(struct sigaction), oldact, sizeof(struct sigaction))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}

void sgx_signal_handle_caller(int signum, int f_id)
{
	if(func_map.find(f_id) == func_map.end()) {
		printf("Error: sgx_signal_handle_caller: func_map not found\n");
		return;
	}
	void(* handle_func)(int) = func_map[f_id];
	handle_func(signum);
}

//int sgx_shutdown(int fd)
int sgx_shutdown(int fd, int how)
{
	int retv;
//	ocall_sgx_shutdown(&retv, fd);
	ocall_sgx_shutdown(&retv, fd, how);
	return retv;
}

// ------------------------------------------------------------------------//
//  ----------------------- BUFFER EVENT OCALL START  ------------------- //
// ------------------------------------------------------------------------//

/*
int sgx_CreateIoCompletionPort(int FileHandle, int p, unsigned long k, unsigned long numthreads)
{
	int retv;
	ocall_sgx_CreateIoCompletionPort(&retv, FileHandle, p, k, numthreads);
	return retv;
}

int sgx_GetQueuedCompletionStatus(int p, unsigned long *numbytes, __int64 *k, void *lpOverlapped, int lpOverlapped_len, unsigned long dwMilliseconds)
{
	int retv, numbytes_len = sizeof(unsigned long), k_len = sizeof(__int64);
	ocall_sgx_GetQueuedCompletionStatus(&retv, p, numbytes, numbytes_len, k, k_len, lpOverlapped, lpOverlapped_len, dwMilliseconds);
	return retv;
}
*/

/*
int sgx_PostQueuedCompletionStatus(int port, unsigned int n, unsigned int key, void *o, int o_len)
{
	int retv;
	ocall_sgx_PostQueuedCompletionStatus(&retv, port, n, key, o, o_len);
	return retv;
}

void sgx_EnterCriticalSection(void *lock, int lock_len)
{
	ocall_sgx_EnterCriticalSection(lock, lock_len);
}

void sgx_LeaveCriticalSection(void *lock, int lock_len)
{
	ocall_sgx_LeaveCriticalSection(lock, lock_len);
}

void sgx_DeleteCriticalSection(void *lock, int lock_len)
{
	ocall_sgx_DeleteCriticalSection(lock, lock_len);
}

void sgx_InitializeCriticalSectionAndSpinCount(void *lock, int lock_len, int count)
{
	ocall_sgx_InitializeCriticalSectionAndSpinCount(lock, lock_len, count);
}

int sgx_CreateSemaphore(void *attr, int attr_len, long initcount, long maxcount, void *name, int name_len)
{
	int retv;
	ocall_sgx_CreateSemaphore(&retv, attr, attr_len, initcount, maxcount, name, name_len);
	return retv;
}

void sgx_WaitForSingleObject(int handle, unsigned long ms_)
{
	ocall_sgx_WaitForSingleObject(handle, ms_);
}

int sgx_ReleaseSemaphore(int hSemaphore, long lReleaseCount, long* lpPreviousCount, int lp_len)
{
	int retv;
	ocall_sgx_ReleaseSemaphore(&retv, hSemaphore, lReleaseCount, lpPreviousCount, lp_len);
	return retv;
}
*/

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

static const sgx_ec256_public_t g_sp_pub_key = {
	{
		0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
		0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
		0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
		0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
	},
	{
		0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
		0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
		0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
		0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
	}
};

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
  sgx_status_t ret;
  if(b_pse)
  {
    int busy_retry_times = 2;
    do{
      ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
      return ret;
  }
  ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
  if(b_pse)
  {
    sgx_close_pse_session();
    return ret;
  }
  return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API
sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
  sgx_status_t ret;
  ret = sgx_ra_close(context);
  return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.
sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t)) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret) {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret) {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }
    }
    while(0);

    return ret;
}

/*
 * Convert a string to a long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
long long int
strtoll(const char *nptr, char **endptr, int base)
{
	const char *s;
	/* LONGLONG */
	long long int acc, cutoff;
	int c;
	int neg, any, cutlim;

	/* endptr may be NULL */

#ifdef __GNUC__
	/* This outrageous construct just to shut up a GCC warning. */
	(void) &acc; (void) &cutoff;
#endif

	/*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
	 */
	s = nptr;
	do {
		c = (unsigned char) *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else {
		neg = 0;
		if (c == '+')
			c = *s++;
	}
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;

	/*
	 * Compute the cutoff value between legal numbers and illegal
	 * numbers.  That is the largest legal value, divided by the
	 * base.  An input number that is greater than this value, if
	 * followed by a legal input character, is too big.  One that
	 * is equal to this value may be valid or not; the limit
	 * between valid and invalid numbers is then based on the last
	 * digit.  For instance, if the range for long longs is
	 * [-9223372036854775808..9223372036854775807] and the input base
	 * is 10, cutoff will be set to 922337203685477580 and cutlim to
	 * either 7 (neg==0) or 8 (neg==1), meaning that if we have
	 * accumulated a value > 922337203685477580, or equal but the
	 * next digit is > 7 (or 8), the number is too big, and we will
	 * return a range error.
	 *
	 * Set any if any `digits' consumed; make it negative to indicate
	 * overflow.
	 */
	cutoff = neg ? LLONG_MIN : LLONG_MAX;
	cutlim = (int)(cutoff % base);
	cutoff /= base;
	if (neg) {
		if (cutlim > 0) {
			cutlim -= base;
			cutoff += 1;
		}
		cutlim = -cutlim;
	}
	for (acc = 0, any = 0;; c = (unsigned char) *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0)
			continue;
		if (neg) {
			if (acc < cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MIN;
				errno = ERANGE;
			} else {
				any = 1;
				acc *= base;
				acc -= c;
			}
		} else {
			if (acc > cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MAX;
				errno = ERANGE;
			} else {
				any = 1;
				acc *= base;
				acc += c;
			}
		}
	}
	if (endptr != 0)
		/* LINTED interface specification */
		*endptr = (char *)(any ? s - 1 : nptr);
	return (acc);
}

#ifdef _MSC_VER
    #pragma warning(pop)
#endif
