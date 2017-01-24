#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include "sgx_ukey_exchange.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#pragma comment(lib, "ws2_32.lib")
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "remote_attest_server.h"
#include "service_provider.h"
#include <list>

using namespace std;

/*************************** Remote attestation Start ***************************/

void PRINT_BYTE_ARRAY(void *mem, uint32_t len)
{
  if(!mem || !len)
  {
    printf("\n( null )\n");
    return;
  }
  uint8_t *array = (uint8_t *)mem;
  printf("%u bytes:\n{\n", len);
  uint32_t i = 0;
  for(i = 0; i < len - 1; i++)
  {
    printf("0x%x, ", array[i]);
    if(i % 8 == 7) 
			printf("\n");
  }
  printf("0x%x ", array[i]);
  printf("\n}\n");
}

int set_cert_key_stuff(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key,
                       STACK_OF(X509) *chain, int build_chain)
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
  (*out) = (char *) malloc(((*out_len) + 1) * sizeof(char));
  memcpy(*out, ptr->data, (*out_len));
  (*out)[(*out_len)] = '\0';

  BIO_free_all(buff);
}

void *sgx_calloc(size_t count, size_t size)
{
	void *ret;
	ret = calloc(count, size);
	if(ret == NULL) {
		puts("*** Error! calloc: out of memory");
		abort();
	}
	return ret;
}

void sgx_free(void *target)
{
	if(target != NULL)
		free(target);
}

char dest_url[] = "https://test-as.sgx.trustedservices.intel.com";
int get_sigrl(ra_samp_request_header_t * p_msg1_full);
SSL_CTX *g_ctx = NULL;

SOCKET create_socket(char url_str[]) {
  SOCKET sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  SOCKADDR_IN dest_addr;

  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';
  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));
  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));
  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }
  port = atoi(portnum);

  if ((host = gethostbyname(hostname)) == NULL ) {
    printf("Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  memset(&(dest_addr.sin_zero), '\0', 8);
  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1 ) {
    printf("Error: Cannot connect to host %s [%s] on port %d.\n", hostname, tmp_ptr, port);
  }

  return sockfd;
}

SSL *s_connect(int sock, char * dest_url)
{
	SSL *ssl;
  int server = 0;
	if(g_ctx == NULL) {
		puts("SSL_CTX is NULL!");
		abort();
	}
  ssl = SSL_new(g_ctx);
  SSL_set_fd(ssl, sock);
  if ( SSL_connect(ssl) != 1 )
    printf("Error: Could not build a SSL session to: %s.\n", dest_url);
  else
    printf("Successfully enabled SSL/TLS session to: %s.\n", dest_url);
  printf("Finished SSL/TLS connection with server: %s.\n", dest_url);
	return ssl;
}

int get_sigrl(ra_samp_request_header_t * p_msg1_full)
{
	SSL * ssl;
	int k;
	int ret = 1;
	SOCKET sock;
	char send_buf[8192], recv_buf[8192];
	sock = create_socket(dest_url);
	ssl = s_connect(sock, dest_url);
	memset(send_buf, 0, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));
	sprintf(send_buf, "GET /attestation/sgx/v1/sigrl/%02X%02X%02X%02X\r\n\r\n", p_msg1_full->body[67],p_msg1_full->body[66],p_msg1_full->body[65],p_msg1_full->body[64]);
	k = SSL_write(ssl, send_buf, strlen(send_buf));
	if( k < 0) {
		printf("Error!\n");
		abort();
	}
	k = SSL_read(ssl, recv_buf, 8192);
	if( k < 0) {
		printf("Error!\n");
		abort();
	}
	printf("Received buffer = %s\n", recv_buf);

	if(strstr(recv_buf, "200 OK") != NULL) {
		printf("Remote attestation success!\n");
		ret = 0;
	}
	else{
		printf("Invalid EPID\n");
		ret = -1;
	}
	SSL_free(ssl);
	closesocket(sock);
	return ret;
}

int post_quote(ra_samp_request_header_t * p_msg3_full)
{
	SSL * ssl;
	SOCKET sock;
	int k = -1, ret = -1;
	sock = create_socket(dest_url);
	ssl = s_connect(sock, dest_url);
	sample_ra_msg3_t *p_msg3 = (sample_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t));
	sample_quote_t *p_quote = (sample_quote_t *)p_msg3->quote;
	size_t quote_size = sizeof(sample_quote_t) + p_quote->signature_len;
	char *base64str;
	size_t base64strlen;
	char send_buf[8192],recv_buf[8192];
	char isvEnclaveQuote[4096];
	memset(send_buf, 0, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));
	memset(isvEnclaveQuote, 0, sizeof(isvEnclaveQuote));

	base64_encode((const byte *)p_quote, quote_size, &base64str, &base64strlen);
	memset(send_buf, 0, sizeof(send_buf));

	sprintf(isvEnclaveQuote, "{\"isvEnclaveQuote\":\"%s\"}", base64str);
	free(base64str);
	sprintf(send_buf,
		"POST /attestation/sgx/v1/report\r\n"
		"Content-Type:application/json\r\n"
		"Content-Length:%d\r\n\r\n"
		"%s"
		"\r\n\r\n",
		strlen(isvEnclaveQuote), isvEnclaveQuote);
	printf("send_buf = %s\n", send_buf);
	k = SSL_write(ssl, send_buf, strlen(send_buf));
	if( k < 0) {
		printf("Error! SSL_write\n");
		abort();
	}
	memset(recv_buf, 0, sizeof(recv_buf));
	k = SSL_read(ssl, recv_buf, 8192);
	if( k < 0) {
		printf("Error! SSL_read\n");
		abort();
	}
	printf("QUOTE response = %s\n", recv_buf);
	if(strstr(recv_buf, "201 Created") != NULL) {
		printf("Remote attestation success!\n");
		ret = 0;
	}
	else{
		printf("Invalid EPID\n");
		ret = -1;
	}
	SSL_free(ssl);
	closesocket(sock);
	return ret;
}

void build_msg2(ra_samp_request_header_t *p_msg1_full, ra_samp_response_header_t **p_msg2_full_return,uint32_t msg2_size)
{
	int ret = 0;
	ra_samp_response_header_t *p_msg2_full;
	if (NULL == p_msg1_full) {
    abort();
  }
	ret = process_msg_all(p_msg1_full, &p_msg2_full);
  if (ret != 0) {
    puts("Error, process_msg_all for msg0 failed.");
    abort();
  }
	if(TYPE_RA_MSG2 != p_msg2_full->type) {
    puts("Error, didn't get MSG2 in response to MSG1.");
		abort();
  }
	*p_msg2_full_return = p_msg2_full;
}

void build_msg4(ra_samp_request_header_t *p_msg3_full, ra_samp_response_header_t **p_att_result_msg_full_return)
{		
	ra_samp_response_header_t *p_att_result_msg_full;

	sample_ra_msg3_t *p_msg3 = (sample_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t));
	sample_quote_t *p_quote = (sample_quote_t *)p_msg3->quote;
	process_msg_all(p_msg3_full, &p_att_result_msg_full);	
	printf("build msg4 complete \n");
	*p_att_result_msg_full_return = p_att_result_msg_full;
}

int SEND(int s, void *msg, int size)
{
	int n, e;
	n = send(s, (const char *)msg, size, 0); 
	if( n < 0 ) { 
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e); 
		if(e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
			Sleep(1000);
			return SEND(s, msg, size); 
		}
		else {
			abort();
		}
	}
	return n;	
}

int RECV(int s, void *msg, int size)
{
	int n, e;
	n = recv(s, (char *)msg, size, 0); 
	if( n < 0 ) { 
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e); 
		if(e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
			Sleep(1000);
			return RECV(s, msg, size); 
		}
		else {
			abort();
		}
	}
	return n;	
}

void sgx_get_ssl_context()
{
	BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  certbio = BIO_new(BIO_s_file());

  if(SSL_library_init() < 0)
    printf("Could not initialize the OpenSSL library !\n");

  method = SSLv23_client_method();

  if ( (g_ctx = SSL_CTX_new(method)) == NULL)
    printf("Unable to create a new SSL context structure.\n");

	# define FORMAT_PEM      3
	BIO *tmp_cert = BIO_new_file("D:\\demo\\client.crt", "r");
	X509 *sgx_cert = PEM_read_bio_X509_AUX(tmp_cert, NULL,
                                  (pem_password_cb *)NULL, NULL);
	BIO_free(tmp_cert);
	if(sgx_cert == NULL) {
		printf("x is NULL\n");
		abort();
	}
	BIO *tmp_key = BIO_new_file("D:\\demo\\client.key", "r");
	EVP_PKEY *sgx_pkey = PEM_read_bio_PrivateKey(tmp_key, NULL,
                                       (pem_password_cb *)NULL, NULL);
	BIO_free(tmp_key);
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

int remote_port_server = -1;
list<unsigned long *> remote_accept_list;
HANDLE remote_accept_mutex;

int check_remote_accept_list(unsigned long ip)
{
	int found = -1;
	WaitForSingleObject(remote_accept_mutex, INFINITE);	
	if(remote_accept_list.empty()) {
		printf("Remote accept list is empty!\n");
		found = 0;
	}
	else {
		list<unsigned long *>::iterator iter;
		for(iter = remote_accept_list.begin(); iter != remote_accept_list.end(); iter++) {
			if(**iter == ip) {
				printf("Found in remote accept list!\n");
				found = 0;
				break;
			}
		}
	}
	ReleaseMutex(remote_accept_mutex);
	return found;
}

void start_remote_attestation_server()
{
	SOCKET server_fd, client_fd;
	SOCKADDR_IN server_addr, client_addr;
	int client_addr_size;
	int n, ret, is_ok = 0;
	ra_samp_request_header_t *p_msg0_full = NULL;
	ra_samp_response_header_t *p_msg0_resp_full = NULL;
	ra_samp_request_header_t *p_msg1_full = NULL;
	ra_samp_response_header_t *p_msg2_full = NULL;
	ra_samp_response_header_t *p_att_result_msg_full = NULL;
	ra_samp_request_header_t *p_msg3_full = NULL;
	unsigned long *accept_ip;
	WSADATA WSAData;
  int r;

  r = WSAStartup(0x101,&WSAData);
  if (r) {
    printf("Error initializing windows network layer: code was %d",r);
    abort();
  }

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_fd == INVALID_SOCKET){
		puts("*** Error, invalid socket");		
		abort();
	}
	server_addr.sin_family=AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(remote_port_server);
	if( bind(server_fd, (sockaddr *) &server_addr, sizeof (server_addr)) == SOCKET_ERROR){
		puts("*** Error, bind");
		closesocket(server_fd);
		abort();
	}
	if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
		printf("listen function failed with error: %d\n", WSAGetLastError());
		closesocket(server_fd);
		abort();
	}
	printf("Listening to client connection... \n");

	while(1) {
		client_addr_size = sizeof(SOCKADDR_IN);
		memset(&client_addr, 0, sizeof(client_addr));
		client_fd = accept(server_fd, (sockaddr *)&client_addr, &client_addr_size);
		printf("Server Remote Attestation Start!\n");
		printf("Client %s:%d is accepted!\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

		uint32_t msg0_full_size = sizeof(ra_samp_request_header_t) +sizeof(uint32_t);
		p_msg0_full = (ra_samp_request_header_t*)sgx_calloc(1,msg0_full_size);
		RECV(client_fd, p_msg0_full, msg0_full_size);
		ret = process_msg_all(p_msg0_full, &p_msg0_resp_full);
		if (ret != 0) {
			puts("Error, process_msg_all for msg0 failed.");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			printf("\nMSG0 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}

		uint32_t msg1_full_size = sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t);
		p_msg1_full = (ra_samp_request_header_t*)sgx_calloc(1,msg1_full_size);
		RECV(client_fd, p_msg1_full, msg1_full_size);	
		sgx_get_ssl_context();

		ret = get_sigrl(p_msg1_full);
		if (ret != 0) {
			puts("Error, process_msg_all for msg1 failed.");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			printf("\nMSG1 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}

		uint32_t msg2_size = 168;
		uint32_t msg2_full_size = sizeof(ra_samp_response_header_t) + msg2_size;
		build_msg2(p_msg1_full,&p_msg2_full,msg2_full_size);
		SEND(client_fd, &msg2_full_size, sizeof(uint32_t));
		SEND(client_fd, p_msg2_full, msg2_full_size);

		uint32_t msg3_size = 0;	
		RECV(client_fd, &msg3_size, sizeof(uint32_t));
		uint32_t msg3_full_size = sizeof(ra_samp_request_header_t) + msg3_size;
		p_msg3_full = (ra_samp_request_header_t*)sgx_calloc(1, msg3_full_size);
		RECV(client_fd, p_msg3_full, sizeof(ra_samp_request_header_t) + msg3_size);
		ret = post_quote(p_msg3_full);
		if(ret != 0){
			printf("invalid quote \n");
			is_ok = -1;
			SEND(client_fd, &is_ok, sizeof(int));
			goto err;
		}
		else {
			printf("MSG4 Verified!\n");
			is_ok = 1234;
			SEND(client_fd, &is_ok, sizeof(int));
		}

		uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t);
		uint32_t msg4_size = att_result_msg_size + sizeof(ra_samp_response_header_t) + 8;
		build_msg4(p_msg3_full, &p_att_result_msg_full);
		SEND(client_fd, p_att_result_msg_full, msg4_size);

		// Append to accept list if success
		accept_ip = (unsigned long *)calloc(1, sizeof(unsigned long));
		memcpy(accept_ip, &client_addr.sin_addr.s_addr, sizeof(unsigned long));
		WaitForSingleObject(remote_accept_mutex, INFINITE);
		remote_accept_list.push_back(accept_ip);
		ReleaseMutex(remote_accept_mutex);

	err:
		sgx_free(p_msg0_full);
		sgx_free(p_msg0_resp_full);
		sgx_free(p_msg1_full);
		sgx_free(p_msg2_full);
		sgx_free(p_msg3_full);
		sgx_free(p_att_result_msg_full);
		if(g_ctx != NULL) {
			SSL_CTX_free(g_ctx);
			g_ctx = NULL;
		}
		closesocket(client_fd);
	}
	closesocket(server_fd);
}

void do_remote_attestatation_server(int port) {
	HANDLE t;
	DWORD tid;
	remote_port_server = port;
	remote_accept_mutex = CreateMutex(NULL, FALSE, NULL);
	t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start_remote_attestation_server, NULL, 0, &tid); 
	if(t == NULL) {
		printf("Error, CreateThread\n");
	}
}