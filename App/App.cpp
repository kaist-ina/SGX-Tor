/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* For Windows */
/*
#pragma comment(lib, "ws2_32.lib")
#include <WinSock2.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include <io.h>
#include <tchar.h>
#include <process.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ShlObj.h>
#include <sys/utime.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include "direct.h"
#include "Basetsd.h"
*/

/* For Linux */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <grp.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/epoll.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <map>
#include <list>
#include <signal.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include "compat.h"
#include "compat_threads.h"
#include "util.h"

#include <limits.h>
#include "sgx_ukey_exchange.h"
#include "network_ra.h"
#include "sgx_uae_service.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "service_provider.h"

/*------------------------------------------------------*/
using namespace std;

// For eval
#include <chrono>
using namespace chrono;
//#define EVAL_INITIALIZATION
//#define EVAL_SEALING

// For eval
//#define EVAL_OCALL_COUNT
#ifdef EVAL_OCALL_COUNT
int ocall_num;
#endif
#define TEST_SGX_TOR

//#define EVAL_REMOTE_ATTEST_COUNT
//#define EVAL_REMOTE_ATTEST_TIME

#ifdef EVAL_REMOTE_ATTEST_COUNT
//bool is_remote_attest_start;  // need modification!
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

/*------------------------------------------------------*/

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_ra_context_t context = INT_MAX;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

ssize_t
read_all(tor_socket_t fd, char *buf, size_t count, int isSocket)
{
  size_t numread = 0;
  ssize_t result;

  if (count > SIZE_T_CEILING || count > SSIZE_MAX) {
    errno = EINVAL;
    return -1;
  }

  while (numread != count) {
    if (isSocket)
      result = tor_socket_recv(fd, buf+numread, count-numread, 0);
    else
      result = read((int)fd, buf+numread, count-numread);
    if (result<0)
      return -1;
    else if (result == 0)
      break;
    numread += result;
  }
  return (ssize_t)numread;
}

void
tor_strstrip(char *s, const char *strip)
{
  char *read = s;
  while (*read) {
    if (strchr(strip, *read)) {
      ++read;
    } else {
      *s++ = *read++;
    }
  }
  *s = '\0';
}

ssize_t
write_all(tor_socket_t fd, const char *buf, size_t count, int isSocket)
{
  size_t written = 0;
  ssize_t result;
  assert(count < SSIZE_MAX);

  while (written != count) {
    if (isSocket)
      result = tor_socket_send(fd, buf+written, count-written, 0);
    else
      result = write((int)fd, buf+written, count-written);
    if (result<0)
      return -1;
    written += result;
  }
  return (ssize_t)count;
}

int remote_attest_server_port = -1;
unsigned long my_ip = 0;

list<struct sockaddr_in *> remote_list;

int load_keys_fing(char *path, int flags, char **ret_str, int *ret_len)
{
        struct stat statbuf;
        char ip[20], port[6];
        int r, fd;
        if (path == NULL) {
                printf("Path not set! Run as default (Client)\n");
                return -1;
        }
        fd = open(path, O_RDONLY | flags, 0);
        if (fd < 0) {
                printf("unable to open torrc! path: %s\n", path);
                return -1;
        }
        if (fstat(fd, &statbuf) < 0) {
                printf("unable to fstat torrc! path: %s\n", path);
                return -1;
        }
        if ((uint64_t)(statbuf.st_size) + 1 >= SIZE_T_CEILING) {
                close(fd);
                printf("unable to fstat torrc! path: %s\n", path);
                return -1;
        }
        *ret_str = (char *)malloc((size_t)statbuf.st_size);
        r = read_all(fd, *ret_str, (size_t)statbuf.st_size, 0);
        if (r < 0) {
                printf("unable to read torrc! path: %s\n", path);
                return -1;
        }
        *ret_len = r;

        return 0;
}

char *dir_address = NULL;

char *load_torrc(char *path)
{
        struct stat statbuf;
        char *torrc, *stastr, *endstr;
        char ip[20], port[6];
        int r, fd;
        if (path == NULL) {
                printf("Path not set! Run as default (Client)\n");
                return NULL;
        }
        fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
                printf("unable to open torrc! path: %s\n", path);
                return NULL;
        }
        if (fstat(fd, &statbuf) < 0) {
                printf("unable to fstat torrc! path: %s\n", path);
                return NULL;
        }
        if ((uint64_t)(statbuf.st_size) + 1 >= SIZE_T_CEILING) {
                close(fd);
                printf("unable to fstat torrc! path: %s\n", path);
                return NULL;
        }
        torrc = (char *)malloc((size_t)(statbuf.st_size + 1));
        r = read_all(fd, torrc, (size_t)statbuf.st_size, 0);
        if (r < 0) {
                printf("unable to read torrc! path: %s\n", path);
                return NULL;
        }
        torrc[r] = '\0';

        if (strchr(torrc, '\r')) {
                tor_strstrip(torrc, "\r");
                r = strlen(torrc);
        }
        statbuf.st_size = (size_t)r;
        if (r != statbuf.st_size) {
                printf("st_size not match for torrc! path: %s\n", path);
                free(torrc);
                close(fd);
                return NULL;
        }


        if ((stastr = strstr(torrc, "DirPort")) != NULL) {
                int ip_len, port_len;
                stastr = strchr(stastr, ' ') + 1;
                endstr = strchr(stastr, '\n');
                memset(port, 0, sizeof(port));
                strncpy(port, stastr, endstr - stastr);
                stastr = strstr(torrc, "Address ");
                if (stastr == NULL) {
                        printf("torrc has no Address [ip] field!");
                        abort();
                }
                stastr = strchr(stastr, ' ') + 1;
                endstr = strchr(stastr, '\n');
                memset(ip, 0, sizeof(ip));
                strncpy(ip, stastr, endstr - stastr);

                ip_len = strlen(ip);
                port_len = strlen(port);
                dir_address = (char *)calloc(1, ip_len + port_len + 2);
                sprintf(dir_address, "%s:%s", ip, port);
        }
        if (remote_attest_server_port == -1 && (stastr = strstr(torrc, "RemoteAttestPort")) != NULL) {
                stastr = strchr(stastr, ' ')+1;
                endstr = strchr(stastr, '\n');
                memset(port, 0, sizeof(port));
                strncpy(port, stastr, endstr-stastr);
                remote_attest_server_port = atoi(port);
                printf("portnumber = %d\n", remote_attest_server_port);

                stastr = strstr(torrc, "Address ");
                if (stastr == NULL) {
                        printf("torrc has no Address [ip] field!");
                        abort();
                }
                stastr = strchr(stastr, ' ') + 1;
                endstr = strchr(stastr, '\n');
                memset(ip, 0, sizeof(ip));
                strncpy(ip, stastr, endstr - stastr);
                my_ip = inet_addr(ip);
        }
        if (remote_list.empty()){
                struct sockaddr_in *addr;
                stastr = torrc;
                while((stastr = strstr(stastr, "RemoteAttestServer")) != NULL) {
                        addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
                        stastr = strchr(stastr, ' ')+1;
                        endstr = strchr(stastr, ':');
                        memset(ip, 0, sizeof(ip));
                        strncpy(ip, stastr, endstr-stastr);
                        stastr = endstr + 1;
                        endstr = strchr(stastr, '\n');
                        memset(port, 0, sizeof(port));
                        strncpy(port, stastr, endstr-stastr);
                        printf("IP = %s\n", ip);
                        printf("Remote Port = %s\n", port);
                        addr->sin_addr.s_addr = inet_addr(ip);
                        addr->sin_family = AF_INET;
                        addr->sin_port = htons(atoi(port));
                        remote_list.push_back(addr);
                }
        }
  close(fd);

        return torrc;
}

#if 0
/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
#endif

void ocall_sgx_ra_free_network_response_buffer(void **resp)
{
	ra_free_network_response_buffer((ra_samp_response_header_t *)*resp);
}

int ocall_sgx_process_msg_all(const void *p_req, int p_req_size, void **p_resp)
{
	int ret;
	ret = process_msg_all((ra_samp_request_header_t*)p_req, (ra_samp_response_header_t **)p_resp);
	return ret;
}

/*
int ocall_sgx_mkdir(const char *path)
{
	return mkdir(path);
}
*/

pid_t ocall_sgx_fork(void)
{
	return fork();
}

int ocall_sgx_sysctl(int *name, int nlen, void *oldval, int oldval_len, size_t *oldlenp, void *newval, size_t newlen)
{
	return sysctl(name, nlen, oldval, oldlenp, newval, newlen);
}

int ocall_sgx_pipe(int pipefd[2])
{
	return pipe(pipefd);
}

int ocall_sgx_chdir(const char *path)
{
	return chdir(path);
}

int ocall_sgx_chmod(const char *pathname, int mode)
{
	return chmod(pathname, (__mode_t)mode);
}

int ocall_sgx_mkdir(const char *path, int mode)
{
	return mkdir(path, (__mode_t)mode);
}

unsigned long long ocall_sgx_malloc(int m_size)
{
	return (unsigned long long)malloc(m_size);
}

void *ocall_sgx_calloc(int m_cnt, int m_size)
{
	return calloc(m_cnt, m_size);
}

void *ocall_sgx_realloc(unsigned long long old_mem, int m_size)
{
	return realloc((void *)old_mem, m_size);
}

int ocall_sgx_stat(const char  *filename, struct stat *st, int stat_size)
{
	return stat(filename, st);
}

int ocall_sgx_fclose(FILE *file, int file_size)
{
	return fclose(file);
}

int ocall_sgx_fileno_stdout(void)
{
	return fileno(stdout);
}

void *ocall_sgx_calloc(size_t cnt, size_t sz)
{
	return calloc(cnt, sz);
}

void ocall_sgx_free(unsigned long long ptr)
{
	free((void *)ptr);
}

void ocall_sgx_sleep(unsigned int seconds)
{
	sleep(seconds);
}

/*
void ocall_sgx_Sleep(unsigned long milli)
{
	Sleep(milli);
}
*/

/*
int
ocall_sgx_UnmapViewOfFile(unsigned long long lpBaseAddress)
{
	return UnmapViewOfFile((const void*)lpBaseAddress);;
}

void *
ocall_sgx_MapViewOfFile(
    int hFileMappingObject,
    unsigned long dwDesiredAccess,
    unsigned long dwFileOffsetHigh,
    unsigned long dwFileOffsetLow,
    unsigned long long dwNumberOfBytesToMap
    )
{
	return MapViewOfFile((HANDLE)hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

int
ocall_sgx_CreateFileMapping(
    int hFile,
    void *_null,
    unsigned long flProtect,
    unsigned long dwMaximumSizeHigh,
    unsigned long dwMaximumSizeLow,
    const char* lpName
    )
{
	return (int)CreateFileMapping((HANDLE)hFile, NULL, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

unsigned long ocall_sgx_GetFileSize(int hFile, unsigned long *lpFileSizeHigh)
{
	return GetFileSize((HANDLE)hFile, lpFileSizeHigh);
}

HANDLE ocall_sgx_CreateFile(
				const char *lpFileName,
				unsigned long dwDesiredAccess,
				unsigned long dwShareMode,
				void *_null,
				unsigned long dwCreationDisposition,
				unsigned long dwFlagsAndAttributes,
				int hTemplateFile)
{
	return CreateFile(lpFileName, dwDesiredAccess, dwShareMode, NULL,
		dwCreationDisposition, dwFlagsAndAttributes, (HANDLE)hTemplateFile);
}
*/

int ocall_sgx_poll(void *fds, int fd_size, int nfds, int timeout)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	int retv = select(nfds, (struct fd_set *)rfd, (struct fd_set *)wfd, (struct fd_set *)efd, timeout);
	int retv = poll((struct pollfd *)fds, nfds, timeout);
	return retv;
}

int ocall_sgx_clock_gettime(clockid_t clk_id, struct timespec *tp, int tp_size)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	int retv = clock_gettime(clk_id, tp);
	return retv;
}

int ocall_sgx_gettimeofday(struct timeval *tv, int tv_size)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	int retv = gettimeofday(tv, NULL);
	return retv;
}

int ocall_sgx_select(int nfds, void *rfd, void *wfd,  void *efd, int fd_size,
										 struct timeval *timeout, int tv_size)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	int retv = select(nfds, (struct fd_set *)rfd, (struct fd_set *)wfd, (struct fd_set *)efd, timeout);
	int retv = select(nfds, (fd_set *)rfd, (fd_set *)wfd, (fd_set *)efd, timeout);
	return retv;
}

void *ocall_sgx_pthread_getspecific(int key)
{
	return pthread_getspecific(key);
}

int ocall_sgx_pthread_setspecific(int key, const void *value)
{
	return pthread_setspecific(key, value);
}

/*
unsigned long ocall_sgx_TlsAlloc(void)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return TlsAlloc();
}

void *ocall_sgx_TlsGetValue(unsigned long index)
{
	return TlsGetValue(index);
}

int ocall_sgx_TlsSetValue(unsigned long index, void *val)
{
	return TlsSetValue(index, val);
}
*/

void ocall_print_string(const char *str)
{	
	printf("%s", str);
}

int ocall_sgx_recv(int s, char *buf, int len, int flags)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//TODO : SOCKET for Windows
//	int retv = recv((SOCKET)s, buf, len, flags);

	int retv = recv(s, buf, len, flags);
	/*
	if(retv == SOCKET_ERROR) {
		long e = WSAGetLastError();
		printf("recv function failed with error: %ld\n", e);
	}
	*/
	return retv;
}

int ocall_sgx_direct_recv(int s, unsigned long long buf, int len, int flags)
{
//	int retv = recv((SOCKET)s, (char *)buf, len, flags);
	int retv = recv(s, (char *)buf, len, flags);
	return retv;
}

int ocall_sgx_send(int s, const char *buf, int len, int flags)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	return send((SOCKET)s, buf, len, flags);
	return send(s, buf, len, flags);
}

int ocall_sgx_direct_send(int s, unsigned long long buf, int len, int flags)
{
//	int retv = send((SOCKET)s, (const char *)buf, len, flags);
	int retv = send(s, (const char *)buf, len, flags);
	return retv;
}

int ocall_sgx_close(int fd)
{
//	return _close(fd);
	return close(fd);
}

int ocall_sgx_read(int fd, char * buf, int buf_len)
{
	return	read(fd,buf,buf_len);
}

void ocall_sgx_exit(int e)
{
	exit(e);
}

unsigned short ocall_sgx_htons(unsigned short hostshort)
{
	return htons(hostshort);
}

unsigned long 	ocall_sgx_htonl(unsigned long hostlong)
{
	return htonl(hostlong);
}

unsigned short ocall_sgx_ntohs(unsigned short netshort)
{
	return ntohs(netshort);
}

unsigned long ocall_sgx_ntohl(unsigned long netlong)
{
	return ntohl(netlong);
}

int ocall_sgx_socketpair(int domain, int type, int protocol, int *sv)
{
	return socketpair(domain, type, protocol, sv);
}

int ocall_sgx_setsockopt(int s, int level, int optname, const char *optval, int optlen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setsockopt(s, level, optname, optval, optlen);
}

int ocall_sgx_socket(int af, int type, int protocol)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	int retv;
//	retv = (SOCKET)socket(af, type, protocol);
	retv = socket(af, type, protocol);
	return retv;
}

//int ocall_sgx_accept(int s, struct sockaddr *addr, int addr_size, int *addrlen)
int ocall_sgx_accept(int s, struct sockaddr *addr, int addr_size, int *addrlen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	int retv = (SOCKET)accept((SOCKET)s, addr, addrlen);
	int retv = accept(s, addr, (socklen_t *)addrlen);
	return retv;

}

int ocall_sgx_bind(int s, const struct sockaddr *addr, int addr_size)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//	return bind((SOCKET)s, addr, addr_size);
	return bind(s, addr, addr_size);
}

int ocall_sgx_fstat(int fd, struct stat *buf, int buflen)
{
	return fstat(fd, buf);
}

int ocall_sgx_listen(int s, int backlog)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//	return listen((SOCKET)s, backlog);
	return listen(s, backlog);
}

int ocall_sgx_connect(int s, const struct sockaddr *addr, int addrlen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//	int retv = connect((SOCKET)s, addr, addrlen);
	int retv = connect(s, addr, addrlen);
	return retv;
}

/*
int ocall_sgx_ioctlsocket(int s, long cmd, unsigned long *argp, int argp_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return ioctlsocket(s, cmd, argp);
}
*/
/*
int ocall_sgx_closesocket(int s)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	return closesocket((SOCKET)s);
	return closesocket(s);
}
*/
/*
void ocall_sgx_EnterCriticalSection(void *lock, int lock_len)
{
	EnterCriticalSection((LPCRITICAL_SECTION)lock);
}

void ocall_sgx_LeaveCriticalSection(void *lock, int lock_len)
{
	LeaveCriticalSection((LPCRITICAL_SECTION)lock);
}

void ocall_sgx_DeleteCriticalSection(void *lock, int lock_len)
{
	DeleteCriticalSection((LPCRITICAL_SECTION)lock);
}

void ocall_sgx_InitializeCriticalSectionAndSpinCount(void *lock, int lock_len, int count)
{
	InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)lock, (DWORD)count);
}
*/

struct hostent *ocall_sgx_gethostbyname(const char *name)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return gethostbyname(name);
}

/*
int ocall_sgx_CryptGenRandom(unsigned long long prov, int buf_len, unsigned char *buf)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return CryptGenRandom((HCRYPTPROV)prov, (DWORD)buf_len, (BYTE *)buf);
}

void ocall_sgx_WSASetLastError(int errcode)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	WSASetLastError(errcode);
}

int ocall_sgx_WSAGetLastError(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return WSAGetLastError();
}

int ocall_sgx_GetLastError(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return GetLastError();
}
*/

gid_t ocall_sgx_getegid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return getegid();
}

uid_t ocall_sgx_geteuid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return geteuid();
}

gid_t ocall_sgx_getgid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return getgid();
}

int ocall_sgx_setgroups(size_t size, const unsigned int *list, int list_num)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setgroups(size, (const gid_t *)list);
}

int ocall_sgx_getgroups(int size, unsigned int *list, int list_num)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return getgroups(size, list);
}

int ocall_sgx_seteuid(unsigned int uid)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return seteuid((uid_t)uid);
}

int ocall_sgx_setegid(unsigned int gid)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setegid((uid_t)gid);
}

int ocall_sgx_setuid(unsigned int uid)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setuid((uid_t)uid);
}

int ocall_sgx_setgid(unsigned int gid)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setgid((uid_t)gid);
}

uid_t ocall_sgx_getuid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return getuid();
}

pid_t ocall_sgx_setsid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return setsid();
}

pid_t ocall_sgx_waitpid(unsigned int pid, int *_status, int status_len, int options)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return waitpid(pid, _status, options);
}

pid_t ocall_sgx_getpid(void)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return getpid();
}

int ocall_sgx_dup2(int oldfd, int newfd)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return dup2(oldfd, newfd);
}

/*
unsigned ocall_sgx_GetSystemDirectory(char *lpBuffer, unsigned int uSize)
{
	return GetSystemDirectory((LPSTR)lpBuffer, (UINT)uSize);
}

unsigned long long ocall_sgx_LoadLibrary(char* lpFileName)
{
	HMODULE retv;
	retv = LoadLibrary((LPCSTR)lpFileName);
	return (unsigned long long)retv;
}
*/

int ocall_sgx_open(const char *pathname, int flags, unsigned mode)
{
//	return _open(pathname, flags, mode);
	return open(pathname, flags, mode);
}

int ocall_sgx_ftruncate(int fd, off_t length)
{
	return ftruncate(fd, length);
}

/*
int ocall_sgx_chsize(int fd, long val)
{
	return chsize(fd, val);
}
*/

// Clear
//void ocall_sgx_ftime(struct _timeb *tb,int size)
void ocall_sgx_ftime(struct timeb *tb,int size)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	_ftime(tb);
	ftime(tb);
}

time_t ocall_get_time(time_t *timep, int t_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return 	time(timep);
}

int ocall_sgx_getaddrinfo(const char *node, const char *service, const void *hints, int hints_len, void **res, int res_len)
{
	return getaddrinfo(node, service, (struct addrinfo *)hints, (struct addrinfo **)res);
}

void ocall_sgx_freeaddrinfo(void *res, int res_len)
{
	return freeaddrinfo((struct addrinfo *)res);
}

int ocall_sgx_getsockname(int s,  struct sockaddr *name, int nlen, int *namelen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

//	return getsockname(s, name, namelen);
	return getsockname(s, name, (socklen_t *)namelen);
}

/*
void ocall_sgx_SetLastError(int e)
{
	SetLastError(e);
}

void ocall_sgx_GetSystemTimeAsFileTime(FILETIME *ft, int ft_size)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	GetSystemTimeAsFileTime(ft);
}
*/

int ocall_sgx_rename(const char *from_str, const char *to_str)
{
	return rename(from_str, to_str);
}

int ocall_sgx_unlink(const char *filename)
{
	return unlink(filename);
}

//int ocall_sgx_shutdown(int fd)
int ocall_sgx_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

int ocall_sgx_write(int fd, const void *buf, int n)
{
	int w = write(fd, buf, n);
	if(w < 0) {
		printf("Error write!: errno = %d\n", errno);
	}
	return w;
}

int ocall_sgx_direct_write(int fd, unsigned long long buf, int n)
{
  int w = write(fd, (const  void *)buf, n);
  if (w < 0) {
    printf("Error write!: errno = %d\n", errno);
  }
  return w;
}

int ocall_sgx_read(int fd, void *buf, int n)
{
	return read(fd, buf, n);
}

int ocall_sgx_direct_read(int fd, unsigned long long buf, int n)
{
  int r = read(fd, (void *)buf, n);
  if (r < 0) {
    printf("Error read!: errno = %d\n", errno);
  }
  return r;
}

/*
char *ocall_sgx_strdup(char *str)
{
  return strdup(str);
}
*/

off_t ocall_sgx_lseek(int fildes, off_t offset, int whence)
{
	return lseek(fildes, offset, whence);
}

/*
int ocall_sgx_locking(int fd, int mode, long num)
{
	return _locking(fd, mode, num);
}
*/

int ocall_sgx_gethostname(char *name, size_t namelen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return gethostname(name, namelen);
}

struct tm *ocall_sgx_localtime(const time_t *timep, int t_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return localtime(timep);
}

struct tm *ocall_sgx_gmtime(const time_t *timep, int t_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return gmtime(timep);
}

time_t ocall_sgx_mktime(struct tm *timeptr, int tm_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return mktime(timeptr);
}

/*
unsigned long ocall_sgx_GetNetworkParams(void *fixed, unsigned long fixed_sz, unsigned long *fixed_size)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return GetNetworkParams((FIXED_INFO *)fixed, fixed_size);
}
*/

int ocall_sgx_sendto(int s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return sendto(s, (const char *)msg, len, flags, to, tolen);
}

//int ocall_sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int frlen, int *in_len)
int ocall_sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int frlen, int *in_len)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//	return recvfrom(s, (char *)msg, len, flags, fr, in_len);
	return recvfrom(s, (char *)msg, len, flags, fr, (socklen_t *)in_len);
}

/*
int ocall_sgx_SHGetSpecialFolderPathA(HWND hwnd, char *path, int path_len, int csidl, int fCreate)
{
	return SHGetSpecialFolderPathA(hwnd, path, csidl, fCreate);
}

int ocall_sgx_CreateSemaphore(void *attr, int attr_len, long initcount, long maxcount, void *name, int name_len)
{
	return (int)CreateSemaphore((LPSECURITY_ATTRIBUTES)attr, (LONG)initcount, (LONG)maxcount, (LPCSTR)name);
}

void ocall_sgx_WaitForSingleObject(int handle, unsigned long ms_)
{
	WaitForSingleObject((HANDLE)handle, (DWORD)ms_);
}

int ocall_sgx_ReleaseSemaphore(int hSemaphore, long lReleaseCount, long* lpPreviousCount, int lp_len)
{
	return ReleaseSemaphore((HANDLE)hSemaphore, lReleaseCount, lpPreviousCount);
}

// Clear
int ocall_sgx_CreateIoCompletionPort(int FileHandle, int p, unsigned long k, unsigned long numthreads)
{
	return (int)CreateIoCompletionPort((HANDLE)FileHandle, (HANDLE)p, (ULONG_PTR)k, (DWORD)numthreads);
}

int ocall_sgx_GetQueuedCompletionStatus(int p, unsigned long *numbytes, int numbytes_len, __int64 *k, int k_len, void *lpOverlapped, int lpOverlapped_len, unsigned long dwMilliseconds)
{
	return GetQueuedCompletionStatus((HANDLE)p, (LPDWORD)numbytes, (PULONG_PTR)k, (LPOVERLAPPED*)lpOverlapped, (DWORD)dwMilliseconds);
}

int ocall_sgx_PostQueuedCompletionStatus(int p, unsigned int n, unsigned int key, void *o, int o_len)
{
	return PostQueuedCompletionStatus((HANDLE)p, (DWORD)n, (ULONG_PTR) key, (LPOVERLAPPED)o);
}

int ocall_sgx_CloseHandle(int hObject)
{
	return CloseHandle((HANDLE)hObject);
}

int ocall_sgx_CryptAcquireContext(void *prov, void *container, void *provider, unsigned long provtype, unsigned long dwflags)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return CryptAcquireContext((HCRYPTPROV *)prov, (LPCSTR)container, (LPCSTR)provider, (DWORD)provtype, (DWORD)dwflags);
}

int ocall_sgx_CryptReleaseContext(unsigned long long hProv, unsigned long dwFlags)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return CryptReleaseContext((HCRYPTPROV)hProv, (DWORD)dwFlags);
}
*/

int ocall_sgx_getenv(const char *env, int envlen, char *ret_str,int ret_len)
{
	const char *env_val = getenv(env);
	if(env_val == NULL){
		return -1;
	}
	memcpy(ret_str, env_val, strlen(env_val)+1);
	return 0;
}

int ocall_sgx_getsockname(int s, void *name, int nlen, int *namelen)
{
//	return getsockname((SOCKET)s, (sockaddr *)name, namelen);
	return getsockname(s, (sockaddr *)name, (socklen_t *)namelen);
}

//int ocall_sgx_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen)
int ocall_sgx_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen)
{
	
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
//	return getsockopt((SOCKET)s, level, optname, optval, optlen);
	return getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

void ocall_sgx_getservbyname(const char *name, int name_len, const char *proto, int proto_len, void *serv_ptr, int serv_len)
{
	struct servent *ent;
	ent = getservbyname(name, proto);
	memcpy(serv_ptr, ent, sizeof(struct servent));
}

void ocall_sgx_getprotobynumber(int number, void *proto, int proto_len, char *proto_name, int proto_name_len)
{
	struct protoent *ent;
	ent = getprotobynumber(number);
	memcpy(proto, ent, sizeof(struct protoent));
	memcpy(proto_name, ent->p_name, strlen(ent->p_name) + 1);
}

struct args_set_t
{
	void *args;
	int args_len;
};

void call_enclave_func(void *args)
{
	sgx_status_t ret;
	struct args_set_t *args_set = (struct args_set_t *)args;
	if((ret = enclave_func_caller(global_eid, args_set->args, args_set->args_len)) != SGX_SUCCESS) {
		printf("enclave_func_caller failed!: %x\n", ret);
		abort();
	}
	free(args_set->args);
	free(args);
}

int ocall_sgx_epoll_create(int size)
{
	return epoll_create(size);
}


int ocall_sgx_epoll_ctl(int epfd, int op, int fd, void *event, int event_len)
{
	return epoll_ctl(epfd, op, fd, (struct epoll_event *)event);
}


int ocall_sgx_epoll_wait(int epfd, void *events, int events_len, int maxevents, int timeout)
{
	return epoll_wait(epfd, (struct epoll_event *)events, maxevents, timeout);
}

/**
 * A pthread attribute to make threads start detached.
 */
static pthread_attr_t attr_detached;

/** Wraps a void (*)(void*) function and its argument so we can
 * invoke them in a way pthreads would expect.
 */
typedef struct tor_pthread_data_t {
  void (*func)(void *);
  void *data;
} tor_pthread_data_t;

/** Given a tor_pthread_data_t <b>_data</b>, call _data-&gt;func(d-&gt;data)
 * and free _data.  Used to make sure we can call functions the way pthread
 * expects. */
static void *
pthread_helper_fn(void *_data)
{
  tor_pthread_data_t *data = (tor_pthread_data_t *)_data;
  void (*func)(void*);
  void *arg;
  /* mask signals to worker threads to avoid SIGPIPE, etc */
  sigset_t sigs;
  /* We're in a subthread; don't handle any signals here. */
  sigfillset(&sigs);
//  sigfillset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  func = data->func;
  arg = data->data;
  tor_free(_data);
  func(arg);
  return NULL;
}

int ocall_sgx_pthread_create(void *args, int args_len)
{
  pthread_t thread;
  tor_pthread_data_t *d;

  d = (tor_pthread_data_t *)malloc(sizeof(tor_pthread_data_t));
  d->data = args;
  d->func = call_enclave_func;

  return pthread_create(&thread, &attr_detached, pthread_helper_fn, d);
}

void *sgx_calloc(size_t count, size_t size)
{

#ifdef EVAL_OCALL_COUNT
        ocall_num++;
#endif

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

#ifdef EVAL_OCALL_COUNT
        ocall_num++;
#endif

        if(target != NULL)
                free(target);
}

/*
unsigned long long  ocall_sgx_beginthread(void *args, int args_len)
{
	struct args_set_t *args_set = (struct args_set_t *)calloc(1, sizeof(struct args_set_t));
	args_set->args = (void *)calloc(1, args_len);
	memcpy(args_set->args, args, args_len);
	args_set->args_len = args_len;

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return _beginthread(call_enclave_func, 0, (void *)args_set);
}

void ocall_sgx_endthread(void)
{
	_endthread();
}
*/

static map<int, int> sig_id_map;

void sgx_signal_handle_caller_caller(int signum)
{
	if(sig_id_map.empty() || sig_id_map.find(signum) == sig_id_map.end()) {
		printf("Error: sgx_signal_handle_caller_caller: func_map not found\n");
		return;
	}
	int f_id = sig_id_map[signum];
	sgx_signal_handle_caller(global_eid, signum, f_id);
}

int ocall_sgx_eventfd(unsigned int initval, int flags)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return eventfd(initval, flags);
}

void ocall_sgx_signal(int signum, int f_id)
{
	sig_id_map[signum] = f_id;
	signal(signum, sgx_signal_handle_caller_caller);
}

int ocall_sgx_sigemptyset(void *set, int setlen)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return sigemptyset((sigset_t *)set);
}

int ocall_sgx_sigfillset(void *set, int setlen)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return sigfillset((sigset_t *)set);
}

//int ocall_sgx_sigaction(int signum, const struct sigaction *act, int act_len, struct sigaction *oldact, int oldact_len)
int ocall_sgx_sigaction(int signum, const void *act, int act_len, void *oldact, int oldact_len)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return sigaction(signum, (const struct sigaction *)act, (struct sigaction *)oldact);
}

int ocall_sgx_fcntl(int fd, int cmd, long arg)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return fcntl(fd, cmd, arg);
}

int ocall_sgx_fcntl2(int fd, int cmd, void *lock, int lock_len)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return fcntl(fd, cmd, (struct flock *)lock);
}

/*
int ocall_sgx_fputs(const char *str, FILE *stream, int stream_size)
{
	return fputs(str, stream);
}
*/

/*
unsigned long ocall_sgx_GetAdaptersAddresses(unsigned long family, unsigned long flags, 
				void *addresses, unsigned long addresses_size, unsigned long *psize)
{
#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
	return GetAdaptersAddresses(family, flags, NULL, (IP_ADAPTER_ADDRESSES *)addresses, psize);
}
*/

// For eval
long ocall_sgx_clock(void)
{
	return clock();
}

void build_msg0(ra_samp_request_header_t *msg0)
{
	uint32_t extended_epid_group_id = 0;
  if (sgx_get_extended_epid_group_id(&extended_epid_group_id) != SGX_SUCCESS){
    puts("*** Error, call sgx_get_extended_epid_group_id fail.");
    abort();
  }
  msg0->type = TYPE_RA_MSG0;
  msg0->size = sizeof(uint32_t);
  *(uint32_t *)((uint8_t *)msg0+sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
	puts("Call sgx_get_extended_epid_group_id success.");
  //puts("MSG0 - ");
  //PRINT_BYTE_ARRAY(msg0->body, msg0->size);
}

void build_msg1(ra_samp_request_header_t *msg1)
{
	sgx_status_t ret;
	int count = 0;
  msg1->type = TYPE_RA_MSG1;
  msg1->size = sizeof(sgx_ra_msg1_t);
  while (1){	
		ret = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga,	(sgx_ra_msg1_t*)((uint8_t*)msg1 + sizeof(ra_samp_request_header_t)));
    if(ret == SGX_SUCCESS) {
			break;
		}
		else if (ret == SGX_ERROR_BUSY){
			if (count == 5){ //retried 5 times, so fail out
				puts("*** Error, sgx_ra_get_msg1 is busy - 5 retries failed");
				abort();
			}
//			Sleep(5000);
			sleep(5);
			count++;
		}
		else {
			puts("*** Error, call sgx_ra_get_msg1 fail.");
			abort();
		}
  }
	puts("Call sgx_ra_get_msg1 success.");
	//puts("MSG1 - ");
	//PRINT_BYTE_ARRAY(msg1->body, msg1->size);
}

void build_msg3(ra_samp_response_header_t *msg2, ra_samp_request_header_t **msg3, uint32_t *msg3_full_size)
{
	sgx_status_t ret;
	uint32_t msg3_size = 0;
	int busy_retry_time = 2;
	sgx_ra_msg2_t* msg2_body = (sgx_ra_msg2_t*)((uint8_t*)msg2 + sizeof(ra_samp_response_header_t));
	sgx_ra_msg3_t *msg3_body = NULL;
  do
  {
    ret = sgx_ra_proc_msg2(context,
                        global_eid,
                        sgx_ra_proc_msg2_trusted,
                        sgx_ra_get_msg3_trusted,
                        msg2_body,
                        msg2->size,
                        &msg3_body,
                        &msg3_size);
  } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

  if(!msg3_body) {
      printf("*** Error, call sgx_ra_proc_msg2 fail. msg3_body = 0x%p.", msg3_body);
      abort();
  }
  if(SGX_SUCCESS != (sgx_status_t)ret)
  {
			printf("*** Error, call sgx_ra_proc_msg2 fail. ret = 0x%08x.", ret);
      abort();
  }
	
	*msg3_full_size = sizeof(ra_samp_request_header_t) + msg3_size;
	*msg3 = (ra_samp_request_header_t*)sgx_calloc(1, *msg3_full_size);
	(*msg3)->type = TYPE_RA_MSG3;
  (*msg3)->size = msg3_size;

  if(memcpy_s((*msg3)->body, msg3_size, msg3_body, msg3_size)) {
      puts("*** Error, memcpy_s failed.");
			abort();
  }
	sgx_free(msg3_body);
	puts("Call sgx_ra_proc_msg2 success.");
  //puts("MSG3 - ");
	//PRINT_BYTE_ARRAY((*msg3)->body, msg3_size);
}

int verify_msg4(ra_samp_response_header_t *msg4)
{
	sgx_status_t ret, status;
	sample_ra_att_result_msg_t * p_msg4_body ;
	if(TYPE_RA_ATT_RESULT != msg4->type) {
    printf("*** Error, Received was NOT of type MSG4. Type = %d.", msg4->type);
    return -1;
  }
	p_msg4_body = (sample_ra_att_result_msg_t *)((uint8_t*)msg4 + sizeof(ra_samp_response_header_t));
	ret = verify_att_result_mac(global_eid,
															&status,
															context,
															(uint8_t*)&p_msg4_body->platform_info_blob,
															sizeof(ias_platform_info_blob_t),
															(uint8_t*)&p_msg4_body->mac,
															sizeof(sgx_mac_t));
	if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status))	{
		puts("Error: INTEGRITY FAILED - attestation result message MK based cmac failed.");
		return -1;
	}
	puts("Call verify_att_result_mac success.");
	//puts("MSG4 - ");
	//PRINT_BYTE_ARRAY(msg4->body, msg4->size);
	return 0;
}

int connect_server(struct sockaddr_in *servAdr)
{
	int hSocket;

	hSocket = socket(PF_INET, SOCK_STREAM, 0);
//	if(hSocket == INVALID_SOCKET){
	if(hSocket == -1){
		puts("*** Error, invalid socket");		
		goto err;
	}
	if(connect(hSocket, (const struct sockaddr *)servAdr, sizeof(struct sockaddr))==-1){
		puts("*** Error, connect");
		close(hSocket);
		goto err;
	}
	puts("Connect Success!");
	return hSocket;

err:
	abort();
	return -1;
}

int SEND(int s, void *msg, int size)
{
	int n, e;
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		end_time = clock();
		diff += (end_time - start_time) / (double)1000;
	}
#endif
	n = send(s, (const char *)msg, size, 0);
	if (n < 0) {
		abort();
/*
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e);
		if (e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
			Sleep(1000);
			return SEND(s, msg, size);
		}
		else {
			abort();
		}
*/
	}
#ifdef EVAL_REMOTE_ATTEST_COUNT
	if (is_remote_attest_start) {
		send_cnt++;
		send_byte += n;
	}
#endif
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		start_time = clock();
	}
#endif
	return n;
}

int RECV(int s, void *msg, int size)
{
	int n, e;
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		end_time = clock();
		diff += (end_time - start_time) / (double)1000;
	}
#endif
	n = recv(s, (char *)msg, size, 0);
	if (n < 0) {
		abort();
/*
		e = WSAGetLastError();
		printf("Error, recv: %d\n", e);
		if (e == WSAEWOULDBLOCK || e == WSAENOTCONN) {
			Sleep(1000);
			return RECV(s, msg, size);
		}
		else {
			abort();
		}
*/
	}
#ifdef EVAL_REMOTE_ATTEST_COUNT
	if (is_remote_attest_start) {
		recv_cnt++;
		recv_byte += n;
	}
#endif
#ifdef EVAL_REMOTE_ATTEST_TIME
	if (is_remote_attest_start) {
		start_time = clock();
	}
#endif
	return n;
}

void init_ra()
{
	sgx_status_t ret, status;
	ret = enclave_init_ra(global_eid,
                        &status,
                        false,
                        &context);

	if (SGX_SUCCESS != ret){
		puts("*** Error, Enclave RA Initialization failed ***");
		abort();
	}
}

int start_remote_attestation_client()
{
        int n, is_ok;
        ra_samp_request_header_t *p_msg0_full = NULL;
        ra_samp_request_header_t *p_msg1_full = NULL;
        ra_samp_response_header_t *p_msg2_full = NULL;
        ra_samp_request_header_t *p_msg3_full = NULL;
        ra_samp_response_header_t* p_msg4_full = NULL;

        list<struct sockaddr_in *>::iterator iter;
        for(iter = remote_list.begin(); iter != remote_list.end(); iter++) {
                int ret = -1;
		uint32_t msg0_full_size = 0;
		uint32_t msg1_full_size = 0;
                uint32_t msg2_full_size = 0;
                uint32_t msg3_full_size = 0;
		uint32_t msg4_full_size = 0;
		int server_fd;
                printf("Client Remote Attestation Start!\n");
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
                start_time = clock();
#endif
//                SOCKET server_fd = connect_server(*iter);
                server_fd = connect_server(*iter);

                msg0_full_size = sizeof(ra_samp_request_header_t)+sizeof(uint32_t);
                p_msg0_full = (ra_samp_request_header_t *)sgx_calloc(1, msg0_full_size);
                build_msg0(p_msg0_full);
                SEND(server_fd, p_msg0_full, msg0_full_size);
                puts("Send MSG0 success!");
                RECV(server_fd, &is_ok, sizeof(int));
                if( is_ok != 1234){
                        printf("remote attestation fail \n");
                        goto err;
                }
                init_ra();
                puts("Call enclave_init_ra success.");

                msg1_full_size = sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t);
                p_msg1_full = (ra_samp_request_header_t*)sgx_calloc(1, msg1_full_size);
                build_msg1(p_msg1_full);
                SEND(server_fd, p_msg1_full, msg1_full_size);
                puts("Send MSG1 success!");
                RECV(server_fd, &is_ok, sizeof(int));
                if( is_ok != 1234){
                        printf("remote attestation fail \n");
                        goto err;
                }

                RECV(server_fd, &msg2_full_size, sizeof(uint32_t));
                p_msg2_full = (ra_samp_response_header_t *)sgx_calloc(1, msg2_full_size);
                RECV(server_fd, p_msg2_full, msg2_full_size);
                //puts("Receive MSG2 success!");
                //PRINT_BYTE_ARRAY(p_msg2_full, sizeof(ra_samp_response_header_t) + p_msg2_full->size);

                build_msg3(p_msg2_full, &p_msg3_full, &msg3_full_size);
                SEND(server_fd, &msg3_full_size, sizeof(uint32_t));
                SEND(server_fd, p_msg3_full, msg3_full_size);
                puts("Send MSG3 success!");
                RECV(server_fd, &is_ok, sizeof(int));
                if( is_ok != 1234){
                        printf("remote attestation fail \n");
                        goto err;
                }
                msg4_full_size = sizeof(sample_ra_att_result_msg_t)+sizeof(ra_samp_response_header_t)+8;
                p_msg4_full = (ra_samp_response_header_t *)sgx_calloc(1, msg4_full_size);
                RECV(server_fd, p_msg4_full, msg4_full_size);
                puts("Receive MSG4 success!");

                if(verify_msg4(p_msg4_full) != 0) {
                        printf("remote attestation fail \n");
                        goto err;
		}
err:
                sgx_free(p_msg0_full);
                sgx_free(p_msg1_full);
                sgx_free(p_msg2_full);
                sgx_free(p_msg3_full);
                sgx_free(p_msg4_full);
                close(server_fd);
                if(ret != 0) {
                        puts("\nRemote Attestation Failed!");
                        return -1;
                }
#ifdef EVAL_REMOTE_ATTEST_TIME
                is_remote_attest_start = false;
                if (is_remote_attest_start) {
                        end_time = clock();
                        diff += (end_time - start_time) / (double)1000;
                }
                printf("Time for remote attestation : %lf\n", diff);

#endif
#ifdef EVAL_REMOTE_ATTEST_COUNT
                is_remote_attest_start = false;
                printf("Count: send = %d, recv = %d\nBytes: send = %d bytes, recv = %d bytes\n", send_cnt, recv_cnt, send_byte, recv_byte);

		printf("Pausing.. Enter a character ...\n");
		getchar();
//                system("pause");
#endif
        }
        return 0;
}

/**************************************************************************/
/*************************** Remote attestation Start ***************************/

typedef struct attest_pthread_data_t {
  void (*func)();
  void *data;
} attest_pthread_data_t;

/** Given a tor_pthread_data_t <b>_data</b>, call _data-&gt;func(d-&gt;data)
 * and free _data.  Used to make sure we can call functions the way pthread
 * expects. */
static void *
attest_pthread_helper_fn(void *_data)
{
  attest_pthread_data_t *data = (attest_pthread_data_t *)_data;
  void (*func)();
  /* mask signals to worker threads to avoid SIGPIPE, etc */
  sigset_t sigs;
  /* We're in a subthread; don't handle any signals here. */
  sigfillset(&sigs);
//  sigfillset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  func = data->func;
  tor_free(_data);
  func();
  return NULL;
}

void start_remote_attestation_server()
{
	int fd, r, sgx_cert_cont_size, sgx_pkey_cont_size;
	char *path;
	void *sgx_cert_cont, *sgx_pkey_cont;
	struct stat statbuf;

	path = "/home/maple/smkim/client.crt";
	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		printf("unable to open torrc! path: %s\n", path);
		return;
	}
	if (fstat(fd, &statbuf) < 0) {
		printf("unable to fstat torrc! path: %s\n", path);
		return;
	}
	if ((uint64_t)(statbuf.st_size) >= SIZE_T_CEILING) {
		close(fd);
		printf("unable to fstat torrc! path: %s\n", path);
		return;
	}
	sgx_cert_cont_size = statbuf.st_size;
	sgx_cert_cont = (char *)malloc(sgx_cert_cont_size);
	r = read_all(fd, (char *)sgx_cert_cont, sgx_cert_cont_size, 0);
	if (r < 0) {
		printf("unable to read torrc! path: %s\n", path);
		return;
	}
	close(fd);

//	path = "D:\\demo\\client.key";
	path = "/home/maple/smkim/client.key";
	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		printf("unable to open torrc! path: %s\n", path);
		return;
	}
	if (fstat(fd, &statbuf) < 0) {
		printf("unable to fstat torrc! path: %s\n", path);
		return;
	}
	if ((uint64_t)(statbuf.st_size) >= SIZE_T_CEILING) {
		close(fd);
		printf("unable to fstat torrc! path: %s\n", path);
		return;
	}
	sgx_pkey_cont_size = statbuf.st_size;
	sgx_pkey_cont = (char *)malloc(sgx_pkey_cont_size);
	r = read_all(fd, (char *)sgx_pkey_cont, sgx_pkey_cont_size, 0);
	if (r < 0) {
		printf("unable to read torrc! path: %s\n", path);
		return;
	}
	close(fd);
	printf("127.0.0.1 = %lu", inet_addr("127.0.0.1"));
	sgx_start_remote_attestation_server(global_eid, remote_attest_server_port, sgx_cert_cont, sgx_cert_cont_size, sgx_pkey_cont, sgx_pkey_cont_size, my_ip);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

#if 0
  HMODULE hMod = GetModuleHandleA("Kernel32.dll");
  if (hMod) {
    typedef BOOL (WINAPI *PSETDEP)(DWORD);
    PSETDEP setdeppolicy = (PSETDEP)GetProcAddress(hMod,
                           "SetProcessDEPPolicy");
    if (setdeppolicy) setdeppolicy(1); /* PROCESS_DEP_ENABLE */
  }

        /* SGX-Tor: network_init() WSAStartup */
        WSADATA WSAData;
  int r;
  r = WSAStartup(0x101,&WSAData);
  if (r) {
    printf("Error initializing windows network layer: code was %d",r);
    return -1;
  }
        MEMORYSTATUSEX mse;
        memset(&mse, 0, sizeof(mse));
  	mse.dwLength = sizeof(mse);
        GlobalMemoryStatusEx(&mse);
#endif

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

/*------------------------------------------------------------------------------*/
/* Start Tor code */
#define TOR_CLIENT 0
#define TOR_RELAY 1
#define TOR_DIR_SERVER 2
#define DIR_MONTH "12"

// For eval
#ifdef EVAL_SEALING 
        system_clock::time_point start, end;
        long long diff = 0;
#endif

#ifdef EVAL_INITIALIZATION
        system_clock::time_point start, end;
        long long diff = 0;
#endif

        sgx_status_t ret = SGX_SUCCESS;
        sgx_launch_token_t token = {0};
        int updated = 0, argv_len = 0;
        char *torrc_path = NULL, *torrc = NULL;

                /* Call SetProcessDEPPolicy to permanently enable DEP.
    The function will not resolve on earlier versions of Windows,
    and failure is not dangerous. */

        for(int i = 0; i < argc; i++) {
                if(!strcmp(argv[i], "-f")) {
                        torrc_path = argv[i+1];
                }
                argv_len += strlen(argv[i]) + 1;
        }

        torrc = load_torrc(torrc_path);
        if(torrc == NULL) {
                printf("Run as CLIENT mode!\n");
        }
        else if(strstr(torrc, "AuthoritativeDirectory 1") != NULL){
                printf("Run as DIR SERVER mode!\n");
#ifndef TEST_SGX_TOR
                char *cert_path, *data_path, *fing_path, *fname;
                char *tor_fing = (char *)calloc(1, 1024);
                char *tor_cert = (char *)calloc(1, 8192);
        #define TOR_SEALING(FN) \
                fname = #FN; \
                FN = calloc(1, 8192); \
                if(SGX_SUCCESS != sgx_seal_files(global_eid, fname, FN)) \
                        return -1;
        #define TOR_UNSEALING(FN) \
                fname = #FN; \
                if(SGX_SUCCESS != sgx_unseal_files(global_eid, fname, FN)) \
                        return -1; \
                free(FN);               

#ifdef EVAL_INITIALIZATION
                start = system_clock::now();
#endif
                // 1. Tor Gencert
                if((ret = sgx_start_gencert(global_eid, tor_cert, (unsigned long long)&errno, DIR_MONTH, dir_address)) != SGX_SUCCESS){
                        printf("sgx_start_gencert failed... Error code = %d\n", ret);
                        goto done;
                }
                cert_path = (char *)calloc(1, 1024);
                strncpy(cert_path, torrc_path, strlen(torrc_path)-5);
                strcat(cert_path, "keys/authority_certificate");
//              printf("cert path = %s\n", cert_path);
                write_file(cert_path, tor_cert);
                free(tor_cert);
                free(cert_path);

#ifdef EVAL_INITIALIZATION
                end = system_clock::now();
                diff += duration_cast<milliseconds>(end - start).count();
#endif

                data_path = (char *)calloc(1, 1024);
                strncpy(data_path, torrc_path, strlen(torrc_path)-6);

                // 2. Tor do-list-fingerprint
#ifndef EVAL_INITIALIZATION
                if((ret = sgx_start_fingerprint(global_eid, tor_fing, data_path, torrc,
                                        (unsigned long long)&errno, &mse)) != SGX_SUCCESS){
                        printf("sgx_start_gencert failed... Error code = %d\n", ret);
                        goto done;
                }
                free(data_path);
                fing_path = (char *)calloc(1, 1024);
                strncpy(fing_path, torrc_path, strlen(torrc_path)-5);
                strcat(fing_path, "fingerprint");
//              printf("fingerprint path = %s\n", fing_path);
//              printf("fingerprint =  %s\n", tor_fing);
                write_file(fing_path, tor_fing);
                free(tor_fing);
                free(fing_path);
#endif

#ifdef EVAL_INITIALIZATION
                start = system_clock::now();
#endif
#ifdef EVAL_SEALING
                start = system_clock::now();
#endif

                void *authority_signing_key, *authority_identity_key, *authority_certificate,
                        *ed25519_master_id_public_key, *ed25519_master_id_secret_key, *ed25519_signing_cert, *ed25519_signing_secret_key,
                        *secret_id_key, *secret_onion_key, *secret_onion_key_ntor,      *fingerprint;
                // 3. Sealing private key sets and fingerprint
                TOR_SEALING(authority_signing_key);
                TOR_SEALING(authority_identity_key);
                TOR_SEALING(authority_certificate);
#ifndef EVAL_INITIALIZATION
                TOR_SEALING(ed25519_master_id_public_key);
                TOR_SEALING(ed25519_master_id_secret_key);
                TOR_SEALING(ed25519_signing_cert);
                TOR_SEALING(ed25519_signing_secret_key);
                TOR_SEALING(secret_id_key);
                TOR_SEALING(secret_onion_key);
                TOR_SEALING(secret_onion_key_ntor);
                TOR_SEALING(fingerprint);
#endif

#ifdef EVAL_INITIALIZATION
                end = system_clock::now();
                diff += duration_cast<milliseconds>(end - start).count();
#endif

#ifdef EVAL_SEALING
                end = system_clock::now();
                diff += duration_cast<milliseconds>(end - start).count();
                printf("Sealing: %15lld milli seconds\n", diff);
#endif
                if(SGX_SUCCESS != sgx_destroy_enclave(global_eid))
                        return -1;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
                if (ret != SGX_SUCCESS) {
                        printf("App: error %#x, failed to create enclave.\n", ret);
                        return -1;
                }

#ifdef EVAL_INITIALIZATION
                start = system_clock::now();
#endif

#ifdef EVAL_SEALING
                start = system_clock::now();
#endif

                // 6. Unsealing private key sets and fingerprint
                TOR_UNSEALING(authority_signing_key);
                TOR_UNSEALING(authority_identity_key);
                TOR_UNSEALING(authority_certificate);
#ifndef EVAL_INITIALIZATION
                TOR_UNSEALING(ed25519_master_id_public_key);
                TOR_UNSEALING(ed25519_master_id_secret_key);
                TOR_UNSEALING(ed25519_signing_cert);
                TOR_UNSEALING(ed25519_signing_secret_key);
                TOR_UNSEALING(secret_id_key);
                TOR_UNSEALING(secret_onion_key);
                TOR_UNSEALING(secret_onion_key_ntor);
                TOR_UNSEALING(fingerprint);
#endif

#ifdef EVAL_INITIALIZATION
                // For eval
                end = system_clock::now();
                diff += duration_cast<milliseconds>(end - start).count();
                printf("Time : %15lld milli seconds\n", diff);
#ifdef EVAL_OCALL_COUNT
                printf("Context switch = %d\n", ocall_num);
#endif
		printf("Pausing.. Enter a character ...\n");
		getchar();
//                system("pause");
#endif

#ifdef EVAL_SEALING
                // For eval
                end = system_clock::now();
                diff = duration_cast<milliseconds>(end - start).count();
                printf("Unsealing: %15lld milli seconds\n", diff);
		printf("Pausing.. Enter a character ...\n");
		getchar();
//                system("pause");
#endif
                printf("Authority certificate and fingerprint was made\nExecute ina_setting!\n");

		printf("Pausing.. Enter a character ...\n");
		getchar();
//                system("pause");
                free(torrc);
                torrc = load_torrc(torrc_path);
#else // TEST_SGX_TOR
        int key_len;
        char *fing_path, *key_path, *tmp_path;
        char *fingerprint, *authority_signing_key, *authority_identity_key, *authority_certificate,
                        *ed25519_master_id_public_key, *ed25519_master_id_secret_key, *ed25519_signing_cert, *ed25519_signing_secret_key,
                        *secret_id_key, *secret_onion_key, *secret_onion_key_ntor;
        fing_path = (char *)calloc(1, 1024);
        key_path = (char *)calloc(1, 1024);
        tmp_path = (char *)calloc(1, 1024);

        strncpy(fing_path, torrc_path, strlen(torrc_path) - 5);
        strncpy(key_path, torrc_path, strlen(torrc_path) - 5);
        strcat(key_path, "keys/");
        printf("key_path = %s\n", key_path);

        strcat(fing_path, "fingerprint");
        printf("fing_path = %s\n", fing_path);
        if (load_keys_fing(fing_path, O_TEXT, &fingerprint, &key_len) < 0) {
                printf("load failed! %s\n", fing_path);
                abort();
        }
        ret = test_sgx_put_gencert(global_eid, "fingerprint", fingerprint, key_len);
        if (ret != SGX_SUCCESS) {
                printf("App: error %#x, failed to create enclave.\n", ret);
                abort();
        }
#define PUT_KEYS(FN, FLAG) \
        memset(tmp_path, 0, 1024); \
        strncpy(tmp_path, key_path, strlen(key_path)); \
        strcat(tmp_path, #FN); \
        if (load_keys_fing(tmp_path, FLAG, &FN, &key_len) < 0) {        \
                printf("load failed! %s\n", FN); \
                abort(); \
        } \
        ret = test_sgx_put_gencert(global_eid, #FN, FN, key_len); \
        if (ret != SGX_SUCCESS) { \
                printf("App: error %#x, failed to create enclave.\n", ret); \
                abort(); \
        } \
        free(FN);

        PUT_KEYS(authority_signing_key, O_TEXT);
        PUT_KEYS(authority_identity_key, O_TEXT);
        PUT_KEYS(authority_certificate, O_TEXT);
        PUT_KEYS(ed25519_master_id_public_key, O_BINARY);
        PUT_KEYS(ed25519_master_id_secret_key, O_BINARY);
        PUT_KEYS(ed25519_signing_cert, O_BINARY);
        PUT_KEYS(ed25519_signing_secret_key, O_BINARY);
        PUT_KEYS(secret_id_key, O_TEXT);
        PUT_KEYS(secret_onion_key, O_TEXT);
        PUT_KEYS(secret_onion_key_ntor, O_BINARY);

        free(fing_path);
        free(key_path);
        free(tmp_path);

#endif // TEST_SGX_TOR
        }

/*
        OSVERSIONINFOEX info;
        memset(&info, 0, sizeof(info));
 	info.dwOSVersionInfoSize = sizeof(info);
        GetVersionEx((LPOSVERSIONINFOA)&info);
        char app_system_dir[MAX_PATH];
        GetSystemDirectory((LPSTR)app_system_dir, (UINT)MAX_PATH);

        SYSTEM_INFO sys_info;
  	memset(&sys_info, 0, sizeof(sys_info));
        GetSystemInfo(&sys_info);
*/

//TODO
///////////////////

        if (remote_attest_server_port != -1) {
		int tid;
		pthread_t thread;
		attest_pthread_data_t *d;

  		d = (attest_pthread_data_t *)malloc(sizeof(attest_pthread_data_t));
  		d->data = NULL;
  		d->func = start_remote_attestation_server;

		tid = pthread_create(&thread, &attr_detached, attest_pthread_helper_fn, d);
		if(tid == -1) {
                        printf("Error, pthread_create\n");
                        goto done;
		}
/*
                HANDLE t;
                DWORD tid;
                t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start_remote_attestation_server, NULL, 0, &tid);
                if(t == NULL) {
                        printf("Error, CreateThread\n");
                        goto done;
                }
*/
		printf("Pausing.. Enter a character ...\n");
		getchar();
//                system("pause");
        }
        if(!remote_list.empty()) {
                int ret;
                ret = start_remote_attestation_client();
                if(ret != 0) {
                        printf("Remote attestation failed\n");
                        goto done;
                }
        }

        if( (ret = StartTorSGX(global_eid, argc, argv, argv_len,
//                        (void *)&info, info.dwOSVersionInfoSize, // GetVersion
                        (unsigned long long)&errno, (unsigned long long)&environ, // errno address
  //                      get_sgx_get_windows_conf_root(), torrc,
			torrc
//                        (const char *)app_system_dir,
//                        &mse, &sys_info
                        )) != SGX_SUCCESS) {
                printf("StartTorSGX failed... Error code = %d\n", ret);
        }
        printf("StartTorSGX Success = %d\n", ret);


/*------------------------------------------------------------------------------*/

#if 0 
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();
#endif

    /* Destroy the enclave */
done:
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

