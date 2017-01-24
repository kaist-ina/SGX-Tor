#ifndef TOR_REMOTE_ATTEST_SEVER_H
#define TOR_REMOTE_ATTEST_SEVER_H

#if defined(__cplusplus)
extern "C" {
#endif

void do_remote_attestatation_server(int port);
int check_remote_accept_list(unsigned long ip);

#if defined(__cplusplus)
}
#endif

#endif