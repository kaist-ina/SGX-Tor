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


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
void log_err(int op, const char *fmt, ...);
void log_notice(int op, const char *fmt, ...);
void log_info(int op, const char *fmt, ...);
void log_warn(int op, const char *fmt, ...);
void puts(const char *s);

//void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#define LOG_DEBUG   7
/** Info-level severity: for messages that appear frequently during normal
 * operation. */
#define LOG_INFO    6
/** Notice-level severity: for messages that appear infrequently
 * during normal operation; that the user will probably care about;
 * and that are not errors.
 */
#define LOG_NOTICE  5
/** Warn-level severity: for messages that only appear when something has gone
 * wrong. */
#define LOG_WARN    4
/** Error-level severity: for messages that only appear when something has gone
 * very wrong, and the Tor process can no longer proceed. */
#define LOG_ERR     3

//#endif

/* Logging domains */

/** Catch-all for miscellaneous events and fatal errors. */
#define LD_GENERAL  (1u<<0)
/** The cryptography subsystem. */
#define LD_CRYPTO   (1u<<1)
/** Networking. */
#define LD_NET      (1u<<2)
/** Parsing and acting on our configuration. */
#define LD_CONFIG   (1u<<3)
/** Reading and writing from the filesystem. */
#define LD_FS       (1u<<4)
/** Other servers' (non)compliance with the Tor protocol. */
#define LD_PROTOCOL (1u<<5)
/** Memory management. */
#define LD_MM       (1u<<6)
/** HTTP implementation. */
#define LD_HTTP     (1u<<7)
/** Application (socks) requests. */
#define LD_APP      (1u<<8)
/** Communication via the controller protocol. */
#define LD_CONTROL  (1u<<9)
/** Building, using, and managing circuits. */
#define LD_CIRC     (1u<<10)
/** Hidden services. */
#define LD_REND     (1u<<11)
/** Internal errors in this Tor process. */
#define LD_BUG      (1u<<12)
/** Learning and using information about Tor servers. */
#define LD_DIR      (1u<<13)
/** Learning and using information about Tor servers. */
#define LD_DIRSERV  (1u<<14)
#define LD_OR       (1u<<15)
/** Generic edge-connection functionality. */
#define LD_EDGE     (1u<<16)
#define LD_EXIT     LD_EDGE
/** Bandwidth accounting. */
#define LD_ACCT     (1u<<17)
/** Router history */
#define LD_HIST     (1u<<18)
/** OR handshaking */
#define LD_HANDSHAKE (1u<<19)
/** Heartbeat messages */
#define LD_HEARTBEAT (1u<<20)
/** Abstract channel_t code */
#define LD_CHANNEL   (1u<<21)
/** Scheduler */
#define LD_SCHED     (1u<<22)
/** Number of logging domains in the code. */
#define N_LOGGING_DOMAINS 23

/** This log message is not safe to send to a callback-based logger
 * immediately.  Used as a flag, not a log domain. */
#define LD_NOCB (1u<<31)
/** This log message should not include a function name, even if it otherwise
 * would. Used as a flag, not a log domain. */
#define LD_NOFUNCNAME (1u<<30)

#endif /* !_ENCLAVE_H_ */
