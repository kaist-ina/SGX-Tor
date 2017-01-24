/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define _GNU_SOURCE

#include "orconfig.h"
#include <time.h>

#include "compat.h"
#include "torlog.h"
#include "util.h"

/** True iff we've called tor_threads_init() */
static int threads_initialized = 0;

/** Minimalist interface to run a void function in the background.  On
 * Unix calls pthread_create, on win32 calls beginthread.  Returns -1 on
 * failure.
 * func should not return, but rather should call spawn_exit.
 *
 * NOTE: if <b>data</b> is used, it should not be allocated on the stack,
 * since in a multithreaded environment, there is no way to be sure that
 * the caller's stack will still be around when the called function is
 * running.
 */
int
spawn_func(void (*func)(void *), void *data, int data_len)
{
  int rv;
  rv = (int)sgx_beginthread(func, 0, data, data_len);
  if (rv == -1)
    return -1;
  return 0;
}

/** End the current thread/process.
 */
void
spawn_exit(void)
{
  sgx_endthread();
  //we should never get here. my compiler thinks that _endthread returns, this
  //is an attempt to fool it.
  tor_assert(0);
  _exit(0);
}

/** A mutex attribute that we're going to use to tell pthreads that we want
 * "recursive" mutexes (i.e., once we can re-lock if we're already holding
 * them.) */
static sgx_thread_mutexattr_t attr_recursive;

/** Initialize <b>mutex</b> so it can be locked.  Every mutex must be set
 * up with tor_mutex_init() or tor_mutex_new(); not both. */
void
tor_mutex_init(tor_mutex_t *mutex)
{
	int err;
  if (PREDICT_UNLIKELY(!threads_initialized))
    tor_threads_init();
  err = sgx_thread_mutex_init(&mutex->mutex, &attr_recursive);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d creating a mutex.", err);
    tor_fragile_assert();
  }
}

/** As tor_mutex_init, but initialize a mutex suitable that may be
 * non-recursive, if the OS supports that. */
void
tor_mutex_init_nonrecursive(tor_mutex_t *mutex)
{
  int err;
  if (PREDICT_UNLIKELY(!threads_initialized))
    tor_threads_init();
  err = sgx_thread_mutex_init(&mutex->mutex, NULL);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d creating a mutex.", err);
    tor_fragile_assert();
  }
}

/** Wait until <b>m</b> is free, then acquire it. */
void
tor_mutex_acquire(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = sgx_thread_mutex_lock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d locking a mutex.", err);
    tor_fragile_assert();
  }
}

/** Release the lock <b>m</b> so another thread can have it. */
void
tor_mutex_release(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = sgx_thread_mutex_unlock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d unlocking a mutex.", err);
    tor_fragile_assert();
  }
}

/** Clean up the mutex <b>m</b> so that it no longer uses any system
 * resources.  Does not free <b>m</b>.  This function must only be called on
 * mutexes from tor_mutex_init(). */
void
tor_mutex_uninit(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = sgx_thread_mutex_destroy(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d destroying a mutex.", err);
    tor_fragile_assert();
  }
}

/** Return an integer representing this thread. */
unsigned long
tor_get_thread_id(void)
{
  unsigned long r;
  r = (unsigned long)sgx_thread_self();
  return r;
}

/* Conditions. */

/** Initialize an already-allocated condition variable. */
int
tor_cond_init(tor_cond_t *cond)
{
  sgx_thread_condattr_t condattr;

  memset(cond, 0, sizeof(tor_cond_t));

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
  /* Use monotonic time so when we timedwait() on it, any clock adjustment
   * won't affect the timeout value. */
  if (pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC)) {
    return -1;
  }
#endif
  if (sgx_thread_cond_init(&cond->cond, &condattr)) {
    return -1;
  }
  return 0;
}

/** Release all resources held by <b>cond</b>, but do not free <b>cond</b>
 * itself. */
void
tor_cond_uninit(tor_cond_t *cond)
{
  if (sgx_thread_cond_destroy(&cond->cond)) {
    log_warn(LD_GENERAL,"Error freeing condition: %s", strerror(errno));
    return;
  }
}
/** Wait until one of the tor_cond_signal functions is called on <b>cond</b>.
 * (If <b>tv</b> is set, and that amount of time passes with no signal to
 * <b>cond</b>, return anyway.  All waiters on the condition must wait holding
 * the same <b>mutex</b>.  All signallers should hold that mutex.  The mutex
 * needs to have been allocated with tor_mutex_init_for_cond().
 *
 * Returns 0 on success, -1 on failure, 1 on timeout. */
int
tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex, const struct timeval *tv)
{
  int r;
#ifndef TOR_SGX
  if (tv == NULL) {
#endif // TOR_SGX
    while (1) {
      r = sgx_thread_cond_wait(&cond->cond, &mutex->mutex);
      if (r == EINTR) {
        /* EINTR should be impossible according to POSIX, but POSIX, like the
         * Pirate's Code, is apparently treated "more like what you'd call
         * guidelines than actual rules." */
        continue;
      }
      return r ? -1 : 0;
    }
#ifndef TOR_SGX
  } else {
    struct timeval tvnow, tvsum;
    struct timespec ts;
    while (1) {
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
      if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        return -1;
      }
      tvnow.tv_sec = ts.tv_sec;
      tvnow.tv_usec = ts.tv_nsec / 1000;
      timeradd(tv, &tvnow, &tvsum);
#else
      if (gettimeofday(&tvnow, NULL) < 0)
        return -1;
      timeradd(tv, &tvnow, &tvsum);
#endif /* HAVE_CLOCK_GETTIME, CLOCK_MONOTONIC */

      ts.tv_sec = tvsum.tv_sec;
      ts.tv_nsec = tvsum.tv_usec * 1000;

      r = pthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts);
      if (r == 0)
        return 0;
      else if (r == ETIMEDOUT)
        return 1;
      else if (r == EINTR)
        continue;
      else
        return -1;
    }
  }
#endif // TOR_SGX
}
/** Wake up one of the waiters on <b>cond</b>. */
void
tor_cond_signal_one(tor_cond_t *cond)
{
  sgx_thread_cond_signal(&cond->cond);
}
/** Wake up all of the waiters on <b>cond</b>. */
void
tor_cond_signal_all(tor_cond_t *cond)
{
  sgx_thread_cond_broadcast(&cond->cond);
}

int
tor_threadlocal_init(tor_threadlocal_t *threadlocal)
{
  threadlocal->index = sgx_TlsAlloc();
  return (threadlocal->index == TLS_OUT_OF_INDEXES) ? -1 : 0;
}

void
tor_threadlocal_destroy(tor_threadlocal_t *threadlocal)
{
	/* This function will not be called any where */
#ifndef TOR_SGX
  TlsFree(threadlocal->index);
  memset(threadlocal, 0, sizeof(tor_threadlocal_t));
#endif // TOR_SGX
}

void *
tor_threadlocal_get(tor_threadlocal_t *threadlocal)
{
  void *value = sgx_TlsGetValue(threadlocal->index);
  if (value == NULL) {
    DWORD err = sgx_GetLastError();
    if (err != ERROR_SUCCESS) {
      char *msg = format_win32_error(err);
      log_err(LD_GENERAL, "Error retrieving thread-local value: %s", msg);
      tor_free(msg);
      tor_assert(err == ERROR_SUCCESS);
    }
  }
  return value;
}

void
tor_threadlocal_set(tor_threadlocal_t *threadlocal, void *value)
{
  BOOL ok = sgx_TlsSetValue(threadlocal->index, value);
  if (!ok) {
    DWORD err = sgx_GetLastError();
    char *msg = format_win32_error(err);
    log_err(LD_GENERAL, "Error adjusting thread-local value: %s", msg);
    tor_free(msg);
    tor_assert(ok);
  }
}

/** Set up common structures for use by threading. */
void
tor_threads_init(void)
{
  if (!threads_initialized) {
#ifndef PTHREAD_CREATE_DETACHED
#define PTHREAD_CREATE_DETACHED 1
#endif
    threads_initialized = 1;
    set_main_thread();
  }
}