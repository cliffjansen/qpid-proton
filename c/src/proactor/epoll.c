/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

/*
 WIP: new epoll proactor.
 Old: each thread without work called epoll_wait for 1 event.
 New: when known work exhausted, only one thread calls epoll_wait for N events.

 Also new: the "poller" thread looks through a small portion of a new snapshot of work and
 looks for warm threads that could be re-assigned to previous context work.  If a thread
 looking for work has not been assigned a context, it looks for the next available one and
 self-assigns to it.  With no work available, a thread either becomes the poller or
 suspends on a condition var.

 The above is protected by a single scheduler mutex per proactor.  Possibly hotly
 contested and worth measuring.

 A serialized grouping of Proton events is a context (connection, listener, proactor).
 Each has multiple pollable fds that make it schedulable.  E.g. a connection could have a
 socket fd, timerfd, and (indirect) eventfd all signaled in a single epoll_wait().

 At the conclusion of each
      N = epoll_wait(..., N_MAX, timeout)

 there will be N epoll events and M wakes on the wake list.  M can be very large in a
 dispatch router with many active connections. The poller makes the contexts "runnable" if
 they are not already running.  N+M-duplicates contexts will be scheduled and the next
 epoll_wait will be after a thread finds no more work to do.

 A running context, before it stops "working" must check to see if there were new incoming
 events that the poller posted to the context, but could not make it runnable since it was
 already running.  The context will know if it needs to put itself back on the wake list
 to be runnable later to process the pending events.


 lock ordering: context/sched/wake  never add locks right to left.

 "ZZZ" in the code indicates impermanent cruft: debug code or vars or reminders to fix.
 */


/* Enable POSIX features beyond c99 for modern pthread and standard strerror_r() */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* Avoid GNU extensions, in particular the incompatible alternative strerror_r() */
#undef _GNU_SOURCE

#include "../core/log_private.h"
#include "./proactor-internal.h"
#include "../core/util.h"

#include <proton/condition.h>
#include <proton/connection_driver.h>
#include <proton/engine.h>
#include <proton/proactor.h>
#include <proton/transport.h>
#include <proton/listener.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/eventfd.h>
#include <limits.h>
#include <time.h>

#include "./netaddr-internal.h" /* Include after socket/inet headers */

static bool dbgz = false;
static bool ZZZdbgy = false;

// TODO: replace timerfd per connection with global lightweight timer mechanism.
// logging in general
// SIGPIPE?
// Can some of the mutexes be spinlocks (any benefit over adaptive pthread mutex)?
//   Maybe futex is even better?
// See other "TODO" in code.
//
// Consider case of large number of wakes: proactor_do_epoll() could start by
// looking for pending wakes before a kernel call to epoll_wait(), or there
// could be several eventfds with random assignment of wakeables.


typedef char strerrorbuf[1024];      /* used for pstrerror message buffer */

/* Like strerror_r but provide a default message if strerror_r fails */
static void pstrerror(int err, strerrorbuf msg) {
  int e = strerror_r(err, msg, sizeof(strerrorbuf));
  if (e) snprintf(msg, sizeof(strerrorbuf), "unknown error %d", err);
}

/* Internal error, no recovery */
#define EPOLL_FATAL(EXPR, SYSERRNO)                                     \
  do {                                                                  \
    strerrorbuf msg;                                                    \
    pstrerror((SYSERRNO), msg);                                         \
    fprintf(stderr, "epoll proactor failure in %s:%d: %s: %s\n",        \
            __FILE__, __LINE__ , #EXPR, msg);                           \
    abort();                                                            \
  } while (0)

// ========================================================================
// First define a proactor mutex (pmutex) and timer mechanism (ptimer) to taste.
// ========================================================================

// In general all locks to be held singly and shortly (possibly as spin locks).
// Exception: psockets+proactor for pn_proactor_disconnect (convention: acquire
// psocket first to avoid deadlock).  TODO: revisit the exception and its
// awkwardness in the code (additional mutex? different type?).

typedef pthread_mutex_t pmutex;
static void pmutex_init(pthread_mutex_t *pm){
  pthread_mutexattr_t attr;

  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
  if (pthread_mutex_init(pm, &attr)) {
    perror("pthread failure");
    abort();
  }
}

static void pmutex_finalize(pthread_mutex_t *m) { pthread_mutex_destroy(m); }
static inline void lock(pmutex *m) { pthread_mutex_lock(m); }
static inline void unlock(pmutex *m) { pthread_mutex_unlock(m); }

typedef struct acceptor_t acceptor_t;
typedef struct tslot_t tslot_t;

typedef enum {
  WAKE,   /* see if any work to do in proactor/psocket context */
  PCONNECTION_IO,
  PCONNECTION_TIMER,
  LISTENER_IO,
  PROACTOR_TIMER } epoll_type_t;

// Data to use with epoll.
typedef struct epoll_extended_t {
  struct psocket_t *psocket;  // pconnection, listener, or NULL -> proactor
  int fd;
  epoll_type_t type;   // io/timer/wakeup
  uint32_t wanted;     // events to poll for
  bool polling;
  pmutex barrier_mutex;
} epoll_extended_t;

/* epoll_ctl()/epoll_wait() do not form a memory barrier, so cached memory
   writes to struct epoll_extended_t in the EPOLL_ADD thread might not be
   visible to epoll_wait() thread. This function creates a memory barrier,
   called before epoll_ctl() and after epoll_wait()
*/
static void memory_barrier(epoll_extended_t *ee) {
  // Mutex lock/unlock has the side-effect of being a memory barrier.
  lock(&ee->barrier_mutex);
  unlock(&ee->barrier_mutex);
}

/*
 * This timerfd logic assumes EPOLLONESHOT and there never being two
 * active timeout callbacks.  There can be multiple (or zero)
 * unclaimed expiries processed in a single callback.
 *
 * timerfd_set() documentation implies a crisp relationship between
 * timer expiry count and oldt's return value, but a return value of
 * zero is ambiguous.  It can lead to no EPOLLIN, EPOLLIN + expected
 * read, or
 *
 *   event expiry (in kernel) -> EPOLLIN
 *   cancel/settime(0) (thread A) (number of expiries resets to zero)
 *   read(timerfd) -> -1, EAGAIN  (thread B servicing epoll event)
 *
 * The original implementation with counters to track expiry counts
 * was abandoned in favor of "in doubt" transitions and resolution
 * at shutdown.
 */

typedef struct ptimer_t {
  pmutex mutex;
  int timerfd;
  epoll_extended_t epoll_io;
  bool timer_active;
  bool in_doubt;  // 0 or 1 callbacks are possible
  bool shutting_down;
} ptimer_t;

static bool ptimer_init(ptimer_t *pt, struct psocket_t *ps) {
  pt->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  pmutex_init(&pt->mutex);
  pt->timer_active = false;
  pt->in_doubt = false;
  pt->shutting_down = false;
  epoll_type_t type = ps ? PCONNECTION_TIMER : PROACTOR_TIMER;
  pt->epoll_io.psocket = ps;
  pt->epoll_io.fd = pt->timerfd;
  pt->epoll_io.type = type;
  pt->epoll_io.wanted = EPOLLIN;
  pt->epoll_io.polling = false;
  return (pt->timerfd >= 0);
}

// Call with ptimer lock held
static void ptimer_set_lh(ptimer_t *pt, uint64_t t_millis) {
  struct itimerspec newt, oldt;
  memset(&newt, 0, sizeof(newt));
  newt.it_value.tv_sec = t_millis / 1000;
  newt.it_value.tv_nsec = (t_millis % 1000) * 1000000;

  timerfd_settime(pt->timerfd, 0, &newt, &oldt);
  if (pt->timer_active && oldt.it_value.tv_nsec == 0 && oldt.it_value.tv_sec == 0) {
    // EPOLLIN is possible but not assured
    pt->in_doubt = true;
  }
  pt->timer_active = t_millis;
}

static void ptimer_set(ptimer_t *pt, uint64_t t_millis) {
  // t_millis == 0 -> cancel
  lock(&pt->mutex);
  if ((t_millis == 0 && !pt->timer_active) || pt->shutting_down) {
    unlock(&pt->mutex);
    return;  // nothing to do
  }
  ptimer_set_lh(pt, t_millis);
  unlock(&pt->mutex);
}

/* Read from a timer or event FD */
static uint64_t read_uint64(int fd) {
  uint64_t result = 0;
  ssize_t n = read(fd, &result, sizeof(result));
  if (n != sizeof(result) && !(n < 0 && errno == EAGAIN)) {
    EPOLL_FATAL("timerfd or eventfd read error", errno);
  }
  return result;
}

// Callback bookkeeping. Return true if there is an expired timer.
static bool ptimer_callback(ptimer_t *pt) {
  lock(&pt->mutex);
  struct itimerspec current;
  if (timerfd_gettime(pt->timerfd, &current) == 0) {
    if (current.it_value.tv_nsec == 0 && current.it_value.tv_sec == 0)
      pt->timer_active = false;
  }
  uint64_t u_exp_count = read_uint64(pt->timerfd);
  if (!pt->timer_active) {
    // Expiry counter just cleared, timer not set, timerfd not armed
    pt->in_doubt = false;
  }
  unlock(&pt->mutex);
  return u_exp_count > 0;
}

// Return true if timerfd has and will have no pollable expiries in the current armed state
static bool ptimer_shutdown(ptimer_t *pt, bool currently_armed) {
  lock(&pt->mutex);
  if (currently_armed) {
    ptimer_set_lh(pt, 0);
    pt->shutting_down = true;
    if (pt->in_doubt)
      // Force at least one callback.  If two, second cannot proceed with unarmed timerfd.
      ptimer_set_lh(pt, 1);
  }
  else
    pt->shutting_down = true;
  bool rv = !pt->in_doubt;
  unlock(&pt->mutex);
  return rv;
}

static void ptimer_finalize(ptimer_t *pt) {
  if (pt->timerfd >= 0) close(pt->timerfd);
  pmutex_finalize(&pt->mutex);
}

pn_timestamp_t pn_i_now2(void)
{
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return ((pn_timestamp_t)now.tv_sec) * 1000 + (now.tv_nsec / 1000000);
}


// ========================================================================
// Proactor common code
// ========================================================================

const char *AMQP_PORT = "5672";
const char *AMQP_PORT_NAME = "amqp";

// The number of times a connection event batch may be replenished for
// a thread between calls to wait().  Some testing shows that
// increasing this value above 1 actually slows performance slightly
// and increases latency.
#define HOG_MAX 1

/* pn_proactor_t and pn_listener_t are plain C structs with normal memory management.
   Class definitions are for identification as pn_event_t context only.
*/
PN_STRUCT_CLASSDEF(pn_proactor, CID_pn_proactor)
PN_STRUCT_CLASSDEF(pn_listener, CID_pn_listener)

static bool start_polling(epoll_extended_t *ee, int epollfd) {
  if (ee->polling)
    return false;
  ee->polling = true;
  struct epoll_event ev = {0};
  ev.data.ptr = ee;
  ev.events = ee->wanted | EPOLLONESHOT;
  memory_barrier(ee);
  return (epoll_ctl(epollfd, EPOLL_CTL_ADD, ee->fd, &ev) == 0);
}

static void stop_polling(epoll_extended_t *ee, int epollfd) {
  // TODO: check for error, return bool or just log?
  // TODO: is EPOLL_CTL_DEL ever needed beyond auto de-register when ee->fd is closed?
  if (ee->fd == -1 || !ee->polling || epollfd == -1)
    return;
  struct epoll_event ev = {0};
  ev.data.ptr = ee;
  ev.events = 0;
  memory_barrier(ee);
  if (epoll_ctl(epollfd, EPOLL_CTL_DEL, ee->fd, &ev) == -1)
    EPOLL_FATAL("EPOLL_CTL_DEL", errno);
  ee->fd = -1;
  ee->polling = false;
}

/*
 * The proactor maintains a number of serialization contexts: each
 * connection, each listener, the proactor itself.  The serialization
 * is presented to the application via each associated event batch.
 *
 * Multiple threads can be trying to do work on a single context
 * (i.e. socket IO is ready and wakeup at same time). Mutexes are used
 * to manage contention.  Some vars are only ever touched by one
 * "working" thread and are accessed without holding the mutex.
 *
 * Currently internal wakeups (via wake()/wake_notify()) are used to
 * force a context to check if it has work to do.  To minimize trips
 * through the kernel, wake() is a no-op if the context has a working
 * thread.  Conversely, a thread must never stop working without
 * checking if it has newly arrived work.
 *
 * External wake operations, like pn_connection_wake() are built on top of
 * the internal wake mechanism.
 *
 * pn_proactor_interrupt() must be async-signal-safe so it has a dedicated
 * eventfd to allow a lock-free pn_proactor_interrupt() implementation.
 */

/*
 * ZZZ redocument.  epollfd_2 gone with single poller thread...


 * **** epollfd and epollfd_2 ****
 *
 * This implementation allows multiple threads to call epoll_wait()
 * concurrently (as opposed to having a single thread call
 * epoll_wait() and feed work to helper threads).  Unfortunately
 * with this approach, it is not possible to change the event
 * mask in one thread and be certain if zero or one callbacks occurred
 * on the previous event mask.  This can greatly complicate ordered
 * shutdown.  (See PROTON-1842)
 *
 * Currently, only pconnection sockets change between EPOLLIN,
 * EPOLLOUT, or both.  The rest use a constant EPOLLIN event mask.
 * Instead of trying to change the event mask for pconnection sockets,
 * if there is a missing attribute, it is added (EPOLLIN or EPOLLOUT)
 * as an event mask on the secondary or chained epollfd_2.  epollfd_2
 * is part of the epollfd fd set, so active events in epollfd_2 are
 * also seen in epollfd (but require a separate epoll_wait() and
 * rearm() to extract).
 *
 * Using this method and EPOLLONESHOT, it is possible to wait for all
 * outstanding armings on a socket to "resolve" via epoll_wait()
 * callbacks before freeing resources.
 */
typedef enum {
  PROACTOR,
  PCONNECTION,
  LISTENER,
  WAKEABLE } pcontext_type_t;

typedef struct pcontext_t {
  pmutex mutex;
  pn_proactor_t *proactor;  /* Immutable */
  void *owner;              /* Instance governed by the context */
  pcontext_type_t type;
  bool working;
  bool on_wake_list;
  bool wake_pending;             // unprocessed eventfd wake callback (convert to bool?)
  struct pcontext_t *wake_next; // wake list, guarded by proactor eventfd_mutex
  bool closing;
  // Next 4 are protected by the proactor mutex
  struct pcontext_t* next;  /* Protected by proactor.mutex */
  struct pcontext_t* prev;  /* Protected by proactor.mutex */
  int disconnect_ops;           /* ops remaining before disconnect complete */
  bool disconnecting;           /* pn_proactor_disconnect */
  // ZZZ allign me
  // Schedule mutex
  bool runnable;                /* in need of scheduling */
  tslot_t *runner;              /* designated or running thread */
  tslot_t *prev_runner;
  bool sched_wake;
  bool sched_pending;           /* If true, one or more unseen epoll or other events to process() */
  uint64_t ZZZr_start, ZZZr_ticks;
  int ZZZxid;
} pcontext_t;

typedef enum {
  NEW,
  UNUSED,
  SUSPENDED,
  PROCESSING,
  BATCHING,
  DELETING,
  POLLING } tslot_state;

struct tslot_t {
  pmutex mutex;
  pthread_cond_t cond;
  pthread_t tid;
  unsigned int generation;
  bool suspended;
  volatile bool scheduled;
  tslot_state state;
  pcontext_t *context;
  pcontext_t *prev_context;
  bool earmarked;
  tslot_t *suspend_list_prev;
  tslot_t *suspend_list_next;
  tslot_t *earmark_override;   // on earmark_drain, which thread was unassigned
  unsigned int earmark_override_gen;
  int zz_susp1, zz_susp2, zz_rsm1, zz_rsm2, ZZ_a;
  long long foolocks;
  int zz_dones;
  int zz_polls, zz_ipolls;
  uint64_t ZZZsusp_s, ZZZsusp_ticks, ZZZtrs, ZZZtrticks, ZZZsched_ticks, ZZZsched_s, ZZZp_s, ZZZp_ticks;
  int ZZZnp, ZZZnepw, ZZZnsusp, ZZZdeeps, ZZZbatches;
  int ZZZrewakes, ZZZrewakes2, ZZZrewakes3;
};

// Fake thread for temporarily disabling the scheduling of a context.
static struct tslot_t *REWAKE_PLACEHOLDER = (struct tslot_t*) -1;

typedef struct tslotmap_t {
  pthread_t id;
  tslot_t *tslot;
} tslotmap_t;

static void pcontext_init(pcontext_t *ctx, pcontext_type_t t, pn_proactor_t *p, void *o) {
  memset(ctx, 0, sizeof(*ctx));
  pmutex_init(&ctx->mutex);
  ctx->proactor = p;
  ctx->owner = o;
  ctx->type = t;
}

static void pcontext_finalize(pcontext_t* ctx) {
  pmutex_finalize(&ctx->mutex);
}


/* common to connection and listener */
typedef struct psocket_t {
  pn_proactor_t *proactor;
  // Remaining protected by the pconnection/listener mutex
  int sockfd;
  epoll_extended_t epoll_io;
  pn_listener_t *listener;      /* NULL for a connection socket */
  char addr_buf[PN_MAX_ADDR];
  const char *host, *port;
  uint32_t sched_io_events;
  uint32_t working_io_events;
} psocket_t;

#define TSMAX 16

struct pn_proactor_t {
  pcontext_t context;
  int epollfd;
  ptimer_t timer;
  pn_collector_t *collector;
  pcontext_t *contexts;         /* in-use contexts for PN_PROACTOR_INACTIVE and cleanup */
  epoll_extended_t epoll_wake;
  epoll_extended_t epoll_interrupt;
  pn_event_batch_t batch;
  size_t disconnects_pending;   /* unfinished proactor disconnects*/
  // need_xxx flags indicate we should generate PN_PROACTOR_XXX on the next update_batch()
  bool need_interrupt;
  bool need_inactive;
  bool need_timeout;
  bool timeout_set; /* timeout has been set by user and not yet cancelled or generated event */
  bool timeout_processed;  /* timeout event dispatched in the most recent event batch */
  bool timer_armed; /* timer is armed in epoll */
  bool shutting_down;
  // wake subsystem
  int eventfd;
  pmutex eventfd_mutex;
  bool wakes_in_progress;
  pcontext_t *wake_list_first;
  pcontext_t *wake_list_last;
  // Interrupts have a dedicated eventfd because they must be async-signal safe.
  int interruptfd;
  // If the process runs out of file descriptors, disarm listening sockets temporarily and save them here.
  acceptor_t *overflow;
  pmutex overflow_mutex;
  // Warm runnables have assigned suspended tslots and can run right away.
  // Other runnables are run as tslots come available.
  // Contexts on the wake queue up to p->last_wake_context are also scheduled prior to a next epoll_wait().
  pmutex sched_mutex;
  bool sched_timeout;
  bool sched_interrupt;
  pcontext_t *runnables[TSMAX];
  int n_runnables;
  int next_runnable;


  tslot_t *suspend_list_head;
  tslot_t *suspend_list_tail;
  int suspend_list_count;
  tslot_t *poller;
  bool poller_suspended;
  // Scratch vars for poller
  tslot_t *resume_list[TSMAX];
  struct epoll_event *kevents; // ZZZ alloca?
  int kevents_length;
  pcontext_t *warm_runnables[TSMAX];
  int n_warm_runnables;
  tslot_t *last_earmark;


  tslotmap_t tmaps[TSMAX];
  tslot_t tslots[TSMAX];
  int thread_count;
  // ZZZ order vars according to access pattern
  pcontext_t *sched_wake_first;
  pcontext_t *sched_wake_last;
  pcontext_t *sched_wake_current;
  pmutex tslot_mutex;
  int earmark_count;
  bool earmark_drain;
  bool sched_wakes_pending;
  int zz_polls, zz_t0polls;
  int ZZZpoller_immediate, ZZZpoller_unassigned, ZZZlost_threads;
  bool ZZZx99;
};

// ==========  ZZZ perf debug stuff ==========

#include <sys/stat.h>
#include <inttypes.h>

static uint64_t hrtick(void) {
  uint32_t lo, hi;
  __asm__ volatile ("rdtscp"
      : /* outputs */ "=a" (lo), "=d" (hi)
      : /* no inputs */
      : /* clobbers */ "%rcx");
  return (uint64_t)lo | (((uint64_t)hi) << 32);
}

static int ZZZwarm_sched = true;
static int ZZZspins = 0;
static int ZZZtsched_bump = 0;
static int ZZZrconns = 0;
static int ZZZclosed = 0;
static bool ZZZrrr = false;
static bool ZZZep_immediate = false;
static uint64_t ZZZr_start = 0;
static uint64_t ZZZi_start = 0;
static uint64_t ZZZi_ticks = 0;
static int ZZZctxc = 0;
static int ZZZready_fd = -1;

static int ZZZts(pn_proactor_t *p, tslot_t *ts) {
  if (!ts) return -1;
  return ts - p->tslots;
}

static void ZZZwk(pn_proactor_t *p) {
  char buf[500];
  char mb[30];
  buf[0] = '\0';
  pcontext_t *ctx = p->sched_wake_first;
  while(ctx) {
    sprintf(mb, "  %p", (void *) ctx);
    ctx = ctx->wake_next;
    strcat(buf, mb);
  }
  strcat(buf, " | ");

  ctx = p->wake_list_first;
  while(ctx) {
    sprintf(mb, "  %p", (void *) ctx);
    ctx = ctx->wake_next;
    strcat(buf, mb);
  }
  fprintf(stderr, ".   %p %p %p %p %p\n  .  %s\n", (void *) p->wake_list_first, (void *) p->wake_list_last, (void *) p->sched_wake_first, (void *) p->sched_wake_last, (void *) p->sched_wake_current, buf);

}



//ZZZ doc somewhere...
// process() is slow, post() is fast and indicates runnable
// degrees of warmth are: paired, suspended list lifo order, none

// wake list is in two parts.  The front is the chunk the scheduler will process
// until the next epoll_wait().
// sched_wake tells which chunk it is on. The ctx may already be running or scheduled much later
// The ctx must be actually running, to absorb ctx->wake_pending

// The wake list can keep growing while popping wakes.  The list between
// sched_wake_first and sched_wake_last are protected by the sched
// lock (for pop operations), sched_wake_last to wake_list_last are
// protected by the eventfd mutex (for add operations).  Both locks
// are needed to cross or reconcile the two portions of the list.
// Call with sched lock held.
static void pop_wake(pcontext_t *ctx, int ZZZdelme) {
  if (dbgz) {
    lock(&ctx->proactor->eventfd_mutex);
    ZZZwk(ctx->proactor);
    unlock(&ctx->proactor->eventfd_mutex);
  }
  pn_proactor_t *p = ctx->proactor;

  // every context on the sched_wake_list is either currently running, or to be scheduled.  wake() will not "see" any of the wake_next pointers until wake_pending and working have transitioned to 0 and false, with intervening context

  // every context must transition as
  // !wake_pending .. wake()  .. on wake_list .. on sched_wake_list .. working context .. !sched_wake && !wake_pending
  // intervening locks at each transition ensures wake_next has memory coherence throughout the wake cycle
  if (ctx == p->sched_wake_current)
    p->sched_wake_current = ctx->wake_next;
  if (ctx == p->sched_wake_first) {
    // normal code path
    if (ctx == p->sched_wake_last) {
      p->sched_wake_first = p->sched_wake_last = NULL;
    } else {
      p->sched_wake_first = ctx->wake_next;
    }
    if (!p->sched_wake_first)
      p->sched_wake_last = NULL;
  } else {
    // ctx is not first in a multi-element list
    pcontext_t *prev = NULL;
    for (pcontext_t *i = p->sched_wake_first; i != ctx; i = i->wake_next)
      prev = i;
    prev->wake_next = ctx->wake_next;
    if (ctx == p->sched_wake_last)
      p->sched_wake_last = prev;
  }
  ctx->on_wake_list = false;
  if (dbgz) fprintf(stderr, "  pop_wake3 %p %d   xx %d\n", (void *) ctx, p->wakes_in_progress, ZZZdelme);
}

static void suspend_list_add_tail(pn_proactor_t *p, tslot_t *ts) {
  LL_ADD(p, suspend_list, ts);
}

static void suspend_list_insert_head(pn_proactor_t *p, tslot_t *ts) {
  ts->suspend_list_next = p->suspend_list_head;
  ts->suspend_list_prev = NULL;
  if (p->suspend_list_head)
    p->suspend_list_head->suspend_list_prev = ts;
  else
    p->suspend_list_tail = ts;
  p->suspend_list_head = ts;
}

// Call with sched lock
static void suspend(pn_proactor_t *p, tslot_t *ts) {
  if (ts->state == NEW)
    suspend_list_add_tail(p, ts);
  else
    suspend_list_insert_head(p, ts);
  p->suspend_list_count++;
  ts->ZZZnsusp++;
  if (ZZZrrr && p->suspend_list_count == p->thread_count - 1) {
    if (!ZZZi_start) ZZZi_start = hrtick();
  }
  // Medium length spinning tried here.  Raises cpu dramatically,
  // unclear throughput or latency benefit (not seen where most
  // expected, modest at other times).
  ts->state = SUSPENDED;
  ts->scheduled = false;
  if (ts->ZZZsched_s) {
    uint64_t ZZZnow = hrtick();
    ts->ZZZsched_ticks += (ZZZnow - ts->ZZZsched_s);
    ts->ZZZsched_s = 0;
    ts->ZZZsusp_s = ZZZnow;
  }

  unlock(&p->sched_mutex);

  if (ZZZdbgy) ts->zz_susp1++;
  lock(&ts->mutex);

  if (ZZZspins && !ts->scheduled) {
    bool locked = true;
    for (volatile int i = 0; i < ZZZspins; i++) {
      if (locked) {
        unlock(&ts->mutex);
        locked = false;
      }
//      __asm volatile ("pause" ::: "memory");
      if ((i % 1000) == 0) {
        locked = (pthread_mutex_trylock(&ts->mutex) == 0);
        ts->foolocks++;
      }
      if (ts->scheduled) break;
    }
    if (!locked)
      lock(&ts->mutex);
  }

  ts->suspended = true;
  while (!ts->scheduled) {
    ts->ZZZdeeps++;
    int result = pthread_cond_wait(&ts->cond, &ts->mutex);
    if (result != 0 && dbgz) fprintf(stderr, "assert1 ZZZ\n");
    if (ZZZdbgy) ts->zz_susp2++;
    assert(result == 0);
  }
  ts->suspended = false;
  unlock(&ts->mutex);
  lock(&p->sched_mutex);
  assert(ts->state == PROCESSING);

  if (ts->ZZZsusp_s || ZZZi_start) {
    uint64_t ZZZnow = hrtick();
    if (ts->ZZZsusp_s)
      ts->ZZZsusp_ticks += (ZZZnow - ts->ZZZsusp_s);
    ts->ZZZsusp_s = 0;
    ts->ZZZsched_s = ZZZnow;
    if (ZZZi_start) {
      ZZZi_ticks += (ZZZnow - ZZZi_start);
      ZZZi_start = 0;
    }
  }

}

// Call with no lock
static void resume(pn_proactor_t *p, tslot_t *ts) {
  lock(&ts->mutex);
  if (ZZZdbgy) ts->zz_rsm1++;
  ts->scheduled = true;
  if (ts->suspended) {
    int result = pthread_cond_signal(&ts->cond);
    if (result != 0 && dbgz) fprintf(stderr, "assert1 ZZZ\n");
    assert(result == 0);
    if (ZZZdbgy) ts->zz_rsm2++;
  }
  unlock(&ts->mutex);

}

static void rearm(pn_proactor_t *p, epoll_extended_t *ee);

/*
 * Wake strategy with eventfd.
 *  - wakees can be in the list only once
 *  - wakers only use the eventfd if wakes_in_progress is false
 * There is a single rearm between wakes > 0 and wakes == 0
 */

// part1: call with ctx->owner lock held, return true if notify required by caller
static bool wake(pcontext_t *ctx) {
  bool notify = false;
  if (dbgz) fprintf(stderr, "W  %p     %d %d\n", (void *) ctx, ctx->wake_pending, ctx->working);
  pn_proactor_t *p = ctx->proactor; //ZZZ for debug statements

  if (!ctx->wake_pending) {
    if (!ctx->working) {
      ctx->wake_pending = true;
      pn_proactor_t *p = ctx->proactor;
      lock(&p->eventfd_mutex);
      ctx->wake_next = NULL;
      ctx->on_wake_list = true;
      if (!p->wake_list_first) {
        p->wake_list_first = p->wake_list_last = ctx;
      } else {
        p->wake_list_last->wake_next = ctx;
        p->wake_list_last = ctx;
      }
      if (!p->wakes_in_progress) {
        // force a wakeup via the eventfd
        p->wakes_in_progress = true;
        notify = true;
      }
      unlock(&p->eventfd_mutex);
    }
  }

  if (dbgz) fprintf(stderr, "   %d    %p %p       %p %p %p\n", p->wakes_in_progress, (void *) p->wake_list_first, (void *) p->wake_list_last, (void *) p->sched_wake_first, (void *) p->sched_wake_last, (void *) p->sched_wake_current);
  return notify;
}

// part2: make OS call without lock held
static inline void wake_notify(pcontext_t *ctx) {
  if (dbgz) fprintf(stderr, "WN  %p\n", (void *) ctx);
  pn_proactor_t *p = ctx->proactor;
  if (p->eventfd == -1)
    return;
  rearm(p, &p->epoll_wake);
}

// call with owner lock held, once for each pop from the wake list
static inline void wake_done(pcontext_t *ctx) {
//  assert(ctx->wake_pending > 0);
  ctx->wake_pending = false;
  if (dbgz) fprintf(stderr, "  WD  %p   %d %d\n", (void *) ctx, ctx->wake_pending, ctx->working);
}


static void psocket_init(psocket_t* ps, pn_proactor_t* p, pn_listener_t *listener, const char *addr)
{
  ps->epoll_io.psocket = ps;
  ps->epoll_io.fd = -1;
  ps->epoll_io.type = listener ? LISTENER_IO : PCONNECTION_IO;
  ps->epoll_io.wanted = 0;
  ps->epoll_io.polling = false;
  ps->proactor = p;
  ps->listener = listener;
  ps->sockfd = -1;
  pni_parse_addr(addr, ps->addr_buf, sizeof(ps->addr_buf), &ps->host, &ps->port);
}

typedef struct pconnection_t {
  psocket_t psocket;
  pcontext_t context;
  uint32_t new_events;
  int wake_count;
  bool server;                /* accept, not connect */
  bool tick_pending;
  bool timer_armed;
  bool queued_disconnect;     /* deferred from pn_proactor_disconnect() */
  pn_condition_t *disconnect_condition;
  ptimer_t timer;  // TODO: review one timerfd per connection
  // Following values only changed by (sole) working context:
  uint32_t current_arm;  // active epoll io events
  bool connected;
  bool read_blocked;
  bool write_blocked;
  bool disconnected;
  int hog_count; // thread hogging limiter
  pn_event_batch_t batch;
  pn_connection_driver_t driver;
  bool wbuf_valid;
  const char *wbuf_current;
  size_t wbuf_remaining;
  size_t wbuf_completed;
  struct pn_netaddr_t local, remote; /* Actual addresses */
  struct addrinfo *addrinfo;         /* Resolved address list */
  struct addrinfo *ai;               /* Current connect address */
  pmutex rearm_mutex;                /* protects pconnection_rearm from out of order arming*/
  bool io_doublecheck;               /* callbacks made and new IO may have arrived */
  // ZZZ allignme
  bool sched_timeout;
  int zzwarm, zzearmk, zzsysw, zzsnd, zzsysr, zzrcv, zzbaddrn, zzrandom_win, zzfallbk, zzlatewk, zzdones;
} pconnection_t;

/* Protects read/update of pn_connnection_t pointer to it's pconnection_t
 *
 * Global because pn_connection_wake()/pn_connection_proactor() navigate from
 * the pn_connection_t before we know the proactor or driver. Critical sections
 * are small: only get/set of the pn_connection_t driver pointer.
 *
 * TODO: replace mutex with atomic load/store
 */
static pthread_mutex_t driver_ptr_mutex = PTHREAD_MUTEX_INITIALIZER;

static pconnection_t *get_pconnection(pn_connection_t* c) {
  if (!c) return NULL;
  lock(&driver_ptr_mutex);
  pn_connection_driver_t *d = *pn_connection_driver_ptr(c);
  unlock(&driver_ptr_mutex);
  if (!d) return NULL;
  return (pconnection_t*)((char*)d-offsetof(pconnection_t, driver));
}

static void set_pconnection(pn_connection_t* c, pconnection_t *pc) {
  lock(&driver_ptr_mutex);
  *pn_connection_driver_ptr(c) = pc ? &pc->driver : NULL;
  unlock(&driver_ptr_mutex);
}


static pconnection_t *dbgy(pcontext_t * ctx) {
  if (ZZZdbgy && ctx->type == PCONNECTION)
    return (pconnection_t *) ctx->owner;
  return NULL;
}

// Call with sched_mutex locked
static void assign_thread(tslot_t *ts, pcontext_t *ctx) {
  assert(!ctx->runner);
  ctx->runner = ts;
  ctx->prev_runner = NULL;
  ctx->runnable = false;
  ts->context = ctx;
  ts->prev_context = NULL;
  if (ZZZdbgy) ts->ZZ_a++;
}

// call with sched lock
static bool rewake(pcontext_t *ctx) {
  // Special case wake() where context is unassigned and a popped wake needs to be put back on the list.
  // Should be rare.
  bool notify = false;
  pn_proactor_t *p = ctx->proactor;
  lock(&p->eventfd_mutex);
  assert(ctx->wake_pending);
  assert(!ctx->on_wake_list);
  ctx->wake_next = NULL;
  ctx->on_wake_list = true;
  if (!p->wake_list_first) {
    p->wake_list_first = p->wake_list_last = ctx;
  } else {
    p->wake_list_last->wake_next = ctx;
    p->wake_list_last = ctx;
  }
  if (!p->wakes_in_progress) {
    // force a wakeup via the eventfd
    p->wakes_in_progress = true;
    notify = true;
  }
  unlock(&p->eventfd_mutex);
  return notify;
}

// Call with sched_mutex locked
static bool unassign_thread_lh(tslot_t *ts, tslot_state new_state) {
  pcontext_t *ctx = ts->context;
  bool notify = false;
  bool deleting = (ts->state == DELETING);
  ctx->runner = NULL;
  ctx->prev_runner = ts;
  if (!deleting)
    ts->prev_context = ts->context;
  ts->context = NULL;
  ts->state = new_state;

  // All accounting must be complete as next step may drop the sched lock.
  // Check if context has unseen events/wake that need processing.

  if (!deleting) {
    pn_proactor_t *p = ctx->proactor;
    if (ctx->sched_pending) {
      // Need a new wake
      if (ctx->sched_wake) {
        if (dbgz) fprintf(stderr, "ut selfwake t%d %p %d %d __ %d\n", ZZZts(ctx->proactor, ts), (void *) ctx, ctx->on_wake_list, ctx->wake_pending, ctx->proactor->wakes_in_progress);
        if (!ctx->on_wake_list) {
          // Remember it for next poller
          ctx->sched_wake = false;
          notify = rewake(ctx);     // back on wake list for poller to see
          ts->ZZZrewakes2++;
        }
        // else already scheduled
      } else {
        // bad corner case.  Block ctx from being scheduled again until a later post_wake()
        ctx->runner = REWAKE_PLACEHOLDER;
        unlock(&p->sched_mutex);
        lock(&ctx->mutex);
        notify = wake(ctx);
        unlock(&ctx->mutex);
        lock(&p->sched_mutex);
        ts->ZZZrewakes3++;
      }
      ts->ZZZrewakes++;
    }
  }
  return notify;
}

// Call with sched_mutex locked
static void earmark_thread(tslot_t *ts, pcontext_t *ctx) {
  assign_thread(ts, ctx);
  ts->earmarked = true;
  ctx->proactor->earmark_count++;
  if (dbgz) fprintf(stderr, "earmark t%d %p %d\n", ZZZts(ctx->proactor, ts), (void *) ctx, ctx->proactor->earmark_count);
}

// Call with sched_mutex locked
static void remove_earmark(tslot_t *ts) {
  pcontext_t *ctx = ts->context;
  ts->context = NULL;
  ctx->runner = NULL;
  ts->earmarked = false;
  ctx->proactor->earmark_count--;
}

// Call with sched_mutex locked
static void make_runnable(pcontext_t *ctx) {
  pn_proactor_t *p = ctx->proactor;
  assert(p->n_runnables <= TSMAX);
  assert(!ctx->runnable);
  if (ctx->runner) return;

  ctx->runnable = true;
  // Track it as normal or warm or earmarked
  if (ZZZwarm_sched) {
    tslot_t *ts = ctx->prev_runner;
    if (ts && ts->prev_context == ctx) {
      if (ts->state == SUSPENDED || ts->state == PROCESSING) {
        p->warm_runnables[p->n_warm_runnables++] = ctx;
        assign_thread(ts, ctx);
        pconnection_t *pc = dbgy(ctx); if (pc) pc->zzwarm++;
        return;
      }
      if (ts->state == UNUSED && !p->earmark_drain) {
        earmark_thread(ts, ctx);
        pconnection_t *pc = dbgy(ctx); if (pc) pc->zzearmk++;
        p->last_earmark = ts;
        return;
      }
    }
  }
  p->runnables[p->n_runnables++] = ctx;
}


/*
 * A listener can have mutiple sockets (as specified in the addrinfo).  They
 * are armed separately.  The individual psockets can be part of at most one
 * list: the global proactor overflow retry list or the per-listener list of
 * pending accepts (valid inbound socket obtained, but pn_listener_accept not
 * yet called by the application).  These lists will be small and quick to
 * traverse.
 */

struct acceptor_t{
  psocket_t psocket;
  int accepted_fd;
  bool armed;
  bool overflowed;
  acceptor_t *next;              /* next listener list member */
  struct pn_netaddr_t addr;      /* listening address */
};

struct pn_listener_t {
  acceptor_t *acceptors;          /* Array of listening sockets */
  size_t acceptors_size;
  int active_count;               /* Number of listener sockets registered with epoll */
  pcontext_t context;
  pn_condition_t *condition;
  pn_collector_t *collector;
  pn_event_batch_t batch;
  pn_record_t *attachments;
  void *listener_context;
  acceptor_t *pending_acceptors;  /* list of those with a valid inbound fd*/
  int pending_count;
  bool unclaimed;                 /* attach event dispatched but no pn_listener_attach() call yet */
  size_t backlog;
  bool close_dispatched;
  pmutex rearm_mutex;             /* orders rearms/disarms, nothing else */
  uint32_t sched_io_events;
};

static pn_event_batch_t *pconnection_process(pconnection_t *pc, uint32_t events, bool timeout, bool wake, bool topup);
static void write_flush(pconnection_t *pc);
static void listener_begin_close(pn_listener_t* l);
static void proactor_add(pcontext_t *ctx);
static bool proactor_remove(pcontext_t *ctx);

static inline pconnection_t *psocket_pconnection(psocket_t* ps) {
  return ps->listener ? NULL : (pconnection_t*)ps;
}

static inline pn_listener_t *psocket_listener(psocket_t* ps) {
  return ps->listener;
}

static inline acceptor_t *psocket_acceptor(psocket_t* ps) {
  return !ps->listener ? NULL : (acceptor_t *)ps;
}

static inline pconnection_t *pcontext_pconnection(pcontext_t *c) {
  return c->type == PCONNECTION ?
    (pconnection_t*)((char*)c - offsetof(pconnection_t, context)) : NULL;
}

static inline pn_listener_t *pcontext_listener(pcontext_t *c) {
  return c->type == LISTENER ?
    (pn_listener_t*)((char*)c - offsetof(pn_listener_t, context)) : NULL;
}

static pn_event_t *listener_batch_next(pn_event_batch_t *batch);
static pn_event_t *proactor_batch_next(pn_event_batch_t *batch);
static pn_event_t *pconnection_batch_next(pn_event_batch_t *batch);

static inline pn_proactor_t *batch_proactor(pn_event_batch_t *batch) {
  return (batch->next_event == proactor_batch_next) ?
    (pn_proactor_t*)((char*)batch - offsetof(pn_proactor_t, batch)) : NULL;
}

static inline pn_listener_t *batch_listener(pn_event_batch_t *batch) {
  return (batch->next_event == listener_batch_next) ?
    (pn_listener_t*)((char*)batch - offsetof(pn_listener_t, batch)) : NULL;
}

static inline pconnection_t *batch_pconnection(pn_event_batch_t *batch) {
  return (batch->next_event == pconnection_batch_next) ?
    (pconnection_t*)((char*)batch - offsetof(pconnection_t, batch)) : NULL;
}

static inline bool pconnection_has_event(pconnection_t *pc) {
  return pn_connection_driver_has_event(&pc->driver);
}

static inline bool listener_has_event(pn_listener_t *l) {
  return pn_collector_peek(l->collector) || (l->pending_count && !l->unclaimed);
}

static inline bool proactor_has_event(pn_proactor_t *p) {
  return pn_collector_peek(p->collector);
}

static pn_event_t *log_event(void* p, pn_event_t *e) {
  if (e) {
    pn_logf("[%p]:(%s)", (void*)p, pn_event_type_name(pn_event_type(e)));
  }
  return e;
}

static void psocket_error_str(psocket_t *ps, const char *msg, const char* what) {
  if (!ps->listener) {
    pn_connection_driver_t *driver = &psocket_pconnection(ps)->driver;
    pn_connection_driver_bind(driver); /* Bind so errors will be reported */
    pni_proactor_set_cond(pn_transport_condition(driver->transport), what, ps->host, ps->port, msg);
    pn_connection_driver_close(driver);
  } else {
    pn_listener_t *l = psocket_listener(ps);
    pni_proactor_set_cond(l->condition, what, ps->host, ps->port, msg);
    listener_begin_close(l);
  }
}

static void psocket_error(psocket_t *ps, int err, const char* what) {
  strerrorbuf msg;
  pstrerror(err, msg);
  psocket_error_str(ps, msg, what);
}

static void psocket_gai_error(psocket_t *ps, int gai_err, const char* what) {
  psocket_error_str(ps, gai_strerror(gai_err), what);
}

static void rearm(pn_proactor_t *p, epoll_extended_t *ee) {
  struct epoll_event ev = {0};
  ev.data.ptr = ee;
  ev.events = ee->wanted | EPOLLONESHOT;
  memory_barrier(ee);
  if (epoll_ctl(p->epollfd, EPOLL_CTL_MOD, ee->fd, &ev) == -1)
    EPOLL_FATAL("arming polled file descriptor", errno);
}

static void listener_list_append(acceptor_t **start, acceptor_t *item) {
  assert(item->next == NULL);
  if (*start) {
    acceptor_t *end = *start;
    while (end->next)
      end = end->next;
    end->next = item;
  }
  else *start = item;
}

static acceptor_t *listener_list_next(acceptor_t **start) {
  acceptor_t *item = *start;
  if (*start) *start = (*start)->next;
  if (item) item->next = NULL;
  return item;
}

// Add an overflowing listener to the overflow list. Called with listener context lock held.
static void listener_set_overflow(acceptor_t *a) {
  a->overflowed = true;
  pn_proactor_t *p = a->psocket.proactor;
  lock(&p->overflow_mutex);
  listener_list_append(&p->overflow, a);
  unlock(&p->overflow_mutex);
}

/* TODO aconway 2017-06-08: we should also call proactor_rearm_overflow after a fixed delay,
   even if the proactor has not freed any file descriptors, since other parts of the process
   might have*/

// Activate overflowing listeners, called when there may be available file descriptors.
static void proactor_rearm_overflow(pn_proactor_t *p) {
  lock(&p->overflow_mutex);
  acceptor_t* ovflw = p->overflow;
  p->overflow = NULL;
  unlock(&p->overflow_mutex);
  acceptor_t *a = listener_list_next(&ovflw);
  while (a) {
    pn_listener_t *l = a->psocket.listener;
    lock(&l->context.mutex);
    bool rearming = !l->context.closing;
    bool notify = false;
    assert(!a->armed);
    assert(a->overflowed);
    a->overflowed = false;
    if (rearming) {
      lock(&l->rearm_mutex);
      a->armed = true;
    }
    else notify = wake(&l->context);
    unlock(&l->context.mutex);
    if (rearming) {
      rearm(p, &a->psocket.epoll_io);
      unlock(&l->rearm_mutex);
    }
    if (notify) wake_notify(&l->context);
    a = listener_list_next(&ovflw);
  }
}

// Close an FD and rearm overflow listeners.  Call with no listener locks held.
static int pclosefd(pn_proactor_t *p, int fd) {
  int err = close(fd);
  if (!err) proactor_rearm_overflow(p);
  return err;
}


// ========================================================================
// pconnection
// ========================================================================

static void pconnection_tick(pconnection_t *pc);

static const char *pconnection_setup(pconnection_t *pc, pn_proactor_t *p, pn_connection_t *c, pn_transport_t *t, bool server, const char *addr)
{
  lock(&p->sched_mutex);
  if (ZZZrconns && !ZZZr_start) {
    // first connection of a perf run
    ZZZr_start = hrtick();
    ZZZrrr = true;
  }
  unlock(&p->sched_mutex);

  memset(pc, 0, sizeof(*pc));

  if (dbgz) fprintf(stderr, "new pc %p\n", (void *) &pc->context);
  if (pn_connection_driver_init(&pc->driver, c, t) != 0) {
    free(pc);
    return "pn_connection_driver_init failure";
  }

  pcontext_init(&pc->context, PCONNECTION, p, pc);
  psocket_init(&pc->psocket, p, NULL, addr);
  pc->new_events = 0;
  pc->wake_count = 0;
  pc->tick_pending = false;
  pc->timer_armed = false;
  pc->queued_disconnect = false;
  pc->disconnect_condition = NULL;

  pc->current_arm = 0;
  pc->connected = false;
  pc->read_blocked = true;
  pc->write_blocked = true;
  pc->disconnected = false;
  pc->wbuf_valid = false;
  pc->wbuf_completed = 0;
  pc->wbuf_remaining = 0;
  pc->wbuf_current = NULL;
  pc->hog_count = 0;
  pc->batch.next_event = pconnection_batch_next;

  if (server) {
    pn_transport_set_server(pc->driver.transport);
  }

  if (!ptimer_init(&pc->timer, &pc->psocket)) {
    psocket_error(&pc->psocket, errno, "timer setup");
    pc->disconnected = true;    /* Already failed */
  }
  pmutex_init(&pc->rearm_mutex);

  /* Set the pconnection_t backpointer last.
     Connections that were released by pn_proactor_release_connection() must not reveal themselves
     to be re-associated with a proactor till setup is complete.
   */
  set_pconnection(pc->driver.connection, pc);

  return NULL;
}

// Call with lock held and closing == true (i.e. pn_connection_driver_finished() == true), timer cancelled.
// Return true when all possible outstanding epoll events associated with this pconnection have been processed.
static inline bool pconnection_is_final(pconnection_t *pc) {
  return !pc->current_arm && !pc->timer_armed && !pc->context.wake_pending;
}

static void pconnection_final_free(pconnection_t *pc) {
  // Ensure any lingering pconnection_rearm is all done.
  lock(&pc->rearm_mutex);  unlock(&pc->rearm_mutex);

  if (pc->driver.connection) {
    set_pconnection(pc->driver.connection, NULL);
  }
  if (pc->addrinfo) {
    freeaddrinfo(pc->addrinfo);
  }
  pmutex_finalize(&pc->rearm_mutex);
  pn_condition_free(pc->disconnect_condition);
  pn_connection_driver_destroy(&pc->driver);
  pcontext_finalize(&pc->context);
  free(pc);
}


// call without lock, but only if pconnection_is_final() is true
static void pconnection_cleanup(pconnection_t *pc) {
  stop_polling(&pc->psocket.epoll_io, pc->psocket.proactor->epollfd);
  if (pc->psocket.sockfd != -1)
    pclosefd(pc->psocket.proactor, pc->psocket.sockfd);
  stop_polling(&pc->timer.epoll_io, pc->psocket.proactor->epollfd);
  ptimer_finalize(&pc->timer);

  pn_proactor_t *p = pc->context.proactor;
  lock(&p->sched_mutex);
  ZZZclosed++;
  uint64_t ZZZr_ticks = 0;
  uint64_t ZZZnow = 0;
  if (ZZZrrr && ZZZclosed == ZZZrconns) {
    // last connection of a perf run
    ZZZnow = hrtick();
    ZZZr_ticks = ZZZnow - ZZZr_start;
    ZZZrrr = false;
  }

  pcontext_t *ctx = &pc->context;
  if (ZZZnow && ZZZrrr) {
    ctx->ZZZr_ticks += (ZZZnow - ctx->ZZZr_start);
    ctx->ZZZr_start = 0;
  }

  unlock(&p->sched_mutex);

  if (dbgy(&pc->context)) {
    fprintf(stdout, "%d  |  %d %d %d %d  |  w %d e %d r %d f %d lw %d  | %d\n", pc->zzdones, pc->zzsysr, pc->zzrcv, pc->zzsysw, pc->zzsnd,        pc->zzwarm, pc->zzearmk, pc->zzrandom_win, pc->zzfallbk, pc->zzlatewk, pc->zzbaddrn);

    double rpct = ZZZr_ticks ? (double) ctx->ZZZr_ticks * 100 / ZZZr_ticks : 0.0;
    fprintf(stdout, "p  %d %d   run %" PRIu64  " (%.2f)    immed %d  unassigned %d  lost_thr %d\n", p->zz_polls, p->zz_t0polls, ctx->ZZZr_ticks, rpct, p->ZZZpoller_immediate, p->ZZZpoller_unassigned, p->ZZZlost_threads);
    if (ZZZr_ticks || !ZZZrconns) {
      int count = p->thread_count;
      for (int i = 0; i < count; i++ ) {
        tslot_t *ts2 = &p->tslots[i];
        fprintf(stdout, "  t%d  %d %d    %d %d    %lld  N %d P %d %d   R %d/%d/%d\n", i, ts2->zz_susp1, ts2->zz_susp2, ts2->zz_rsm1, ts2->zz_rsm2, ts2->foolocks, ts2->zz_dones, ts2->zz_polls, ts2->zz_ipolls, ts2->ZZZrewakes, ts2->ZZZrewakes2, ts2->ZZZrewakes3);
        if (ZZZr_ticks) {
          if (ts2->state == SUSPENDED && ZZZrrr) {
            ts2->ZZZsusp_ticks += (ZZZnow - ts2->ZZZsusp_s);
            ts2->ZZZsusp_s = 0;
          }
          fprintf(stdout, "    run %.2f   susp %.2f   sched %.2f  poll %.2f     epw %d b %d p %d susp %d ds %d\n",
                  (double) ts2->ZZZtrticks * 100 / ZZZr_ticks,
                  (double) ts2->ZZZsusp_ticks * 100 / ZZZr_ticks,
                  (double) ts2->ZZZsched_ticks * 100 / ZZZr_ticks,
                  (double) ts2->ZZZp_ticks * 100 / ZZZr_ticks,
ts2->ZZZnepw, ts2->ZZZbatches, ts2->ZZZnp, ts2->ZZZnsusp, ts2->ZZZdeeps);
        }
      }
      if (ZZZi_ticks) fprintf(stdout, "idle %.4f\n", (double) ZZZi_ticks * 100 / ZZZr_ticks);
    }
    fflush(stdout);
  }
  if (ZZZready_fd == -2 && ZZZclosed == ZZZrconns) exit (3);

  lock(&pc->context.mutex);
  bool can_free = proactor_remove(&pc->context);
  unlock(&pc->context.mutex);
  if (can_free)
    pconnection_final_free(pc);
  // else proactor_disconnect logic owns psocket and its final free
}

static void invalidate_wbuf(pconnection_t *pc) {
  if (pc->wbuf_valid) {
    if (pc->wbuf_completed)
      pn_connection_driver_write_done(&pc->driver, pc->wbuf_completed);
    pc->wbuf_completed = 0;
    pc->wbuf_remaining = 0;
    pc->wbuf_valid = false;
  }
}

// Never call with any locks held.
static void ensure_wbuf(pconnection_t *pc) {
  if (!pc->wbuf_valid) {
    // next connection_driver call is the expensive output generator
    pn_bytes_t wbuf = pn_connection_driver_write_buffer(&pc->driver);
    pc->wbuf_completed = 0;
    pc->wbuf_remaining = wbuf.size;
    pc->wbuf_current = wbuf.start;
    pc->wbuf_valid = true;
  }
}

// Call with lock held or from forced_shutdown
static void pconnection_begin_close(pconnection_t *pc) {
  if (!pc->context.closing) {
    pc->context.closing = true;
    if (pc->current_arm) {
      // Force EPOLLHUP callback(s)
      shutdown(pc->psocket.sockfd, SHUT_RDWR);
    }

    pn_connection_driver_close(&pc->driver);
    if (ptimer_shutdown(&pc->timer, pc->timer_armed))
      pc->timer_armed = false;  // disarmed in the sense that the timer will never fire again
    else if (!pc->timer_armed) {
      // In doubt.  One last callback to collect
      rearm(pc->psocket.proactor, &pc->timer.epoll_io);
      pc->timer_armed = true;
    }
  }
}

static void pconnection_forced_shutdown(pconnection_t *pc) {
  // Called by proactor_free, no competing threads, no epoll activity.
  pc->current_arm = 0;
  pc->new_events = 0;
  pconnection_begin_close(pc);
  // pconnection_process will never be called again.  Zero everything.
  pc->timer_armed = false;
  pc->context.wake_pending = 0;
  pn_collector_release(pc->driver.collector);
  assert(pconnection_is_final(pc));
  pconnection_cleanup(pc);
}

static pn_event_t *pconnection_batch_next(pn_event_batch_t *batch) {
  pconnection_t *pc = batch_pconnection(batch);
  if (!pc->driver.connection) return NULL;
  pn_event_t *e = pn_connection_driver_next_event(&pc->driver);
  if (!e) {
    pn_proactor_t *p = pc->context.proactor;
    bool idle_threads;
    lock(&p->sched_mutex);
    idle_threads = (p->suspend_list_head != NULL);
    unlock(&p->sched_mutex);
    if (idle_threads) {
      write_flush(pc);  // May generate transport event
      pc->read_blocked = pc->write_blocked = false;
      pconnection_process(pc, 0, false, false, true);
      e = pn_connection_driver_next_event(&pc->driver);
    }
    else {
      write_flush(pc);  // May generate transport event
      e = pn_connection_driver_next_event(&pc->driver);
      if (!e && pc->hog_count < HOG_MAX) {
        pconnection_process(pc, 0, false, false, true);
        e = pn_connection_driver_next_event(&pc->driver);
      }
    }
  }
  if (e) invalidate_wbuf(pc);
  return e;
}

/* Shortcuts */
static inline bool pconnection_rclosed(pconnection_t  *pc) {
  return pn_connection_driver_read_closed(&pc->driver);
}

static inline bool pconnection_wclosed(pconnection_t  *pc) {
  return pn_connection_driver_write_closed(&pc->driver);
}

/* Call only from working context (no competitor for pc->current_arm or
   connection driver).  If true returned, caller must do
   pconnection_rearm().

   Never rearm(0 | EPOLLONESHOT), since this really means
   rearm(EPOLLHUP | EPOLLERR | EPOLLONESHOT) and leaves doubt that the
   EPOLL_CTL_DEL can prevent a parallel HUP/ERR error notification during
   close/shutdown.  Let read()/write() return 0 or -1 to trigger cleanup logic.
*/
static bool pconnection_rearm_check(pconnection_t *pc) {
  assert(pc->wbuf_valid);
  if (pconnection_rclosed(pc) && pconnection_wclosed(pc)) {
    return false;
  }
  uint32_t wanted_now = (pc->read_blocked && !pconnection_rclosed(pc)) ? EPOLLIN : 0;
  if (!pconnection_wclosed(pc)) {
    if (pc->write_blocked)
      wanted_now |= EPOLLOUT;
    else {
      if (pc->wbuf_remaining > 0)
        wanted_now |= EPOLLOUT;
    }
  }
  if (!wanted_now && dbgz) fprintf(stderr, "=rearmchk no want %p\n", (void *) &pc->context);
  if (!wanted_now) return false;
  if (wanted_now == pc->current_arm && dbgz) fprintf(stderr, "=rearmchk want same %d %p\n", wanted_now, (void *) &pc->context);
  if (wanted_now == pc->current_arm) return false;
  if (dbgz) fprintf(stderr, "=rearmchk needed old %d  new %d   %p  %d %d\n", pc->current_arm, wanted_now, (void *) &pc->context, pc->read_blocked, pc->write_blocked);
  lock(&pc->rearm_mutex);      /* unlocked in pconnection_rearm... */
  // Always favour main epollfd

  pc->current_arm = pc->psocket.epoll_io.wanted = wanted_now;
  return true;                     /* ... so caller MUST call pconnection_rearm */
}

/* Call without lock */
static inline void pconnection_rearm(pconnection_t *pc) {
  rearm(pc->psocket.proactor, &pc->psocket.epoll_io);
  unlock(&pc->rearm_mutex);
  // Return immediately.  pc may have just been freed by another thread.
}

/* Only call when context switch is imminent.  Sched lock is highly contested. */
// Call with both context and sched locks.
static bool pconnection_sched_sync(pconnection_t *pc) {
  if (pc->sched_timeout) {
    pc->tick_pending = true;
    pc->sched_timeout = false;
  }
  if (pc->psocket.sched_io_events) {
    pc->new_events = pc->psocket.sched_io_events;
    pc->psocket.sched_io_events = 0;
    pc->current_arm = 0;  // or outside lock?
  }
  if (pc->context.sched_wake) {
    pc->context.sched_wake = false;
    wake_done(&pc->context);
  }
  pc->context.sched_pending = false;

  // Indicate if there are free proactor threads
  pn_proactor_t *p = pc->context.proactor;
  return p->poller_suspended || p->suspend_list_head;
}

/* Call with context lock and having done a write_flush() to "know" the value of wbuf_remaining */
static inline bool pconnection_work_pending(pconnection_t *pc) {
  assert(pc->wbuf_valid);
  if (pc->new_events || pc->wake_count || pc->tick_pending || pc->queued_disconnect)
    return true;
  if (!pc->read_blocked && !pconnection_rclosed(pc))
    return true;
  return (pc->wbuf_remaining > 0 && !pc->write_blocked);
}

/* Call with no locks. */
static void pconnection_done(pconnection_t *pc) {
  pn_proactor_t *p = pc->context.proactor;
  tslot_t *ts = pc->context.runner;
  write_flush(pc);
  if (dbgy(&pc->context)) pc->zzdones++;
  bool notify = false;
  bool self_wake = false;
  lock(&pc->context.mutex);
  pc->context.working = false;  // So we can wake() ourself if necessary.  We remain the de facto
                                // working context while the lock is held.  Need sched_sync too to drain possible stale wake.
  pc->hog_count = 0;
  bool has_event = pconnection_has_event(pc);
  // Do as little as possible while holding the sched lock
  lock(&p->sched_mutex);
  pconnection_sched_sync(pc);
  unlock(&p->sched_mutex);

  if (has_event || pconnection_work_pending(pc)) {
    self_wake = true;
    if (dbgz) fprintf(stderr, "Pd %d  selfwake %d\n", pc->context.ZZZxid, notify);
  } else if (pn_connection_driver_finished(&pc->driver)) {
    if (dbgz) fprintf(stderr, "pc_done_finished      %p\n", (void *) pc);
    pconnection_begin_close(pc);
    if (pconnection_is_final(pc)) {
      unlock(&pc->context.mutex);
      if (dbgz) fprintf(stderr, "pc_done_cleanup      %p\n", (void *) pc);
      pconnection_cleanup(pc);
      // pc may be undefined now
      lock(&p->sched_mutex);
      notify = unassign_thread_lh(ts, UNUSED);
      unlock(&p->sched_mutex);
      if (notify)
        wake_notify(&p->context);
      return;
    }
    if (dbgz) fprintf(stderr, "PD %d  surprise ZZZZZZZZZZZZZZZZZZZZZZ\n", pc->context.ZZZxid);
  }
  if (dbgz) fprintf(stderr, "zepd pc %p   t%d\n", (void *) &pc->context, ZZZts(p, pc->context.runner));
  if (self_wake)
    notify = wake(&pc->context);

  pcontext_t *ctx = &pc->context;
  if (ctx->ZZZr_start) {
    ctx->ZZZr_ticks += (hrtick() - ctx->ZZZr_start);
    ctx->ZZZr_start = 0;
  }

  bool rearm = pconnection_rearm_check(pc);
  if (dbgz) fprintf(stderr, "PD  %d %d %d\n", pc->context.ZZZxid, pc->context.wake_pending, pc->wake_count);

  unlock(&pc->context.mutex);
  if (rearm) pconnection_rearm(pc);  // May free pc on another thread.  Return.
  lock(&p->sched_mutex);
  if (unassign_thread_lh(ts, UNUSED))
    notify = true;
  unlock(&p->sched_mutex);
  if (notify) wake_notify(&p->context);
  return;
}

// Return true unless error
 static bool pconnection_write(pconnection_t *pc) {
  size_t wbuf_size = pc->wbuf_remaining;
  ssize_t n = send(pc->psocket.sockfd, pc->wbuf_current, wbuf_size, MSG_NOSIGNAL);
  if (dbgz) fprintf(stderr, "    ----> %p %d\n", (void *) &pc->context, (int) n);
  if (ZZZdbgy) pc->zzsysw++;
  if (n > 0) {
    if (ZZZdbgy) pc->zzsnd++;

    pc->wbuf_completed += n;
    pc->wbuf_remaining -= n;
    pc->io_doublecheck = false;
    if (pc->wbuf_remaining)
      pc->write_blocked = true;
    else {
      // No need to aggregate multiple writes
      pn_connection_driver_write_done(&pc->driver, pc->wbuf_completed);
      pc->wbuf_completed = 0;
    }
  } else if (errno == EWOULDBLOCK) {
    pc->write_blocked = true;
  } else if (!(errno == EAGAIN || errno == EINTR)) {
    return false;
  }
  return true;
}

// Never call with any locks held.
static void write_flush(pconnection_t *pc) {
  ensure_wbuf(pc);
  if (!pc->write_blocked && !pconnection_wclosed(pc)) {
    if (pc->wbuf_remaining > 0) {
      if (!pconnection_write(pc)) {
        psocket_error(&pc->psocket, errno, pc->disconnected ? "disconnected" : "on write to");
      }
    }
    else {
      if (pn_connection_driver_write_closed(&pc->driver)) {
        shutdown(pc->psocket.sockfd, SHUT_WR);
        pc->write_blocked = true;
      }
    }
  }
}

static void pconnection_connected_lh(pconnection_t *pc);
static void pconnection_maybe_connect_lh(pconnection_t *pc);

/* BOGUS DOC with new epoll ZZZZZ
 * May be called concurrently from multiple threads:
 *   pn_event_batch_t loop (topup is true)
 *   timer (timeout is true)
 *   socket io (events != 0) from PCONNECTION_IO
 *      and PCONNECTION_IO_2 event masks (possibly simultaneously)
 *   one or more wake()
 * Only one thread becomes (or always was) the working thread.
 */
static pn_event_batch_t *pconnection_process(pconnection_t *pc, uint32_t events, bool timeout, bool sched_wake, bool topup) {
//  bool inbound_wake = !(events | timeout | topup);
  bool inbound_wake = sched_wake;
  bool rearm_timer = false;
  bool timer_fired = false;
  bool waking = false;
  bool tick_required = false;

  // Don't touch data exclusive to working thread (yet).

  if (dbgz) fprintf(stderr, "pc_proc %d %d %d %d     t%d %p\n", (int) events, timeout, sched_wake, topup, ZZZts(pc->context.proactor, pc->context.runner), (void *) &pc->context);
  if (timeout) {
    rearm_timer = true;
    timer_fired = ptimer_callback(&pc->timer) != 0;
  }
  lock(&pc->context.mutex);

  if (events) {
    pc->new_events = events;
    pc->current_arm = 0;
    events = 0;
  }
  if (timer_fired) {
    pc->tick_pending = true;
    timer_fired = false;
  }
  if (inbound_wake) {
    wake_done(&pc->context);
    inbound_wake = false;
  }

  if (rearm_timer)
    pc->timer_armed = false;

  if (topup) {
    // Only called by the batch owner.  Does not loop, just "tops up"
    // once.  May be back depending on hog_count.
    assert(pc->context.working);
  }
  else {
    if (pc->context.working) {
      // Another thread is the working context.
      assert(false); // Should be impossible with new scheduler
      unlock(&pc->context.mutex);
      return NULL;
    }
    pc->context.working = true;
  }

  // Confirmed as working thread.  Review state and unlock ASAP.

 retry:

  if (pc->queued_disconnect) {  // From pn_proactor_disconnect()
    pc->queued_disconnect = false;
    if (!pc->context.closing) {
      if (pc->disconnect_condition) {
        pn_condition_copy(pn_transport_condition(pc->driver.transport), pc->disconnect_condition);
      }
      pn_connection_driver_close(&pc->driver);
    }
  }

  if (pconnection_has_event(pc)) {
    unlock(&pc->context.mutex);
    return &pc->batch;
  }
  bool closed = pconnection_rclosed(pc) && pconnection_wclosed(pc);
  if (pc->wake_count) {
    waking = !closed;
    pc->wake_count = 0;
  }
  if (pc->tick_pending) {
    pc->tick_pending = false;
    tick_required = !closed;
  }

  if (pc->new_events) {
    uint32_t update_events = pc->new_events;
    pc->current_arm = 0;
    pc->new_events = 0;
    if (!pc->context.closing) {
      if ((update_events & (EPOLLHUP | EPOLLERR)) && !pconnection_rclosed(pc) && !pconnection_wclosed(pc))
        pconnection_maybe_connect_lh(pc);
      else
        pconnection_connected_lh(pc); /* Non error event means we are connected */
      if (update_events & EPOLLOUT)
        pc->write_blocked = false;
      if (update_events & EPOLLIN)
        pc->read_blocked = false;
    }
  }

  if (pc->context.closing && pconnection_is_final(pc)) {
    unlock(&pc->context.mutex);
    pconnection_cleanup(pc);
    return NULL;
  }

  unlock(&pc->context.mutex);
  pc->hog_count++; // working context doing work

  if (waking) {
    pn_connection_t *c = pc->driver.connection;
    pn_collector_put(pn_connection_collector(c), PN_OBJECT, c, PN_CONNECTION_WAKE);
    waking = false;
  }

  // read... tick... write
  // perhaps should be: write_if_recent_EPOLLOUT... read... tick... write

  if (!pconnection_rclosed(pc)) {
    pn_rwbytes_t rbuf = pn_connection_driver_read_buffer(&pc->driver);
    if (rbuf.size > 0 && !pc->read_blocked) {
      ssize_t n = read(pc->psocket.sockfd, rbuf.start, rbuf.size);
      if (ZZZdbgy) pc->zzsysr++;
      if (dbgz) fprintf(stderr, "    <---- %p %d\n", (void *) &pc->context, (int) n);

      if (n > 0) {
        pn_connection_driver_read_done(&pc->driver, n);
        invalidate_wbuf(pc);
        pconnection_tick(pc);         /* check for tick changes. */
        tick_required = false;
        pc->io_doublecheck = false;
        if (ZZZdbgy) pc->zzrcv++;
        if (!pn_connection_driver_read_closed(&pc->driver) && (size_t)n < rbuf.size)
          pc->read_blocked = true;
      }
      else if (n == 0) {
        pn_connection_driver_read_close(&pc->driver);
      }
      else if (errno == EWOULDBLOCK)
        pc->read_blocked = true;
      else if (!(errno == EAGAIN || errno == EINTR)) {
        psocket_error(&pc->psocket, errno, pc->disconnected ? "disconnected" : "on read from");
      }
    }
  }

  if (tick_required) {
    pconnection_tick(pc);         /* check for tick changes. */
    tick_required = false;
    invalidate_wbuf(pc);
  }

  if (topup) {
    // If there was anything new to topup, we have it by now.
    return NULL;  // caller already owns the batch
  }

  if (pconnection_has_event(pc)) {
    invalidate_wbuf(pc);
    return &pc->batch;
  }

  write_flush(pc);

  lock(&pc->context.mutex);
  if (pc->context.closing && pconnection_is_final(pc)) {
    unlock(&pc->context.mutex);
    pconnection_cleanup(pc);
    return NULL;
  }

  // Never stop working while work remains.  hog_count exception to this rule is elsewhere.
  lock(&pc->context.proactor->sched_mutex);
  bool workers_free = pconnection_sched_sync(pc);
  unlock(&pc->context.proactor->sched_mutex);

  if (pconnection_work_pending(pc)) {
    goto retry;  // TODO: get rid of goto without adding more locking
  }

  pc->context.working = false;
  pc->hog_count = 0;
  if (pn_connection_driver_finished(&pc->driver)) {
    pconnection_begin_close(pc);
    if (pconnection_is_final(pc)) {
      unlock(&pc->context.mutex);
      pconnection_cleanup(pc);
      return NULL;
    }
  }

  if (workers_free && !pc->context.closing && !pc->io_doublecheck) {
    // check one last time for new io before context switch
    pc->io_doublecheck = true;
    pc->read_blocked = false;
    pc->write_blocked = false;
    pc->context.working = true;
    goto retry;
  }

  if (!pc->timer_armed && !pc->timer.shutting_down && pc->timer.timerfd >= 0) {
    pc->timer_armed = true;
    rearm(pc->psocket.proactor, &pc->timer.epoll_io);
  }
  bool rearm_pc = pconnection_rearm_check(pc);  // holds rearm_mutex until pconnection_rearm() below

  unlock(&pc->context.mutex);
  if (rearm_pc) pconnection_rearm(pc);  // May free pc on another thread.  Return right away.
  return NULL;
}

static void configure_socket(int sock) {
  int flags = fcntl(sock, F_GETFL);
  flags |= O_NONBLOCK;
  (void)fcntl(sock, F_SETFL, flags); // TODO: check for error

  int tcp_nodelay = 1;
  (void)setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*) &tcp_nodelay, sizeof(tcp_nodelay));
}

/* Called with context.lock held */
void pconnection_connected_lh(pconnection_t *pc) {
  if (!pc->connected) {
    pc->connected = true;
    if (pc->addrinfo) {
      freeaddrinfo(pc->addrinfo);
      pc->addrinfo = NULL;
    }
    pc->ai = NULL;
    socklen_t len = sizeof(pc->remote.ss);
    (void)getpeername(pc->psocket.sockfd, (struct sockaddr*)&pc->remote.ss, &len);
  }
}

/* multi-address connections may call pconnection_start multiple times with diffferent FDs  */
static void pconnection_start(pconnection_t *pc) {
  int efd = pc->psocket.proactor->epollfd;
  /* Start timer, a no-op if the timer has already started. */
  start_polling(&pc->timer.epoll_io, efd);  // TODO: check for error

  /* Get the local socket name now, get the peer name in pconnection_connected */
  socklen_t len = sizeof(pc->local.ss);
  (void)getsockname(pc->psocket.sockfd, (struct sockaddr*)&pc->local.ss, &len);

  epoll_extended_t *ee = &pc->psocket.epoll_io;
  if (ee->polling) {     /* This is not the first attempt, stop polling and close the old FD */
    int fd = ee->fd;     /* Save fd, it will be set to -1 by stop_polling */
    stop_polling(ee, efd);
    pclosefd(pc->psocket.proactor, fd);
  }
  ee->fd = pc->psocket.sockfd;
  pc->current_arm = ee->wanted = EPOLLIN | EPOLLOUT;
  start_polling(ee, efd);  // TODO: check for error
}

/* Called on initial connect, and if connection fails to try another address */
static void pconnection_maybe_connect_lh(pconnection_t *pc) {
  errno = 0;
  if (!pc->connected) {         /* Not yet connected */
    while (pc->ai) {            /* Have an address */
      struct addrinfo *ai = pc->ai;
      pc->ai = pc->ai->ai_next; /* Move to next address in case this fails */
      int fd = socket(ai->ai_family, SOCK_STREAM, 0);
      if (fd >= 0) {
        configure_socket(fd);
        if (!connect(fd, ai->ai_addr, ai->ai_addrlen) || errno == EINPROGRESS) {
          pc->psocket.sockfd = fd;
          pconnection_start(pc);
          return;               /* Async connection started */
        } else {
          close(fd);
        }
      }
      /* connect failed immediately, go round the loop to try the next addr */
    }
    freeaddrinfo(pc->addrinfo);
    pc->addrinfo = NULL;
    /* If there was a previous attempted connection, let the poller discover the
       errno from its socket, otherwise set the current error. */
    if (pc->psocket.sockfd < 1) {
      psocket_error(&pc->psocket, errno ? errno : ENOTCONN, "on connect");
    }
  }
  pc->disconnected = true;
}

static int pgetaddrinfo(const char *host, const char *port, int flags, struct addrinfo **res)
{
  struct addrinfo hints = { 0 };
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | flags;
  return getaddrinfo(host, port, &hints, res);
}

static inline bool is_inactive(pn_proactor_t *p) {
  return (!p->contexts && !p->disconnects_pending && !p->timeout_set && !p->shutting_down);
}

/* If inactive set need_inactive and return true if the proactor needs a wakeup */
static bool wake_if_inactive(pn_proactor_t *p) {
  if (is_inactive(p)) {
    p->need_inactive = true;
    return wake(&p->context);
  }
  return false;
}

void pn_proactor_connect2(pn_proactor_t *p, pn_connection_t *c, pn_transport_t *t, const char *addr) {
  pconnection_t *pc = (pconnection_t*) calloc(1, sizeof(pconnection_t));
  assert(pc); // TODO: memory safety
  const char *err = pconnection_setup(pc, p, c, t, false, addr);
  if (err) {    /* TODO aconway 2017-09-13: errors must be reported as events */
    pn_logf("pn_proactor_connect failure: %s", err);
    return;
  }
  // TODO: check case of proactor shutting down

  lock(&pc->context.mutex);
  proactor_add(&pc->context);
  pn_connection_open(pc->driver.connection); /* Auto-open */

  bool notify = false;
  bool notify_proactor = false;

  if (pc->disconnected) {
    notify = wake(&pc->context);    /* Error during initialization */
  } else {
    int gai_error = pgetaddrinfo(pc->psocket.host, pc->psocket.port, 0, &pc->addrinfo);
    if (!gai_error) {
      pn_connection_open(pc->driver.connection); /* Auto-open */
      pc->ai = pc->addrinfo;
      pconnection_maybe_connect_lh(pc); /* Start connection attempts */
      if (pc->disconnected) notify = wake(&pc->context);
    } else {
      psocket_gai_error(&pc->psocket, gai_error, "connect to ");
      notify = wake(&pc->context);
      lock(&p->context.mutex);
      notify_proactor = wake_if_inactive(p);
      unlock(&p->context.mutex);
    }
  }
  /* We need to issue INACTIVE on immediate failure */
  unlock(&pc->context.mutex);
  if (notify) wake_notify(&pc->context);
  if (notify_proactor) wake_notify(&p->context);
}

static void pconnection_tick(pconnection_t *pc) {
  pn_transport_t *t = pc->driver.transport;
  if (pn_transport_get_idle_timeout(t) || pn_transport_get_remote_idle_timeout(t)) {
    ptimer_set(&pc->timer, 0);
    uint64_t now = pn_i_now2();
    uint64_t next = pn_transport_tick(t, now);
    if (next) {
      ptimer_set(&pc->timer, next - now);
    }
  }
}

void pn_connection_wake(pn_connection_t* c) {
  bool notify = false;
  pconnection_t *pc = get_pconnection(c);
  if (pc) {
    lock(&pc->context.mutex);
    if (!pc->context.closing) {
      pc->wake_count++;
      notify = wake(&pc->context);
    }
    unlock(&pc->context.mutex);
  }
  if (notify) wake_notify(&pc->context);
}

void pn_proactor_release_connection(pn_connection_t *c) {
  bool notify = false;
  pconnection_t *pc = get_pconnection(c);
  if (pc) {
    set_pconnection(c, NULL);
    lock(&pc->context.mutex);
    pn_connection_driver_release_connection(&pc->driver);
    pconnection_begin_close(pc);
    notify = wake(&pc->context);
    unlock(&pc->context.mutex);
  }
  if (notify) wake_notify(&pc->context);
}

// ========================================================================
// listener
// ========================================================================

pn_listener_t *pn_event_listener(pn_event_t *e) {
  return (pn_event_class(e) == pn_listener__class()) ? (pn_listener_t*)pn_event_context(e) : NULL;
}

pn_listener_t *pn_listener() {
  pn_listener_t *l = (pn_listener_t*)calloc(1, sizeof(pn_listener_t));
  if (l) {
    l->batch.next_event = listener_batch_next;
    l->collector = pn_collector();
    l->condition = pn_condition();
    l->attachments = pn_record();
    if (!l->condition || !l->collector || !l->attachments) {
      pn_listener_free(l);
      return NULL;
    }
    pn_proactor_t *unknown = NULL;  // won't know until pn_proactor_listen
    pcontext_init(&l->context, LISTENER, unknown, l);
    pmutex_init(&l->rearm_mutex);
  }
  return l;
}

void pn_proactor_listen(pn_proactor_t *p, pn_listener_t *l, const char *addr, int backlog)
{
  // TODO: check listener not already listening for this or another proactor
  lock(&l->context.mutex);
  l->context.proactor = p;;
  l->backlog = backlog;

  char addr_buf[PN_MAX_ADDR];
  const char *host, *port;
  pni_parse_addr(addr, addr_buf, PN_MAX_ADDR, &host, &port);

  struct addrinfo *addrinfo = NULL;
  int gai_err = pgetaddrinfo(host, port, AI_PASSIVE | AI_ALL, &addrinfo);
  if (!gai_err) {
    /* Count addresses, allocate enough space for sockets */
    size_t len = 0;
    for (struct addrinfo *ai = addrinfo; ai; ai = ai->ai_next) {
      ++len;
    }
    assert(len > 0);            /* guaranteed by getaddrinfo */
    l->acceptors = (acceptor_t*)calloc(len, sizeof(acceptor_t));
    assert(l->acceptors);      /* TODO aconway 2017-05-05: memory safety */
    l->acceptors_size = 0;
    uint16_t dynamic_port = 0;  /* Record dynamic port from first bind(0) */
    /* Find working listen addresses */
    for (struct addrinfo *ai = addrinfo; ai; ai = ai->ai_next) {
      if (dynamic_port) set_port(ai->ai_addr, dynamic_port);
      int fd = socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
      static int on = 1;
      if (fd >= 0) {
        if (!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) &&
            /* We listen to v4/v6 on separate sockets, don't let v6 listen for v4 */
            (ai->ai_family != AF_INET6 ||
             !setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on))) &&
            !bind(fd, ai->ai_addr, ai->ai_addrlen) &&
            !listen(fd, backlog))
        {
          acceptor_t *acceptor = &l->acceptors[l->acceptors_size++];
          /* Get actual address */
          socklen_t len = pn_netaddr_socklen(&acceptor->addr);
          (void)getsockname(fd, (struct sockaddr*)(&acceptor->addr.ss), &len);
          if (acceptor == l->acceptors) { /* First acceptor, check for dynamic port */
            dynamic_port = check_dynamic_port(ai->ai_addr, pn_netaddr_sockaddr(&acceptor->addr));
          } else {              /* Link addr to previous addr */
            (acceptor-1)->addr.next = &acceptor->addr;
          }

          acceptor->accepted_fd = -1;
          psocket_t *ps = &acceptor->psocket;
          psocket_init(ps, p, l, addr);
          ps->sockfd = fd;
          ps->epoll_io.fd = fd;
          ps->epoll_io.wanted = EPOLLIN;
          ps->epoll_io.polling = false;
          lock(&l->rearm_mutex);
          start_polling(&ps->epoll_io, ps->proactor->epollfd);  // TODO: check for error
          l->active_count++;
          acceptor->armed = true;
          unlock(&l->rearm_mutex);
        } else {
          close(fd);
        }
      }
    }
  }
  if (addrinfo) {
    freeaddrinfo(addrinfo);
  }
  bool notify = wake(&l->context);

  if (l->acceptors_size == 0) { /* All failed, create dummy socket with an error */
    l->acceptors = (acceptor_t*)realloc(l->acceptors, sizeof(acceptor_t));
    l->acceptors_size = 1;
    memset(l->acceptors, 0, sizeof(acceptor_t));
    psocket_init(&l->acceptors[0].psocket, p, l, addr);
    l->acceptors[0].accepted_fd = -1;
    if (gai_err) {
      psocket_gai_error(&l->acceptors[0].psocket, gai_err, "listen on");
    } else {
      psocket_error(&l->acceptors[0].psocket, errno, "listen on");
    }
  } else {
    pn_collector_put(l->collector, pn_listener__class(), l, PN_LISTENER_OPEN);
  }
  proactor_add(&l->context);
  unlock(&l->context.mutex);
  if (notify) wake_notify(&l->context);
  return;
}

// call with lock held and context.working false
static inline bool listener_can_free(pn_listener_t *l) {
  return l->context.closing && l->close_dispatched && !l->context.wake_pending && !l->active_count;
}

static inline void listener_final_free(pn_listener_t *l) {
  pcontext_finalize(&l->context);
  pmutex_finalize(&l->rearm_mutex);
  free(l->acceptors);
  free(l);
}

void pn_listener_free(pn_listener_t *l) {
  /* Note at this point either the listener has never been used (freed by user)
     or it has been closed, so all its sockets are closed.
  */
  if (l) {
    bool can_free = true;
    if (l->collector) pn_collector_free(l->collector);
    if (l->condition) pn_condition_free(l->condition);
    if (l->attachments) pn_free(l->attachments);
    lock(&l->context.mutex);
    if (l->context.proactor) {
      can_free = proactor_remove(&l->context);
    }
    unlock(&l->context.mutex);
    if (can_free)
      listener_final_free(l);
  }
}

/* Always call with lock held so it can be unlocked around overflow processing. */
static void listener_begin_close(pn_listener_t* l) {
  if (!l->context.closing) {
    l->context.closing = true;

    /* Close all listening sockets */
    for (size_t i = 0; i < l->acceptors_size; ++i) {
      acceptor_t *a = &l->acceptors[i];
      psocket_t *ps = &a->psocket;
      if (ps->sockfd >= 0) {
        lock(&l->rearm_mutex);
        if (a->armed) {
          shutdown(ps->sockfd, SHUT_RD);  // Force epoll event and callback
        } else {
          stop_polling(&ps->epoll_io, ps->proactor->epollfd);
          close(ps->sockfd);
          ps->sockfd = -1;
          l->active_count--;
        }
        unlock(&l->rearm_mutex);
      }
    }
    /* Close all sockets waiting for a pn_listener_accept2() */
    if (l->unclaimed) l->pending_count++;
    acceptor_t *a = listener_list_next(&l->pending_acceptors);
    while (a) {
      close(a->accepted_fd);
      a->accepted_fd = -1;
      l->pending_count--;
      a = listener_list_next(&l->pending_acceptors);
    }
    assert(!l->pending_count);

    unlock(&l->context.mutex);
    /* Remove all acceptors from the overflow list.  closing flag prevents re-insertion.*/
    proactor_rearm_overflow(pn_listener_proactor(l));
    lock(&l->context.mutex);
    pn_collector_put(l->collector, pn_listener__class(), l, PN_LISTENER_CLOSE);
  }
}

void pn_listener_close(pn_listener_t* l) {
  bool notify = false;
  lock(&l->context.mutex);
  if (!l->context.closing) {
    listener_begin_close(l);
    notify = wake(&l->context);
  }
  unlock(&l->context.mutex);
  if (notify) wake_notify(&l->context);
}

static void listener_forced_shutdown(pn_listener_t *l) {
  // Called by proactor_free, no competing threads, no epoll activity.
  lock(&l->context.mutex); // needed because of interaction with proactor_rearm_overflow
  listener_begin_close(l);
  unlock(&l->context.mutex);
  // pconnection_process will never be called again.  Zero everything.
  l->context.wake_pending = 0;
  l->close_dispatched = true;
  l->active_count = 0;
  assert(listener_can_free(l));
  pn_listener_free(l);
}

/* Accept a connection as part of listener_process(). Called with listener context lock held. */
static void listener_accept_lh(psocket_t *ps) {
  pn_listener_t *l = psocket_listener(ps);
  acceptor_t *acceptor = psocket_acceptor(ps);
  assert(acceptor->accepted_fd < 0); /* Shouldn't already have an accepted_fd */
  acceptor->accepted_fd = accept(ps->sockfd, NULL, 0);
  if (dbgz) fprintf(stderr, "    l accept %p  %d\n", (void *) &l->context, acceptor->accepted_fd);
  if (acceptor->accepted_fd >= 0) {
    //    acceptor_t *acceptor = listener_list_next(pending_acceptors);
    listener_list_append(&l->pending_acceptors, acceptor);
    l->pending_count++;
  } else {
    int err = errno;
    if (err == ENFILE || err == EMFILE) {
      listener_set_overflow(acceptor);
    } else {
      psocket_error(ps, err, "accept");
    }
  }
}

/* Process a listening socket */
static pn_event_batch_t *listener_process(pn_listener_t *l, int n_events, bool wake) {
  // TODO: some parallelization of the accept mechanism.
//  pn_listener_t *l = psocket_listener(ps);
//  acceptor_t *a = psocket_acceptor(ps);

  lock(&l->context.mutex);
  if (n_events) {
    for (size_t i = 0; i < l->acceptors_size; i++) {
      psocket_t *ps = &l->acceptors[i].psocket;
      if (ps->working_io_events) {
        uint32_t events = ps->working_io_events;
        ps->working_io_events = 0;
        l->acceptors[i].armed = false;
        if (l->context.closing) {
          lock(&l->rearm_mutex);
          stop_polling(&ps->epoll_io, ps->proactor->epollfd);
          unlock(&l->rearm_mutex);
          close(ps->sockfd);
          ps->sockfd = -1;
          l->active_count--;
        }
        else {
          if (events & EPOLLRDHUP) {
            /* Calls listener_begin_close which closes all the listener's sockets */
            psocket_error(ps, errno, "listener epoll");
          } else if (!l->context.closing && events & EPOLLIN) {
            listener_accept_lh(ps);
          }
        }
      }
    }
  }
  if (wake) {
    wake_done(&l->context); // callback accounting
  }
  pn_event_batch_t *lb = NULL;
  if (!l->context.working) {
    l->context.working = true;
    if (listener_has_event(l))
      lb = &l->batch;
    else {
      l->context.working = false;
      if (listener_can_free(l)) {
        unlock(&l->context.mutex);
        pn_listener_free(l);
        return NULL;
      }
    }
  }
  unlock(&l->context.mutex);
  return lb;
}

static pn_event_t *listener_batch_next(pn_event_batch_t *batch) {
  pn_listener_t *l = batch_listener(batch);
  lock(&l->context.mutex);
  pn_event_t *e = pn_collector_next(l->collector);
  if (!e && l->pending_count && !l->unclaimed) {
    // empty collector means pn_collector_put() will not coalesce
    pn_collector_put(l->collector, pn_listener__class(), l, PN_LISTENER_ACCEPT);
    l->unclaimed = true;
    l->pending_count--;
    e = pn_collector_next(l->collector);
  }
  if (e && pn_event_type(e) == PN_LISTENER_CLOSE)
    l->close_dispatched = true;
  unlock(&l->context.mutex);
  if (ZZZready_fd >= 0 && pn_event_type(e) == PN_LISTENER_OPEN) {
    write(ZZZready_fd, "\n", 1);
    close(ZZZready_fd);
    ZZZready_fd = -2;
  }
  return log_event(l, e);
}

static void listener_done(pn_listener_t *l) {
  pn_proactor_t *p = l->context.proactor;
  tslot_t *ts = l->context.runner;
  bool notify = false;
  lock(&l->context.mutex);
  l->context.working = false;

  lock(&p->sched_mutex);
  int n_events = 0;
  for (size_t i = 0; i < l->acceptors_size; i++) {
    psocket_t *ps = &l->acceptors[i].psocket;
    if (ps->sched_io_events) {
      ps->working_io_events = ps->sched_io_events;
      ps->sched_io_events = 0;
    }
    if (ps->working_io_events)
      n_events++;
  }
  if (l->context.sched_wake) {
    l->context.sched_wake = false;
    wake_done(&l->context);
  }
  unlock(&p->sched_mutex);

  if (!n_events && listener_can_free(l)) {
    unlock(&l->context.mutex);
    pn_listener_free(l);
    lock(&p->sched_mutex);
    notify = unassign_thread_lh(ts, UNUSED);
    unlock(&p->sched_mutex);
    if (notify)
      wake_notify(&p->context);
    return;
  } else if (n_events || listener_has_event(l))
    notify = wake(&l->context);

  if (dbgz) fprintf(stderr, "zepd l %p  t%d\n", (void *) &l->context, ZZZts(p, l->context.prev_runner));
  unlock(&l->context.mutex);
  lock(&p->sched_mutex);
  if (unassign_thread_lh(ts, UNUSED))
    notify = true;
  unlock(&p->sched_mutex);
  if (notify) wake_notify(&l->context);
}

pn_proactor_t *pn_listener_proactor(pn_listener_t* l) {
  return l ? l->acceptors[0].psocket.proactor : NULL;
}

pn_condition_t* pn_listener_condition(pn_listener_t* l) {
  return l->condition;
}

void *pn_listener_get_context(pn_listener_t *l) {
  return l->listener_context;
}

void pn_listener_set_context(pn_listener_t *l, void *context) {
  l->listener_context = context;
}

pn_record_t *pn_listener_attachments(pn_listener_t *l) {
  return l->attachments;
}

void pn_listener_accept2(pn_listener_t *l, pn_connection_t *c, pn_transport_t *t) {
  pconnection_t *pc = (pconnection_t*) calloc(1, sizeof(pconnection_t));
  assert(pc); // TODO: memory safety
  const char *err = pconnection_setup(pc, pn_listener_proactor(l), c, t, true, "");
  if (err) {
    pn_logf("pn_listener_accept failure: %s", err);
    return;
  }
  // TODO: fuller sanity check on input args

  int err2 = 0;
  int fd = -1;
  psocket_t *rearming_ps = NULL;
  bool notify = false;
  lock(&l->context.mutex);
  if (l->context.closing)
    err2 = EBADF;
  else if (l->unclaimed) {
    l->unclaimed = false;
    acceptor_t *a = listener_list_next(&l->pending_acceptors);
    assert(a);
    assert(!a->armed);
    fd = a->accepted_fd;
    a->accepted_fd = -1;
    lock(&l->rearm_mutex);
    rearming_ps = &a->psocket;
    a->armed = true;
  }
  else err2 = EWOULDBLOCK;

  proactor_add(&pc->context);
  lock(&pc->context.mutex);
  pc->psocket.sockfd = fd;
  if (fd >= 0) {
    configure_socket(fd);
    pconnection_start(pc);
    pconnection_connected_lh(pc);
  }
  else
    psocket_error(&pc->psocket, err2, "pn_listener_accept");
  if (!l->context.working && listener_has_event(l))
    notify = wake(&l->context);
  unlock(&pc->context.mutex);
  unlock(&l->context.mutex);
  if (rearming_ps) {
    rearm(rearming_ps->proactor, &rearming_ps->epoll_io);
    unlock(&l->rearm_mutex);
  }
  if (dbgz) fprintf(stderr, "listener accept    rearm: %d\n", rearming_ps != NULL);
  if (notify) wake_notify(&l->context);
}


// ========================================================================
// proactor
// ========================================================================

/* Set up an epoll_extended_t to be used for wakeup or interrupts */
 static void epoll_wake_init(epoll_extended_t *ee, int eventfd, int epollfd, bool always_set) {
  ee->psocket = NULL;
  ee->fd = eventfd;
  ee->type = WAKE;
  if (always_set) {
    uint64_t increment = 1;
    if (write(eventfd, &increment, sizeof(uint64_t)) != sizeof(uint64_t))
      EPOLL_FATAL("setting eventfd", errno);
    // eventfd is set forever.  No reads, just rearms as needed.
    ee->wanted = 0;
  } else {
    ee->wanted = EPOLLIN;
  }
  ee->polling = false;
  start_polling(ee, epollfd);  // TODO: check for error
  if (always_set)
    ee->wanted = EPOLLIN;      // for all subsequent rearms
}

pn_proactor_t *pn_proactor() {
  if (getenv("EPOLL_NOWARM")) ZZZwarm_sched = false;
  if (getenv("EPOLL_DBGZ")) dbgz = true;
  if (getenv("EPOLL_DBGY")) ZZZdbgy = true;
  if (getenv("EPOLL_IMMED")) ZZZep_immediate = true;
  if (getenv("EPOLL_SPIN")) ZZZspins = atoi(getenv("EPOLL_SPIN"));
  if (getenv("EPOLL_RCONN")) ZZZrconns = atoi(getenv("EPOLL_RCONN"));
  if (getenv("EPOLL_TSBMP")) ZZZtsched_bump = atoi(getenv("EPOLL_TSBMP"));
  if (ZZZrconns) {
    if (getenv("EPOLL_READY")) {
      ZZZready_fd = open(getenv("EPOLL_READY"), O_WRONLY);
      if (ZZZready_fd < 0) printf("  ready file open failed %d\n", ZZZready_fd);
    }
  }
  if (ZZZspins) {printf("  < spins %d > \n", ZZZspins); fflush(stdout); }
  if (getenv("EPOLL_PRF")) {printf("  < new_epoll_7x > warm=%d immed=%d\n", ZZZwarm_sched, ZZZep_immediate); fflush(stdout); }
  pn_proactor_t *p = (pn_proactor_t*)calloc(1, sizeof(*p));
  if (!p) return NULL;
  p->epollfd = p->eventfd = p->timer.timerfd = -1;
  pcontext_init(&p->context, PROACTOR, p, p);
  pmutex_init(&p->eventfd_mutex);
  pmutex_init(&p->sched_mutex);
  pmutex_init(&p->tslot_mutex);
  ptimer_init(&p->timer, 0);

  if ((p->epollfd = epoll_create(1)) >= 0) {
    if ((p->eventfd = eventfd(0, EFD_NONBLOCK)) >= 0) {
      if ((p->interruptfd = eventfd(0, EFD_NONBLOCK)) >= 0) {
        if (p->timer.timerfd >= 0)
          if ((p->collector = pn_collector()) != NULL) {
            p->batch.next_event = &proactor_batch_next;
            start_polling(&p->timer.epoll_io, p->epollfd);  // TODO: check for error
            p->timer_armed = true;
            epoll_wake_init(&p->epoll_wake, p->eventfd, p->epollfd, true);
            epoll_wake_init(&p->epoll_interrupt, p->interruptfd, p->epollfd, false);
            p->kevents_length = TSMAX;  // ZZZ tuneable? variable over time?
            p->kevents = (struct epoll_event *) calloc(p->kevents_length, sizeof(struct epoll_event));
            return p;
          }
      }
    }
  }
  if (p->epollfd >= 0) close(p->epollfd);
  if (p->eventfd >= 0) close(p->eventfd);
  if (p->interruptfd >= 0) close(p->interruptfd);
  ptimer_finalize(&p->timer);
  pmutex_finalize(&p->tslot_mutex);
  pmutex_finalize(&p->sched_mutex);
  pmutex_finalize(&p->eventfd_mutex);
  if (p->collector) pn_free(p->collector);
  for (int i = 0; i < p->thread_count; i++)
    pmutex_finalize(&p->tslots[i].mutex);
  free (p);
  return NULL;
}

void pn_proactor_free(pn_proactor_t *p) {
  //  No competing threads, not even a pending timer
  p->shutting_down = true;
  close(p->epollfd);
  p->epollfd = -1;
  close(p->eventfd);
  p->eventfd = -1;
  close(p->interruptfd);
  p->interruptfd = -1;
  ptimer_finalize(&p->timer);
  while (p->contexts) {
    pcontext_t *ctx = p->contexts;
    p->contexts = ctx->next;
    switch (ctx->type) {
     case PCONNECTION:
      pconnection_forced_shutdown(pcontext_pconnection(ctx));
      break;
     case LISTENER:
      listener_forced_shutdown(pcontext_listener(ctx));
      break;
     default:
      break;
    }
  }

  pn_collector_free(p->collector);
  pmutex_finalize(&p->tslot_mutex);
  pmutex_finalize(&p->sched_mutex);
  pmutex_finalize(&p->eventfd_mutex);
  pcontext_finalize(&p->context);
  free(p);
}

pn_proactor_t *pn_event_proactor(pn_event_t *e) {
  if (pn_event_class(e) == pn_proactor__class()) return (pn_proactor_t*)pn_event_context(e);
  pn_listener_t *l = pn_event_listener(e);
  if (l) return l->acceptors[0].psocket.proactor;
  pn_connection_t *c = pn_event_connection(e);
  if (c) return pn_connection_proactor(c);
  return NULL;
}

static void proactor_add_event(pn_proactor_t *p, pn_event_type_t t) {
  pn_collector_put(p->collector, pn_proactor__class(), p, t);
}

// Call with lock held.  Leave unchanged if events pending.
// There can be multiple interrupts but only one inside the collector to avoid coalescing.
// Return true if there is an event in the collector.
static bool proactor_update_batch(pn_proactor_t *p) {
  if (proactor_has_event(p))
    return true;

  if (p->need_timeout) {
    p->need_timeout = false;
    p->timeout_set = false;
    proactor_add_event(p, PN_PROACTOR_TIMEOUT);
    return true;
  }
  if (p->need_interrupt) {
    p->need_interrupt = false;
    proactor_add_event(p, PN_PROACTOR_INTERRUPT);
    return true;
  }
  if (p->need_inactive) {
    p->need_inactive = false;
    proactor_add_event(p, PN_PROACTOR_INACTIVE);
    return true;
  }
  return false;
}

static pn_event_t *proactor_batch_next(pn_event_batch_t *batch) {
  pn_proactor_t *p = batch_proactor(batch);
  lock(&p->context.mutex);
  proactor_update_batch(p);
  pn_event_t *e = pn_collector_next(p->collector);
  if (e && pn_event_type(e) == PN_PROACTOR_TIMEOUT)
    p->timeout_processed = true;
  unlock(&p->context.mutex);
  return log_event(p, e);
}

static pn_event_batch_t *proactor_process(pn_proactor_t *p, bool timeout, bool interrupt, bool wake) {
  if (dbgz) fprintf(stderr, "p_proc %d %d %d         %d\n", timeout, interrupt, wake, p->context.working);
  bool timer_fired = timeout && ptimer_callback(&p->timer) != 0;
  if (interrupt) {
    (void)read_uint64(p->interruptfd);
    rearm(p, &p->epoll_interrupt);
  }
  lock(&p->context.mutex);
  if (interrupt) {
    p->need_interrupt = true;
  }
  if (timeout) {
    p->timer_armed = false;
    if (timer_fired && p->timeout_set) {
      p->need_timeout = true;
    }
  }
  if (wake) {
    wake_done(&p->context);
  }
  if (!p->context.working) {       /* Can generate proactor events */
    if (proactor_update_batch(p)) {
      p->context.working = true;
      unlock(&p->context.mutex);
      return &p->batch;
    }
  }
  bool rearm_timer = !p->timer_armed && !p->timer.shutting_down;
  p->timer_armed = true;
  unlock(&p->context.mutex);
  if (rearm_timer)
    rearm(p, &p->timer.epoll_io);
  return NULL;
}

static void proactor_add(pcontext_t *ctx) {
  pn_proactor_t *p = ctx->proactor;
  lock(&p->context.mutex);
  if (p->contexts) {
    p->contexts->prev = ctx;
    ctx->next = p->contexts;
  }
  p->contexts = ctx;
  ctx->ZZZxid = ++ZZZctxc;
  if (dbgz) fprintf(stderr, "A %d %d\n", ctx->ZZZxid, ctx->type);
  unlock(&p->context.mutex);
}

// call with psocket's mutex held
// return true if safe for caller to free psocket
static bool proactor_remove(pcontext_t *ctx) {
  pn_proactor_t *p = ctx->proactor;
  // Disassociate this context from scheduler
  if (!p->shutting_down) {
    lock(&p->sched_mutex);
    ctx->runner->state = DELETING;
    int count = p->thread_count;
    for (int i = 0; i < count; i++) {
      tslot_t *ts = &p->tslots[i];
      if (ts->prev_context == ctx)
        ts->prev_context = NULL;
    }
    unlock(&p->sched_mutex);
  }

  lock(&p->context.mutex);
  bool can_free = true;
  if (ctx->disconnecting) {
    // No longer on contexts list
    --p->disconnects_pending;
    if (--ctx->disconnect_ops != 0) {
      // procator_disconnect() does the free
      can_free = false;
    }
  }
  else {
    // normal case
    if (ctx->prev)
      ctx->prev->next = ctx->next;
    else {
      p->contexts = ctx->next;
      ctx->next = NULL;
      if (p->contexts)
        p->contexts->prev = NULL;
    }
    if (ctx->next) {
      ctx->next->prev = ctx->prev;
    }
  }
  bool notify = wake_if_inactive(p);
  unlock(&p->context.mutex);
  if (notify) wake_notify(&p->context);
  if (dbgz) fprintf(stderr, "proactor remove %d %d\n", notify, can_free);
  return can_free;
}

static tslot_t *find_tslot(pn_proactor_t *p) {
  pthread_t tid = pthread_self();
  int count = p->thread_count;
  for (int i = 0; i < count; i++ )
    if (p->tmaps[i].id == tid) return p->tmaps[i].tslot;
  if (count == TSMAX) {
    if (dbgz) fprintf(stderr, "ZZZ fixme, too many threads to handle %d\n", count + 1);
    abort();
  }
  tslot_t *ts = &p->tslots[count];
  p->tmaps[count].id = tid;
  p->tmaps[count].tslot = ts;
  p->thread_count = count + 1;
  ts->state = NEW;
  ts->tid = tid;
  return ts;
}

// Call with shed_lock held
// Caller must resume() return value if not null
static tslot_t *resume_one_thread(pn_proactor_t *p) {
  // If pn_proactor_get has an early return, we need to resume one suspended thread (if any)
  // to be the new poller.

  tslot_t *ts = p->suspend_list_head;
  if (ts) {
    LL_REMOVE(p, suspend_list, ts);
    p->suspend_list_count--;
    ts->state = PROCESSING;
  }
  return ts;
}

// Call with sched lock.
static pn_event_batch_t *process(pcontext_t *ctx) {
  bool ctx_wake = false;
  ctx->sched_pending = false;
  if (ctx->sched_wake) {
    // update the wake status before releasing the sched_mutex
    ctx->sched_wake = false;
    ctx_wake = true;
  }

  if (ctx->type == PROACTOR) {
    pn_proactor_t *p = ctx->proactor;
    bool timeout = p->sched_timeout;
    if (timeout) p->sched_timeout = false;
    bool intr = p->sched_interrupt;
    if (intr) p->sched_interrupt = false;
    unlock(&p->sched_mutex);
    return proactor_process(p, timeout, intr, ctx_wake);
  }
  pconnection_t *pc = pcontext_pconnection(ctx);
  if (pc) {
    uint32_t events = pc->psocket.sched_io_events;
    if (events) pc->psocket.sched_io_events = 0;
    bool timeout = pc->sched_timeout;
    if (timeout) pc->sched_timeout = false;
    unlock(&ctx->proactor->sched_mutex);
    return pconnection_process(pc, events, timeout, ctx_wake, false);
  }
  pn_listener_t *l = pcontext_listener(ctx);
  int n_events = 0;
  for (size_t i = 0; i < l->acceptors_size; i++) {
    psocket_t *ps = &l->acceptors[i].psocket;
    if (ps->sched_io_events) {
      ps->working_io_events = ps->sched_io_events;
      ps->sched_io_events = 0;
    }
    if (ps->working_io_events)
      n_events++;
  }
  unlock(&ctx->proactor->sched_mutex);
  return listener_process(l, n_events, ctx_wake);
}


// Call with both sched and wake locks
static void schedule_wake_list(pn_proactor_t *p) {
  // append wake_list_first..wake_list_last to end of sched_wake_last
  if (p->wake_list_first) {
    if (p->sched_wake_last)
      p->sched_wake_last->wake_next = p->wake_list_first;  // join them
    if (!p->sched_wake_first)
      p->sched_wake_first = p->wake_list_first;
    p->sched_wake_last = p->wake_list_last;
    if (!p->sched_wake_current)
      p->sched_wake_current = p->sched_wake_first;
    p->wake_list_first = p->wake_list_last = NULL;
  }
}

// Call with schedule lock held.  Called only by poller thread.
static pcontext_t *post_event(pn_proactor_t *p, struct epoll_event *evp) {
  epoll_extended_t *ee = (epoll_extended_t *) evp->data.ptr;
  pcontext_t *ctx = NULL;

  if (ee->type == WAKE) {
    if  (ee->fd == p->interruptfd) {        /* Interrupts have their own dedicated eventfd */
      p->sched_interrupt = true;
      ctx = &p->context;
      ctx->sched_pending = true;
    } else {
      // main eventfd wake
      lock(&p->eventfd_mutex);
      pcontext_t * ZZZpre = p->sched_wake_first;
      schedule_wake_list(p);
      ctx = p->sched_wake_current;
      if (dbgz) ZZZwk(p);
      unlock(&p->eventfd_mutex);
      if (dbgz && ZZZpre) fprintf(stderr, "  saw BAD %p wake first\n", (void *) ZZZpre);
    }
  } else if (ee->type == PROACTOR_TIMER) {
    p->sched_timeout = true;
    ctx = &p->context;
    ctx->sched_pending = true;
  } else {
    pconnection_t *pc = psocket_pconnection(ee->psocket);
    if (pc) {
      ctx = &pc->context;
      if (ee->type == PCONNECTION_IO) {
        ee->psocket->sched_io_events = evp->events;
        pcontext_t *fooc = &pc->context;  // ZZZ
        if (dbgz) fprintf(stderr, " pc_post %d  %p  t%d %d \n", evp->events, (void *) fooc, ZZZts(fooc->proactor, fooc->runner), fooc->runnable);
      } else {
        pc->sched_timeout = true;;
      }
      ctx->sched_pending = true;
    }
    else {
      pn_listener_t *l = psocket_listener(ee->psocket);
      assert(l);
      ctx = &l->context;
        if (dbgz) fprintf(stderr, "  l_post %d  %p  t%d %d \n", evp->events, (void *) ctx, ZZZts(ctx->proactor, ctx->runner), ctx->runnable);
      ee->psocket->sched_io_events = evp->events;
      ctx->sched_pending = true;
    }
  }
  if (ctx && !ctx->runnable && !ctx->runner)
    return ctx;
  return NULL;
}


static pcontext_t *post_wake(pn_proactor_t *p, pcontext_t *ctx) {
  ctx->sched_wake = true;
  ctx->sched_pending = true;
  if (dbgz) fprintf(stderr, "  postwk %p  %d  t%d\n", (void *) ctx, ctx->runnable, ZZZts(p, ctx->runner));
  if (!ctx->runnable && !ctx->runner)
    return ctx;
  return NULL;
}

// call with sched_lock held
static pcontext_t *next_drain(pn_proactor_t *p, tslot_t *ts) {
  // There should be very few of these, hopefully as few as one per thread removal on shutdown.

  int count = p->thread_count;
  for (int i = 0; i < count; i++ ) {
    tslot_t *ts2 = &p->tslots[i];
    if (ts2->earmarked) {
      // undo the old assign thread and earmark.  ts2 may never come back
      pcontext_t *switch_ctx = ts2->context;
      remove_earmark(ts2);
      assign_thread(ts, switch_ctx);
      if (dbgz) fprintf(stderr, " nxt drn2 t%d is  %p %p  %d %d\n", ZZZts(p,ts), (void *) ts->context, (void *) ts->prev_context, ts->state, ts->earmarked);
      pconnection_t *pc = dbgy(switch_ctx); if (pc) pc->zzbaddrn++;
      ts->earmark_override = ts2;
      ts->earmark_override_gen = ts2->generation;
      return switch_ctx;
    }
  }
  assert(false);
  return NULL;
}

// call with sched_lock held
static pcontext_t *next_runnable(pn_proactor_t *p, tslot_t *ts) {
  if (ts->context) {
    // Already assigned
    if (ts->earmarked) {
      ts->earmarked = false;
      if (--p->earmark_count == 0)
        p->earmark_drain = false;
    }
    return ts->context;
  }

  // warm pairing ?
  pcontext_t *ctx = ts->prev_context;
  if (ctx && (ctx->runnable)) { // or ctx->sched_wake too?
    assign_thread(ts, ctx);
    pconnection_t *pc = dbgy(ctx); if (pc) pc->zzrandom_win++;
    return ctx;
  }

  if (p->earmark_drain) {
    ctx = next_drain(p, ts);
    if (p->earmark_count == 0)
      p->earmark_drain = false;
    return ctx;
  }

  // check for an unassigned runnable context or unprocessed wake
  if (p->n_runnables) {
    // Any unclaimed runnable?
    while (p->n_runnables) {
      ctx = p->runnables[p->next_runnable++];
      if (p->n_runnables == p->next_runnable)
        p->n_runnables = 0;
      if (ctx->runnable) {
        assign_thread(ts, ctx);
        pconnection_t *pc = dbgy(ctx); if (pc) pc->zzfallbk++;
        return ctx;
      }
    }
  }

  if (p->sched_wake_current) {
    ctx = p->sched_wake_current;
    pop_wake(ctx, 6);  // updates sched_wake_current
    assert(!ctx->runnable && !ctx->runner);
    assign_thread(ts, ctx);
    pconnection_t *pc = dbgy(ctx); if (pc) pc->zzlatewk++;
    return ctx;
  }

  return NULL;
}

static pn_event_batch_t *proactor_do_epoll(pn_proactor_t* p, bool can_block) {
  lock(&p->tslot_mutex);
  tslot_t * ts = find_tslot(p);
  unlock(&p->tslot_mutex);
  ts->ZZZnepw++;
  ts->generation++;  // wrapping OK.  Just looking for any change
  pn_event_batch_t *batch = NULL;

  // TODO: try preassigned context using ts->mutex as memory barrier, and skip sched_mutex on entry

  if (ZZZrrr) ts->ZZZsched_s = hrtick();
  lock(&p->sched_mutex);
  assert(ts->context == NULL || ts->earmarked);
  assert(ts->state == UNUSED || ts->state == NEW);
  ts->state = PROCESSING;

  while (true) {
    uint64_t ZZZnow = ZZZdbgy ? hrtick() : 0;
    // Process outstanding epoll events until we get a batch or need to block.

    pcontext_t *ctx = next_runnable(p, ts);
    if (dbgz) fprintf(stderr, "__next t%d  %p  t%d   %d\n", ZZZts(p, ts), (void *) ctx, ZZZts(p, p->poller), ctx ? ctx->sched_wake : -1);
    if (ctx) {
      if (ZZZrrr && ZZZnow) ctx->ZZZr_start = ZZZnow;
      if (ts->ZZZsched_s && ZZZnow) {
        ts->ZZZsched_ticks += (ZZZnow - ts->ZZZsched_s);
        ts->ZZZsched_s = 0;
        ts->ZZZtrs = ZZZnow;
      }
      ts->state = BATCHING;
      batch = process(ctx);  // unlocks sched_lock before returning
      if (batch) {
        ts->ZZZbatches++;
        return batch;
      }
      lock(&p->sched_mutex);
      if (ZZZnow) ZZZnow = hrtick();
      if (ts->state != DELETING) {
        if (ctx->ZZZr_start) {
          ctx->ZZZr_ticks += (ZZZnow - ctx->ZZZr_start);
          ctx->ZZZr_start = 0;
        }
      }
      if (ts->ZZZtrs && ZZZnow) {
        ts->ZZZtrticks += (ZZZnow - ts->ZZZtrs);
        ts->ZZZtrs = 0;
        ts->ZZZsched_s = ZZZnow;
      }
      bool notify = unassign_thread_lh(ts, PROCESSING);
      if (notify) {
        unlock(&p->sched_mutex);
        wake_notify(&p->context);
        lock(&p->sched_mutex);
      }
      continue;  // Long time may have passed.  Back to beginning.
    }

    // poll or wait for a runnable context
    if (p->poller == NULL) {
      if (dbgz) fprintf(stderr, "__newpoller        t%d\n", ZZZts(p, ts));
      p->poller = ts;
      ts->ZZZnp++;
      assert(p->n_runnables == 0);
      p->next_runnable = 0;
      p->n_warm_runnables = 0;
      p->last_earmark = NULL;

      bool unfinished_earmarks = p->earmark_count > 0;
      bool new_wakes = false;
      bool epoll_immediate = unfinished_earmarks || !can_block;
      assert(!p->sched_wake_first);
      if (!epoll_immediate) {
        lock(&p->eventfd_mutex);
        if (p->wake_list_first) {
          epoll_immediate = true;
          new_wakes = true;
        } else {
          p->wakes_in_progress = false;
        }
        unlock(&p->eventfd_mutex);
      }
      int timeout = (epoll_immediate) ? 0 : -1;
      p->poller_suspended = (timeout == -1);
      unlock(&p->sched_mutex);
      if (ZZZdbgy) { p->zz_polls++; if (timeout == 0) p->zz_t0polls++; }
      memset(p->kevents, 0, sizeof(struct epoll_event) * p->kevents_length);


      if (ts->ZZZsched_s) {
        uint64_t ZZZnow = hrtick();
        ts->ZZZsched_ticks += (ZZZnow - ts->ZZZsched_s);
        ts->ZZZsched_s = 0;
        ts->ZZZp_s = ZZZnow;
      }

      int n = epoll_wait(p->epollfd, p->kevents, p->kevents_length, timeout);

      if (ts->ZZZp_s) {
        uint64_t ZZZnow = hrtick();
        ts->ZZZp_ticks += (ZZZnow - ts->ZZZp_s);
        ts->ZZZp_s = 0;
        ts->ZZZsched_s = ZZZnow;
        if (ZZZi_start) {
          ZZZi_ticks += (ZZZnow - ZZZi_start);
          ZZZi_start = 0;
        }
      }

      if (n < 0) perror("epoll ZZZ");
      ts->zz_polls++;
      if (epoll_immediate) ts->zz_ipolls++;
      lock(&p->sched_mutex);
      p->poller_suspended = false;

      bool unpolled_work = false;
      if (p->earmark_count > 0) {
        p->earmark_drain = true;
        if (dbgz) fprintf(stderr, "__startdrain t%d %d\n", ZZZts(p, ts), p->earmark_count);
        unpolled_work = true;
      }
      if (new_wakes) {
        lock(&p->eventfd_mutex);
        schedule_wake_list(p);
        unlock(&p->eventfd_mutex);
        unpolled_work = true;
      }

      if (dbgz) fprintf(stderr, "__waited t%d   %d    upw %d drn %d   cur  %p  %d t\n", ZZZts(p, ts), n, unpolled_work, p->earmark_drain, (void *) p->sched_wake_current, timeout);

      if (n < 0) {
        if (errno != EINTR)
          perror("epoll_wait"); // TODO: proper log
        if (!can_block && !unpolled_work) {
          p->poller = NULL;
          tslot_t *res_ts = resume_one_thread(p);
          ts->state = UNUSED;
          unlock(&p->sched_mutex);
          if (res_ts) resume(p, res_ts);
          return NULL;
        }
        else {
          p->poller = NULL;
          continue;
        }
      } else if (n == 0) {
        if (!can_block && !unpolled_work) {
          p->poller = NULL;
          tslot_t *res_ts = resume_one_thread(p);
          ts->state = UNUSED;
          unlock(&p->sched_mutex);
          if (res_ts) resume(p, res_ts);
          return NULL;
        }
        else {
          if (!epoll_immediate)
            perror("epoll_wait unexpected timeout"); // TODO: proper log
          if (!unpolled_work) {
            p->poller = NULL;
            continue;
          }
        }
      }

      for (int i = 0; i < n; i++) {
        ctx = post_event(p, &p->kevents[i]);
        if (ctx)
          make_runnable(ctx);
      }
      if (n > 0)
        memset(p->kevents, 0, sizeof(struct epoll_event) * n);

      // The list of pending wakes can be very long.  Traverse part of it looking for warm pairings.
      pcontext_t *wctx = p->sched_wake_current;
      if (dbgz) {
        lock(&p->eventfd_mutex);
        ZZZwk(p);
        unlock(&p->eventfd_mutex);
      }
      while (wctx && p->n_runnables < TSMAX) {
        p->ZZZx99 = true;
        if (wctx->runner == REWAKE_PLACEHOLDER)
          wctx->runner = NULL;  // Allow context to run again.
        ctx = post_wake(p, wctx);
        if (ctx)
          make_runnable(ctx);
        pop_wake(wctx, 7);
        wctx = wctx->wake_next;
      }
      p->sched_wake_current = wctx;
      // More wakes than places on the runnables list
      while (wctx) {
        if (wctx->runner == REWAKE_PLACEHOLDER)
          wctx->runner = NULL;  // Allow context to run again.
        wctx->sched_wake = true;
        wctx->sched_pending = true;
        if (wctx->runnable || wctx->runner)
          pop_wake(wctx, 11);
        wctx = wctx->wake_next;
      }

      if (ZZZep_immediate && !ts->context) {
        // Poller gets to run if possible
        pcontext_t *pctx;
        if (p->n_runnables) {
          assert(p->next_runnable == 0);
          pctx = p->runnables[0];
          if (++p->next_runnable == p->n_runnables)
            p->n_runnables = 0;
        } else if (p->n_warm_runnables) {
          pctx = p->warm_runnables[--p->n_warm_runnables];
          tslot_t *ts2 = pctx->runner;
          ts2->prev_context = ts2->context = NULL;
          pctx->runner = NULL;
          pconnection_t *pc = dbgy(pctx); if (pc) pc->zzwarm--;
        } else if (p->last_earmark) {
          pctx = p->last_earmark->context;
          remove_earmark(p->last_earmark);
          if (p->earmark_count == 0)
            p->earmark_drain = false;
        } else {
          pctx = NULL;
        }
        if (pctx) {
          assign_thread(ts, pctx);
          p->ZZZpoller_immediate++;
        }
      }
      if (!ts->context) p->ZZZpoller_unassigned++;

      // Create a list of available threads to put to work.
      int resume_list_count = 0;
      for (int i = 0; i < p->n_warm_runnables ; i++) {
        ctx = p->warm_runnables[i];
        tslot_t *tsp = ctx->runner;
        if (tsp->state == SUSPENDED) {
          p->resume_list[resume_list_count++] = tsp;
          LL_REMOVE(p, suspend_list, tsp);
          p->suspend_list_count--;
          tsp->state = PROCESSING;
        }
      }

      int can_use = p->suspend_list_count;
      if (!ts->context)
        can_use++;
      // run as many unpaired runnable contexts as possible and allow for a new poller
      int new_runners = pn_min(p->n_runnables + 1, can_use);
      if (!ts->context)
        new_runners--;  // poller available and does not need resume

      if (ZZZtsched_bump) {
        new_runners += ZZZtsched_bump;
        if (new_runners > p->suspend_list_count)
          new_runners = p->suspend_list_count;
      }

      for (int i = 0; i < new_runners; i++) {
        tslot_t *tsp = p->suspend_list_head;
        assert(tsp);
        p->resume_list[resume_list_count++] = tsp;
        LL_REMOVE(p, suspend_list, tsp);
        p->suspend_list_count--;
        tsp->state = PROCESSING;
      }

      if (resume_list_count) {
        unlock(&p->sched_mutex);
        for (int i = 0; i < resume_list_count; i++) {
          resume(p, p->resume_list[i]);
        }
        lock(&p->sched_mutex);
      }
      p->poller = NULL;
    } else if (!can_block) {
      ts->state = UNUSED;
      unlock(&p->sched_mutex);
      return NULL;
    } else {
      // todo: loop while !poller_suspended, since new work coming
      suspend(p, ts);
    }
  } // while
}

pn_event_batch_t *pn_proactor_wait(struct pn_proactor_t* p) {
//ZZZ restore non debug code...   return proactor_do_epoll(p, true);
  pn_event_batch_t *b  = proactor_do_epoll(p, true);
  if (dbgz) fprintf(stderr, "zepw %p\n", (void *) b);
  return b;
}

pn_event_batch_t *pn_proactor_get(struct pn_proactor_t* p) {
  return proactor_do_epoll(p, false);
}

// Call with no locks
static inline void check_earmark_override(pn_proactor_t *p, tslot_t *ts) {
  if (!ts->earmark_override)
    return;
  if (ts->earmark_override->generation == ts->earmark_override_gen) {
    // Other (overridden) thread not seen since this thread started and finished the event batch.
    // Thread is perhaps gone forever, which may leave us short of a poller thread
    lock(&p->sched_mutex);
    tslot_t *res_ts = resume_one_thread(p);
    p->ZZZlost_threads++;
    unlock(&p->sched_mutex);
    if (res_ts) resume(p, res_ts);
  }
  ts->earmark_override = NULL;
}

void pn_proactor_done(pn_proactor_t *p, pn_event_batch_t *batch) {
  pconnection_t *pc = batch_pconnection(batch);
  if (pc) {
    tslot_t *ts = pc->context.runner; // ZZZ
    pc->context.runner->zz_dones++;

    pconnection_done(pc);
    // pc possibly freed/invalid

    uint64_t ZZZnow = hrtick();
    if (ts->ZZZtrs) {
      ts->ZZZtrticks += (ZZZnow - ts->ZZZtrs);
      ts->ZZZtrs = 0;
      ts->ZZZsched_s = ZZZnow;
    }
    check_earmark_override(p, ts);
    return;
  }
  pn_listener_t *l = batch_listener(batch);
  if (l) {
    tslot_t *ts = l->context.runner; // ZZZ
    l->context.runner->zz_dones++;

    listener_done(l);
    // l possibly freed/invalid

    uint64_t ZZZnow = hrtick();
    if (ts->ZZZtrs) {
      ts->ZZZtrticks += (ZZZnow - ts->ZZZtrs);
      ts->ZZZtrs = 0;
      ts->ZZZsched_s = ZZZnow;
    }
    check_earmark_override(p, ts);
    return;
  }
  pn_proactor_t *bp = batch_proactor(batch);
  if (bp == p) {
    p->context.runner->zz_dones++;
    bool notify = false;
    bool rearm_interrupt = false;
    lock(&p->context.mutex);
    lock(&p->sched_mutex);

    // ZZZ from process() type == PROACTOR just sched_mutex
    bool timeout = p->sched_timeout;
    if (timeout) p->sched_timeout = false;
    bool intr = p->sched_interrupt;
    if (intr) {
      p->sched_interrupt = false;
      rearm_interrupt = true;
    }
    if (p->context.sched_wake) {
      p->context.sched_wake = false;
      wake_done(&p->context);
    }

    // ZZZ from proactor_process just context.mutex
    if (intr) {
      p->need_interrupt = true;
    }
    // ZZZ ptimer_callback is slow.  revisit timer cancel code in light of single poller change.
    bool timer_fired = timeout && ptimer_callback(&p->timer) != 0;
    if (timeout) {
      p->timer_armed = false;
      if (timer_fired && p->timeout_set) {
        p->need_timeout = true;
      }
    }


    bool rearm_timer = !p->timer_armed && !p->shutting_down;
    p->timer_armed = true;
    p->context.working = false;
    if (p->timeout_processed) {
      p->timeout_processed = false;
      if (wake_if_inactive(p))
        notify = true;
    }
    proactor_update_batch(p);
    if (proactor_has_event(p))
      if (wake(&p->context))
        notify = true;
    tslot_t *ts = p->context.runner;
    if (unassign_thread_lh(ts, UNUSED))
      notify = true;
    unlock(&p->sched_mutex);
    unlock(&p->context.mutex);
    if (notify)
      wake_notify(&p->context);
    if (rearm_timer)
      rearm(p, &p->timer.epoll_io);
    if (rearm_interrupt) {
      (void)read_uint64(p->interruptfd);
      rearm(p, &p->epoll_interrupt);
    }
    if (dbgz) fprintf(stderr, "zepd proactor %p  %p t%d\n", (void *) batch, (void *) &p->context, ZZZts(p, p->context.prev_runner));

    uint64_t ZZZnow = hrtick();
    if (ts->ZZZtrs) {
      ts->ZZZtrticks += (ZZZnow - ts->ZZZtrs);
      ts->ZZZtrs = 0;
      ts->ZZZsched_s = ZZZnow;
    }
    check_earmark_override(p, ts);
    return;
  }
}

void pn_proactor_interrupt(pn_proactor_t *p) {
  if (p->interruptfd == -1)
    return;
  uint64_t increment = 1;
  if (write(p->interruptfd, &increment, sizeof(uint64_t)) != sizeof(uint64_t))
    EPOLL_FATAL("setting eventfd", errno);
}

void pn_proactor_set_timeout(pn_proactor_t *p, pn_millis_t t) {
  bool notify = false;
  lock(&p->context.mutex);
  p->timeout_set = true;
  if (t == 0) {
    ptimer_set(&p->timer, 0);
    p->need_timeout = true;
    notify = wake(&p->context);
  } else {
    ptimer_set(&p->timer, t);
  }
  unlock(&p->context.mutex);
  if (notify) wake_notify(&p->context);
}

void pn_proactor_cancel_timeout(pn_proactor_t *p) {
  lock(&p->context.mutex);
  p->timeout_set = false;
  p->need_timeout = false;
  ptimer_set(&p->timer, 0);
  bool notify = wake_if_inactive(p);
  unlock(&p->context.mutex);
  if (notify) wake_notify(&p->context);
}

pn_proactor_t *pn_connection_proactor(pn_connection_t* c) {
  pconnection_t *pc = get_pconnection(c);
  return pc ? pc->psocket.proactor : NULL;
}

void pn_proactor_disconnect(pn_proactor_t *p, pn_condition_t *cond) {
  bool notify = false;

  lock(&p->context.mutex);
  // Move the whole contexts list into a disconnecting state
  pcontext_t *disconnecting_pcontexts = p->contexts;
  p->contexts = NULL;
  // First pass: mark each pcontext as disconnecting and update global pending count.
  pcontext_t *ctx = disconnecting_pcontexts;
  while (ctx) {
    ctx->disconnecting = true;
    ctx->disconnect_ops = 2;   // Second pass below and proactor_remove(), in any order.
    p->disconnects_pending++;
    ctx = ctx->next;
  }
  notify = wake_if_inactive(p);
  unlock(&p->context.mutex);
  if (!disconnecting_pcontexts) {
    if (notify) wake_notify(&p->context);
    return;
  }

  // Second pass: different locking, close the pcontexts, free them if !disconnect_ops
  pcontext_t *next = disconnecting_pcontexts;
  while (next) {
    ctx = next;
    next = ctx->next;           /* Save next pointer in case we free ctx */
    bool do_free = false;
    bool ctx_notify = false;
    pmutex *ctx_mutex = NULL;
    pconnection_t *pc = pcontext_pconnection(ctx);
    if (pc) {
      ctx_mutex = &pc->context.mutex;
      lock(ctx_mutex);
      if (!ctx->closing) {
        ctx_notify = true;
        if (ctx->working) {
          // Must defer
          pc->queued_disconnect = true;
          if (cond) {
            if (!pc->disconnect_condition)
              pc->disconnect_condition = pn_condition();
            pn_condition_copy(pc->disconnect_condition, cond);
          }
        }
        else {
          // No conflicting working context.
          if (cond) {
            pn_condition_copy(pn_transport_condition(pc->driver.transport), cond);
          }
          pn_connection_driver_close(&pc->driver);
        }
      }
    } else {
      pn_listener_t *l = pcontext_listener(ctx);
      assert(l);
      ctx_mutex = &l->context.mutex;
      lock(ctx_mutex);
      if (!ctx->closing) {
        ctx_notify = true;
        if (cond) {
          pn_condition_copy(pn_listener_condition(l), cond);
        }
        listener_begin_close(l);
      }
    }

    lock(&p->context.mutex);
    if (--ctx->disconnect_ops == 0) {
      do_free = true;
      ctx_notify = false;
      notify = wake_if_inactive(p);
    } else {
      // If initiating the close, wake the pcontext to do the free.
      if (ctx_notify)
        ctx_notify = wake(ctx);
      if (ctx_notify)
        wake_notify(ctx);
    }
    unlock(&p->context.mutex);
    unlock(ctx_mutex);

    // Unsafe to touch ctx after lock release, except if we are the designated final_free
    if (do_free) {
      if (pc) pconnection_final_free(pc);
      else listener_final_free(pcontext_listener(ctx));
    }
  }
  if (notify)
    wake_notify(&p->context);
}

const pn_netaddr_t *pn_transport_local_addr(pn_transport_t *t) {
  pconnection_t *pc = get_pconnection(pn_transport_connection(t));
  return pc? &pc->local : NULL;
}

const pn_netaddr_t *pn_transport_remote_addr(pn_transport_t *t) {
  pconnection_t *pc = get_pconnection(pn_transport_connection(t));
  return pc ? &pc->remote : NULL;
}

const pn_netaddr_t *pn_listener_addr(pn_listener_t *l) {
  return l->acceptors_size > 0 ? &l->acceptors[0].addr : NULL;
}

pn_millis_t pn_proactor_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec*1000 + t.tv_nsec/1000000;
}
