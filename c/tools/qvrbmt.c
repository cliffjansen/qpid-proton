/*
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
 */

/*
 * Quiver "broker" multi-threaded.  Assumes default quiver run.  Same
 * sized messages per link, max credit up front, one link per
 * connection.
 */


#include <proton/connection_driver.h>
#include <proton/proactor.h>
#include <proton/engine.h>
#include <proton/sasl.h>
#include <proton/transport.h>
#include <proton/url.h>
#include <proton/object.h>
#include <proton/listener.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifdef WIN32
#include <windows.h>
#include <process.h>
typedef CRITICAL_SECTION pneg_mutex_t;
static void pneg_mutex_init(pneg_mutex_t *m) { InitializeCriticalSectionAndSpinCount(m, 4000); }
static void pneg_mutex_destroy(pneg_mutex_t *m) { DeleteCriticalSection(m); }
static inline void pneg_mutex_lock(pneg_mutex_t *m) { EnterCriticalSection(m); }
static inline void pneg_mutex_unlock(pneg_mutex_t *m) { LeaveCriticalSection(m); }

typedef struct {
  HANDLE handle;
  void (*func)(void *);
  void *arg;
} pneg_thread_t;

unsigned __stdcall pneg_run(void *thr0) {
  pneg_thread_t *t = (pneg_thread_t *) thr0;
  t->func(t->arg);
  return 0;
}

static int pneg_thread_create(pneg_thread_t *t, void (*f)(void *), void *arg) {
  fprintf(stderr,"ZZZthread create\n");fflush(stderr);
  t->handle = 0;
  t->func = f;
  t->arg = arg;
  HANDLE th = (HANDLE) _beginthreadex(0, 0, &pneg_run, t, 0, 0);
  if (th) {
    t->handle = th;
    return 0;
  }
  return -1;    
}
static int pneg_thread_join(pneg_thread_t *t) {
  if (t->handle) {
    WaitForSingleObject(t->handle, INFINITE);
    CloseHandle(t->handle);
  }
  return 0;
}

#else
#include <pthread.h>
#include <unistd.h>
typedef pthread_t pneg_thread_t;
static int pneg_thread_create(pneg_thread_t *t, void * (*f)(void *), void *arg) {
  return pthread_create(t, NULL, f, arg);
}

static int pneg_thread_join(pneg_thread_t *t) {
  return pthread_join(*t, (void **) NULL);
}

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

// need portable/conditional compile version of this for other platforms
uint64_t hrtick(void) {
  uint32_t lo, hi;
  __asm__ volatile ("rdtscp"
      : /* outputs */ "=a" (lo), "=d" (hi)
      : /* no inputs */
      : /* clobbers */ "%rcx");
  return (uint64_t)lo | (((uint64_t)hi) << 32);
}


#endif

pmutex global_mutex;

bool sasl_anon = false;

bool enable_debug = false;

void debug(const char* fmt, ...) {
  if (enable_debug) {
    lock(&global_mutex);
    fflush(stdout);
    va_list(ap);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    unlock(&global_mutex);
  }
}

void check(int err, const char* s) {
  if (err != 0) {
    perror(s);
    exit(1);
  }
}

void pcheck(int err, const char* s) {
  if (err != 0) {
    fprintf(stderr, "%s: %s", s, pn_code(err));
    exit(1);
  }
}

void check_true(bool is_true, const char *msg) {
  if (!is_true) {
    fprintf(stderr, "check_true fail: %s", msg);
    exit(1);
  }
}

/* Simple re-sizable vector that acts as a queue */
#define VEC(T) struct { T* data; size_t len, cap; }

#define VEC_INIT(V)                             \
  do {                                          \
    V.len = 0;                                  \
    V.cap = 16;                                 \
    void **vp = (void**)&V.data;                \
    *vp = malloc(V.cap * sizeof(*V.data));      \
  } while(0)

#define VEC_FINAL(V) free(V.data)

#define VEC_PUSH(V, X)                                  \
  do {                                                  \
    if (V.len == V.cap) {                               \
      V.cap *= 2;                                       \
      void **vp = (void**)&V.data;                      \
      *vp = realloc(V.data, V.cap * sizeof(*V.data));   \
    }                                                   \
    V.data[V.len++] = X;                                \
  } while(0)                                            \

#define VEC_POP(V)                                              \
  do {                                                          \
    if (V.len > 0)                                              \
      memmove(V.data, V.data+1, (--V.len)*sizeof(*V.data));     \
  } while(0)


static bool early_flow = false;
// next two vars thread safe only for single quiver ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
//static bool early_flow_set = false;
//static bool early_flow_wflush = false;

#define Q_NAME_LEN 80
PN_HANDLE(QVRQ_CTX)

typedef struct msg_t msg_t;
typedef struct connection_context_t connection_context_t;
/*
 * a msg_t goes from: free_list->inbound->outbound->"no list"->accepted->free_list
 */

struct qvrq {
  // static post link setup
  pn_link_t *inlink;
  pn_link_t *outlink;
  connection_context_t *incc;
  connection_context_t *outcc;
  int credit_window;
  char name[Q_NAME_LEN];
  struct qvrq* next;
  // ZZZ cache line padding?
  // owned by inbound connection
  msg_t *inbound_head;
  msg_t *inbound_tail;
  uint64_t zero_c_start;
  uint64_t zero_c_ticks;
  // owned by outbound connection
  msg_t *accepted_head;
  msg_t *accepted_tail;
  size_t sent_count;
  size_t accept_count;
  int last_credit;
  bool early_flow_set;
  // Other
  pmutex qlock;
  int conn_count;
  msg_t *msgs;
  int msg_count;
  int initial_credit;
  msg_t *free_list;
  int inbound_count;
  msg_t *outbound_head;
  msg_t *outbound_tail;
  msg_t *complete_head;
  msg_t *complete_tail;
  int outbound_count;
  bool early_flow_wflush;
};

typedef struct qvrq qvrq_t;

qvrq_t *qvrq_start = NULL;

PN_HANDLE(CONNECTION_CONTEXT)

typedef struct connection_context_t {
  qvrq_t *q;
  pn_connection_t *connection;
  int cswitch;
  bool inbound_c;
  bool closed;
  pmutex memory_barrier;
  uint64_t creation;
  uint64_t start;
  pmutex wake_lock;
  bool can_wake;
} connection_context_t;


void set_context(pn_link_t *l, void* value) {
  pn_record_t *record = pn_link_attachments(l);
  pn_record_def(record, QVRQ_CTX, PN_VOID);
  pn_record_set(record, QVRQ_CTX, value);
}

qvrq_t * get_context(pn_link_t *l) {
  return (qvrq_t *) pn_record_get(pn_link_attachments(l), QVRQ_CTX);
}

static qvrq_t *qvrq_find(const char *nm) {
  size_t len = strlen(nm);
  qvrq_t *qvrq = qvrq_start;
  qvrq_t *last = NULL;
  while (qvrq) {
    if (!strncmp(qvrq->name, nm, len)) {
      check_true((qvrq->inlink == NULL || qvrq->outlink == NULL), "more than one sender and one receiver to queue");
      return qvrq;
    }
    last = qvrq;
    qvrq = qvrq->next;
  }
  qvrq_t *neq = calloc(sizeof(qvrq_t), 1);
  strcpy(neq->name, nm);
  pmutex_init(&neq->qlock);
  if (qvrq_start == NULL)
    qvrq_start = neq;
  else
    last->next = neq;
  return neq;
}


static const char* qname(const char* n) {
  // point to last 5 chars
  size_t len = strlen(n);
  check_true(len <= (Q_NAME_LEN - 1), "nm len");
  return n;
}

void qvrq_add_link(pn_link_t *l, qvrq_t **pq) {
  if (pn_link_is_sender(l)) {
    qvrq_t *qvrq = qvrq_find(qname(pn_terminus_get_address(pn_link_remote_source(l))));
    check_true(qvrq->outlink == NULL, "addlink out not null");
    qvrq->outlink = l;
    set_context(l, qvrq);
    *pq = qvrq;
  } else {
    qvrq_t *qvrq = qvrq_find(qname(pn_terminus_get_address(pn_link_remote_target(l))));
    check_true(qvrq->inlink == NULL, "addlink in not null");
    qvrq->inlink = l;
    set_context(l, qvrq);
    *pq = qvrq;
  }
}

void qvrq_remove_link(pn_link_t *l) {
  qvrq_t *qvrq = get_context(l);
  if (qvrq) {
    if (qvrq->inlink == l) qvrq->inlink = NULL;
    else if (qvrq->outlink == l) qvrq->outlink = NULL;
  }
}

/* The broker implementation */
typedef struct broker_t {
  pn_proactor_t *proactor;
  const char *container_id;     /* AMQP container-id */
  size_t threads;
  size_t conns;
  size_t max_conns;
  pn_millis_t heartbeat;
  bool finished;
} broker_t;

void broker_init(broker_t *b, const char *container_id, size_t threads, pn_millis_t heartbeat, size_t n_conns) {
  memset(b, 0, sizeof(*b));
  b->proactor = pn_proactor();
  b->container_id = container_id;
  b->threads = threads;
  b->heartbeat = 0;
  b->max_conns = n_conns;
}

void broker_stop(broker_t *b) {
  /* In this broker an interrupt stops a thread, stopping all threads stops the broker */
  for (size_t i = 0; i < b->threads; ++i)
    pn_proactor_interrupt(b->proactor);
}

static void check_condition(pn_event_t *e, pn_condition_t *cond) {
  if (pn_condition_is_set(cond)) {
    const char *ename = e ? pn_event_type_name(pn_event_type(e)) : "UNKNOWN";
    fprintf(stderr, "%s: %s: %s\n", ename,
            pn_condition_get_name(cond), pn_condition_get_description(cond));
  }
}

typedef struct msg_t {
  size_t buf_capacity;
  size_t buf_size;
  char *buf;  // temp storage for encoded content (never decoded)
  qvrq_t *q;
  pn_delivery_t *in;
  pn_delivery_t *out; // just 1 for q
  struct msg_t *next;
} msg_t;

// always called from inbound connection..  no lock for this and next function
static msg_t *get_free_msg(qvrq_t *q) {
  check_true(q->free_list, "free list empty");
  msg_t *m = q->free_list;
  q->free_list = m->next;
  m->next = NULL;
  return m;
}

// always called from inbound connection, see get_free_msg above
static void free_list_add(msg_t *m) {
  qvrq_t *q = m->q;
  m->next = q->free_list;
  q->free_list = m;
  m->out = m->in = NULL;
}

static void qvrq_destroy(qvrq_t *q) {
  qvrq_t *qvrq = qvrq_start;
  qvrq_t *prev = NULL;
  while (qvrq) {
    if (qvrq == q) break;
    prev = qvrq;
    qvrq = qvrq->next;
  }
  check_true(qvrq == q, "queue destroy failure");
  if (prev)
    prev->next = q->next;
  else
    qvrq_start = q->next;
  for (int i = 0; i < q->msg_count; i++)
    free(q->msgs[i].buf);
  free(q->msgs);
  fprintf(stderr, "ZZZ destroyed q %s\n", q->name);
//  if (q->inlink) pn_link_free(q->inlink);  core dump.  need incref?
//  if (q->outlink) pn_link_free(q->outlink);
  pmutex_finalize(&q->qlock);
  free(q);
}


static void wake_other(connection_context_t *cc) {
  if (cc->q) {
    connection_context_t *cc2 = (cc->inbound_c) ? cc->q->outcc : cc->q->incc;
    check_true(cc != cc2, "ZZZ just checking... dump this");
    if (cc2) {
      lock(&cc2->wake_lock);
      if (cc2->can_wake)
        pn_connection_wake(cc2->connection);
      unlock(&cc2->wake_lock);
    }
  }
}

static connection_context_t *new_c_context() {
  connection_context_t *cc = (connection_context_t *) malloc(sizeof(connection_context_t));
  memset(cc, 0, sizeof(*cc));
  pmutex_init(&cc->memory_barrier);
  pmutex_init(&cc->wake_lock);
  cc->creation = hrtick();
  return cc;
}

static void cc_memory_barrier(connection_context_t *cc) {
  lock(&cc->memory_barrier);
  unlock(&cc->memory_barrier);
}


connection_context_t *get_c_context(pn_connection_t *c) {
  pn_record_t *record = pn_connection_attachments(c);
  connection_context_t *cc = (connection_context_t *) pn_record_get(record, CONNECTION_CONTEXT);
  return cc;
}

static connection_context_t *cc_from_link(pn_link_t *l) {
  pn_connection_t *c = pn_session_connection(pn_link_session(l));
  return get_c_context(c);
}

static void set_c_context(pn_connection_t *c, connection_context_t *cc) {
  pn_record_t *record = pn_connection_attachments(c);
  pn_record_def(record, CONNECTION_CONTEXT, PN_VOID);
  pn_record_set(record, CONNECTION_CONTEXT, cc);
}

static void cc_destroy(connection_context_t *cc) {
  set_c_context(cc->connection, NULL);
  pmutex_finalize(&cc->memory_barrier);
  pmutex_finalize(&cc->wake_lock);
  free(cc);
}


//const int WINDOW=10;            /* Incoming credit window */
int WINDOW_old=10;            /* Incoming credit window */

static void update_credit(connection_context_t *cc, int extra) {
  if (early_flow) {
    lock(&cc->q->qlock);
    if (cc->q->early_flow_set) {
      cc->q->early_flow_set = false;
      // pn_link_credit on other connection is thread safe (currently, not guaranteed) and useful with lock/memory barrier
      int delta = pn_link_credit(cc->q->outlink) - pn_link_remote_credit(cc->q->inlink);
      if (delta > 0) {
        cc->q->early_flow_wflush = true;
        pn_link_flow(cc->q->inlink, delta);
        if (cc->q->zero_c_start) {
          uint64_t now = hrtick();
          cc->q->zero_c_ticks += now - cc->q->zero_c_start;
          cc->q->zero_c_start = 0;
        }

      }
//      fprintf(stderr, "ZZZz AG credit foo  %d  %d %d %d\n", delta, pn_link_credit(cc->q->outlink), pn_link_credit(cc->q->inlink), pn_link_remote_credit(cc->q->inlink));
    }
    unlock(&cc->q->qlock);
    return;
  }
  if (extra > 0) {
    pn_link_flow(cc->q->inlink, extra);
    check_true(pn_link_credit(cc->q->inlink) <= cc->q->msg_count, "too much credit granted to sender");
    if (enable_debug) { debug("ZZZ credit foo  %d  %d", extra, pn_link_credit(cc->q->inlink)); }
//    fprintf(stderr, "ZZZz credit foo  %d  %d %d\n", extra, pn_link_credit(cc->q->inlink), pn_link_remote_credit(cc->q->inlink));
    if (cc->q->zero_c_start) {
      uint64_t now = hrtick();
      cc->q->zero_c_ticks += now - cc->q->zero_c_start;
      cc->q->zero_c_start = 0;
    }
  }

}

static void context_end(connection_context_t *cc) {
  if (enable_debug) { debug("ZZZ ctx END  c %p   cc %p", cc->connection, cc, cc->inbound_c); }
  cc->cswitch++;
  qvrq_t *q = cc->q;
  if (!q) return;

  if (cc->inbound_c) {
    // forward inbound messsages to other connection context, settle messages accepted by receiver
    msg_t *completed_list = NULL;
    int initial_credit = 0;
    bool wake_needed = false;  // for wake outside lock
    lock(&q->qlock);
    if (q->complete_head) {
      if (enable_debug) { debug("ZZZ w1  complete %p", q->outcc->connection); }
      wake_needed = true;
      completed_list = q->complete_head;
      q->complete_head = q->complete_tail = NULL;
    } else if (q->initial_credit) {
      initial_credit = q->initial_credit;
      q->initial_credit = 0;
    }
    if (q->inbound_head) {
      if (enable_debug) { debug("ZZZ w2  outbound %p", q->outcc->connection); }
      wake_needed = true;
      if (q->outbound_tail) {
        q->outbound_tail->next = q->inbound_head;
        q->outbound_tail = q->inbound_tail;
      } else {
        q->outbound_head = q->inbound_head;
        q->outbound_tail = q->inbound_tail;
      }
      q->inbound_head = q->inbound_tail = NULL;
    }
    unlock(&q->qlock);
    if (wake_needed)
      wake_other(cc);

    int extra_credit = 0;
    for (msg_t *m = completed_list; m; ) {
      pn_delivery_update(m->in, PN_ACCEPTED);
      pn_delivery_settle(m->in);
      extra_credit++;
      msg_t *oldm = m;
      m = m->next;
      free_list_add(oldm);
    }
    if (extra_credit) {
      update_credit(cc, extra_credit);
    } else if (initial_credit) {
      if (early_flow) { q->early_flow_set = true; q->last_credit = initial_credit; }
      update_credit(cc, initial_credit);
    }
  } else {
    // outbound connection.  First forward completions to other thread, then send outbound messages.
    msg_t *outbound_list = NULL;
    if (enable_debug) { debug("ZZZ outbound %p  ah  %p  ic %d  oh %p", cc->connection, q->accepted_head, q->initial_credit, q->outbound_head); }
    bool wake_needed = false;  // for wake outside lock
    int current_credit = pn_link_credit(q->outlink);
    if (early_flow && q->last_credit != current_credit) {
      wake_needed = true;
      q->last_credit = current_credit;
    }
    lock(&q->qlock);
    if (early_flow && wake_needed) { q->early_flow_set = true; }
    if (q->accepted_head) {
      wake_needed = true;
      if (enable_debug) { debug("ZZZ w3  accepted %p", q->incc->connection); }
      if (q->complete_tail) {
        q->complete_tail->next = q->accepted_head;
        q->complete_tail = q->accepted_tail;
      } else {
        q->complete_head = q->accepted_head;
        q->complete_tail = q->accepted_tail;
      }
      q->accepted_head = q->accepted_tail = NULL;
    } else if (q->initial_credit && q->inlink) {
      if (enable_debug) { debug("ZZZ w4  initial %p", q->incc->connection); }
      wake_needed = true;
    }
    if (q->outbound_head) {
      outbound_list = q->outbound_head;
      q->outbound_head = q->outbound_tail = NULL;
    }
    unlock(&q->qlock);
    if (wake_needed)
      wake_other(cc);

    for (msg_t *m = outbound_list; m; ) {
      size_t tag = ++q->sent_count;
      pn_delivery_t *d = pn_delivery(q->outlink, pn_dtag((char*)&tag, sizeof(tag)));
      pn_delivery_set_context(d, m);
      ssize_t ZZZi = pn_link_send(q->outlink, m->buf, m->buf_size);
      if (enable_debug) { debug("ZZZ send    %p %d", cc->connection, (int) ZZZi); }
      pn_link_advance(q->outlink);
      m->out = d;
      msg_t *oldm = m;
      m = m->next;
      oldm->next = NULL;
      oldm->buf_size = 0;
    }
    // Should never be out of credit unless receiver lowered it in an un-quiver way.
    if (!early_flow)
      check_true(!outbound_list || pn_link_credit(q->outlink) >= 0, "message credit mismatch");
  }

  if (cc->closed) {
    if (cc->q) {
      bool last_c = false;
      lock(&cc->q->qlock);
      cc->q->conn_count--;  //  cc and q may both be gone after lock released
      if (cc->q->conn_count == 0) last_c = true;
      unlock(&cc->q->qlock);
      if (last_c) {
        if (cc->q->sent_count) check_true(cc->q->sent_count == cc->q->accept_count, "shutdown accept mismatch");
        connection_context_t *incc = cc->q->incc;
        connection_context_t *outcc = cc->q->outcc;
        lock(&global_mutex);
        qvrq_destroy(cc->q);
        unlock(&global_mutex);
        cc_destroy(incc);
        cc_destroy(outcc);
      }
      return;
    } else {
      // not associated with a q
      cc_destroy(cc);
      return;
    }
  }
}

/* If *app_ctx is NULL, new batch/context may be set if desired.  If e
   is is NULL, the previous event was the last in the batch before
   context switch on this thread. Currently we only care about
   connection context boundaries.
*/

static void handle(broker_t* b, pn_event_t* e, void **app_ctx, bool *wflush) {
  pn_connection_t *c = NULL;

  if (e) {
    if (!*app_ctx) {
      c = pn_event_connection(e);
      if (c) {
        *app_ctx = c;
        connection_context_t *cc = get_c_context(c);
        if (cc) {
          cc_memory_barrier(cc);
          if (cc->inbound_c && cc->q && cc->q->inlink && !cc->q->zero_c_start) {
            // Set before processing events.  Under-represents true
            // start time by network xmit time and proton
            // parsing/copying initial frames
            if (pn_link_remote_credit(cc->q->inlink) <= 0)
              cc->q->zero_c_start = hrtick();
          }
          if (cc->inbound_c && cc->q && cc->q->inlink) {
            int ZZZq = pn_link_queued(cc->q->inlink);
//            fprintf(stderr, "ZZZz bstart %d %d\n", ZZZq, (cc->q->zero_c_start != 0));
            if (cc->q->outlink && early_flow) {
              update_credit(cc, 0);
              if (cc->q->early_flow_wflush) { *wflush = true; cc->q->early_flow_wflush = false; }
            }
          }
                    
        }
      }
    } else {
      c = (pn_connection_t *) *app_ctx;
    }
  } else {  // e == NULL
    c = (pn_connection_t *) *app_ctx;
    if (c) {
      connection_context_t *cc = get_c_context(c);
      if (cc) {
        context_end(cc);
        cc_memory_barrier(cc);
      }
    }
    return;
  }

  switch (pn_event_type(e)) {

   case PN_LISTENER_ACCEPT:
       pn_listener_accept(pn_event_listener(e), pn_connection());
       b->conns++;
     break;

   case PN_CONNECTION_INIT: 
     c = pn_event_connection(e);
     set_c_context(c, new_c_context());
     connection_context_t *cc = get_c_context(c);
     cc->connection = c;
     lock(&cc->wake_lock);
     cc->can_wake = true;
     unlock(&cc->wake_lock);
     pn_connection_set_container(c, b->container_id);
     break;

   case PN_CONNECTION_FINAL: {
     free(cc);
     if (b->conns >= b->max_conns)
       pn_listener_close(pn_event_listener(e));
     fprintf(stderr, "on final %d %d\n", b->conns, b->max_conns);
     break;
   }
   case PN_CONNECTION_BOUND: {
     /* Turn off security */
     pn_transport_t *t = pn_connection_transport(c);
     pn_transport_require_auth(t, sasl_anon);
     pn_sasl_allowed_mechs(pn_sasl(t), "ANONYMOUS");
//ZZZ     fflush(stdout);fprintf(stderr, "ZZZsasl %d anon\n", (int) sasl_anon);fflush(stderr);
     pn_transport_set_idle_timeout(t, 2 * b->heartbeat);
   }
   case PN_CONNECTION_REMOTE_OPEN: {
     pn_connection_open(pn_event_connection(e)); /* Complete the open */
     break;
   }
   case PN_CONNECTION_WAKE: {
     connection_context_t *cc = get_c_context(c);
     check_true(cc, "connection wake with no set context");
     if (enable_debug) { debug("ZZZ ***   wake   ***   %p", c); }
     if (early_flow && cc->inbound_c && cc->q->inlink && cc->q->outlink)
       update_credit(cc, 0);
     if (cc->inbound_c && cc->q->early_flow_wflush) { *wflush = true; cc->q->early_flow_wflush = false; }
     // ZZZ count ??
     break;
   }
   case PN_SESSION_REMOTE_OPEN: {
     pn_session_open(pn_event_session(e));
     break;
   }
   case PN_LINK_REMOTE_OPEN: {
     pn_link_t *l = pn_event_link(e);
     connection_context_t *cc = cc_from_link(l);
     check_true(cc->q == NULL, "2nd link opened on connection");
     lock(&global_mutex);
     qvrq_add_link(l, &cc->q);
     unlock(&global_mutex);
     if (pn_link_is_sender(l)) {
       const char *source = pn_terminus_get_address(pn_link_remote_source(l));
       pn_terminus_set_address(pn_link_source(l), source);
     } else {
       const char* target = pn_terminus_get_address(pn_link_remote_target(l));
       pn_terminus_set_address(pn_link_target(l), target);
       cc->inbound_c = true;
     }
     pn_link_open(l);
     if (cc->inbound_c) cc->q->incc = cc;
     else cc->q->outcc = cc;
     cc->q->conn_count++;
     if (cc->q->conn_count == 2)
       cc->q->incc->start = cc->q->outcc->start = hrtick();
     break;
   }
   case PN_LINK_FLOW: {
     connection_context_t *cc = get_c_context(c);
     if (!cc->inbound_c && cc->q->credit_window == 0) {
       int cw = pn_link_credit(cc->q->outlink);
       int nmsg = (early_flow) ? cw * 3 : cw;
       if (enable_debug) { debug("ZZZ ***   flow 1   ***   %d", cw); }
//       fprintf(stderr, "ZZZz using cw %d nmsg %d\n", cw, nmsg);
       msg_t *msgs = calloc(sizeof(msg_t), nmsg);
       check_true(msgs, "calloc failure");
       msg_t *prev = NULL;
       for (int i = 0; i < nmsg; i++) {
         msg_t *m = msgs + i;
         m->q = cc->q;
         if (prev) prev->next = m;
         prev = m;
       }
       lock(&cc->q->qlock);
       cc->q->credit_window = cw;
       cc->q->msgs = msgs;
       cc->q->msg_count = nmsg;
       cc->q->initial_credit = cw;
       cc->q->free_list = msgs;
       unlock(&cc->q->qlock);
       if (enable_debug) { debug("ZZZ ***   flow 2   ***   %d %d", cw, cc->q->initial_credit); }
     }
     else if (!cc->inbound_c && early_flow) {
       lock(&cc->q->qlock);
       cc->q->early_flow_set = true;
       cc->q->last_credit = pn_link_credit(cc->q->outlink);
       unlock(&cc->q->qlock);
       wake_other(cc);
     }
     break;
   }
   case PN_DELIVERY: {
     pn_delivery_t *d = pn_event_delivery(e);
     pn_link_t *r = pn_delivery_link(d);
     if (enable_debug) { debug("ZZZ DDD  %p %p     %d %d %d", r, cc, pn_link_is_receiver(r)
                               , pn_delivery_readable(d) ,pn_delivery_partial(d)); }
     qvrq_t *qvrq = get_context(r);
     if (!qvrq)
       break;
     connection_context_t *cc = cc_from_link(r);
     if (enable_debug) { debug("ZZZ DDD  %p %p     %d %d %d", r, cc, pn_link_is_receiver(r)
                               , pn_delivery_readable(d) ,pn_delivery_partial(d)); }
     if (pn_link_is_receiver(r) &&
         pn_delivery_readable(d) && !pn_delivery_partial(d))
     {
       msg_t *m = get_free_msg(qvrq);
       check_true(m, "less messages than credit");
       size_t size = pn_delivery_pending(d);
       if (m->buf == NULL) {
         m->buf_capacity = size + 10;
         m->buf = (char *) malloc(m->buf_capacity);
       }
       check_true(m->buf && size <= m->buf_capacity, "internal error on delivery");

       m->buf_size = size;
       ssize_t ZZZi = pn_link_recv(r, m->buf, m->buf_size);
       if (enable_debug) { debug("ZZZ recv    %p %p %d %d %d", cc->connection, m, (int)m->buf_capacity, (int) m->buf_size, (int) ZZZi); }
       m->in = d;
       qvrq->inbound_count++;
       if (qvrq->inbound_tail) {
         qvrq->inbound_tail->next = m;
         qvrq->inbound_tail = m;
       } else {
         qvrq->inbound_head = qvrq->inbound_tail = m;
       }
       pn_link_advance(r);
       if (cc->inbound_c && qvrq->early_flow_wflush) { *wflush = true; qvrq->early_flow_wflush = false; }
     }
     else if (pn_link_is_sender(r)) { /* Message acknowledged */
       connection_context_t *cc = get_c_context(c);
       check_true(PN_ACCEPTED == pn_delivery_remote_state(d), "bad delivery state");
       msg_t *m = (msg_t *) pn_delivery_get_context(d);
       pn_delivery_settle(d);
       qvrq_t *q = m->q;
       if (q->accepted_tail) {
         q->accepted_tail->next = m;
         q->accepted_tail = m;
       } else q->accepted_tail = q->accepted_head = m;
       cc->q->accept_count++;
     }
     break;
   }

  case PN_TRANSPORT_CLOSED: {
     connection_context_t *cc = get_c_context(c);
     lock(&cc->wake_lock);
     cc->can_wake = false;
     unlock(&cc->wake_lock);
     check_condition(e, pn_transport_condition(pn_event_transport(e)));
     if (cc) {
       if (cc->q) {
         check_true(cc->q->conn_count > 0, "bad connection count on close");
         cc->closed = true;
       }
       uint64_t now = hrtick();
       uint64_t life_ticks = now - cc->creation;
       uint64_t run_ticks = now - cc->start;
       uint64_t credit_stall = (cc->inbound_c && cc->q) ? cc->q->zero_c_ticks : 0;
       fprintf(stderr, "transport is closed ... %d %d life %" PRIu64 " run %" PRIu64 " no cr %" PRIu64 "\n", 
               (int) cc->cswitch, cc->inbound_c, life_ticks, run_ticks, credit_stall);
     } else {
       fprintf(stderr, "transport is closed without context\n");
     }

    break;
   }
 
  case PN_CONNECTION_REMOTE_CLOSE:
    check_condition(e, pn_connection_remote_condition(pn_event_connection(e)));
    pn_connection_close(pn_event_connection(e));
    break;

   case PN_SESSION_REMOTE_CLOSE:
    check_condition(e, pn_session_remote_condition(pn_event_session(e)));
    pn_session_close(pn_event_session(e));
    pn_session_free(pn_event_session(e));
    break;

   case PN_LINK_REMOTE_CLOSE:
     {
       pn_link_t *l = pn_event_link(e);
       qvrq_t *qvrq = get_context(l);
       /*ZZZ
       if (qvrq) {
         if (qvrq->outlink) set_context(qvrq->outlink, NULL);
         if (qvrq->inlink) set_context(qvrq->inlink, NULL);
         qvrq->outlink = NULL;
         qvrq->inlink = NULL;
       }
       */
       check_condition(e, pn_link_remote_condition(l));
       pn_link_close(l);
       //       pn_link_free(l);  defer to qvrq_destroy()
     }
    break;

/*ZZZ
   case PN_LINK_REMOTE_CLOSE:
     {
       pn_link_t *l = pn_event_link(e);
       qvrq_remove_link(l);
     }
     break;
*/
   case PN_LISTENER_CLOSE:
    check_condition(e, pn_listener_condition(pn_event_listener(e)));
    break;

   case PN_PROACTOR_INACTIVE: /* listener and all connections closed */
    broker_stop(b);
    break;

   case PN_PROACTOR_INTERRUPT:
    b->finished = true;
    break;

   default:
    break;
  }
}

static int ZZZbno = 0;

static void * broker_thread(void *void_broker) {
  int bno = ZZZbno++;
  void *app_ctx = NULL;
  fprintf(stderr,"ZZZ thread start %d\n", bno);fflush(stderr);
  broker_t *b = (broker_t*)void_broker;
  do {
//    fprintf(stderr,"ZZZ wait 1\n");fflush(stderr);
    pn_event_batch_t *events = pn_proactor_wait(b->proactor);
//    fprintf(stderr,"ZZZ wait 2\n");fflush(stderr);
    pn_event_t *e;
    while ((e = pn_event_batch_next(events))) {
      bool wflush = false;
/*
      if (e) {
        fprintf(stderr,"ZZZ e %d %s\n", bno, pn_event_type_name(pn_event_type(e))); fflush(stderr);
      } else {
        fprintf(stderr,"ZZZ e %d NULL\n", bno);fflush(stderr);
      }
*/
      if (enable_debug) { debug("ZZZ EV    %p  %s", (void *) events, pn_event_type_name(pn_event_type(e))); }
      handle(b, e, &app_ctx, &wflush);
//      if (wflush) fprintf(stderr, "ZZZz early ret WFLUSH\n");
      if (wflush) break;
    }
    if (enable_debug) { debug("ZZZ EVD   %p", (void *) events); }
    bool af_ignore = false;
    handle(b, NULL, &app_ctx, &af_ignore);
    app_ctx = NULL;
    pn_proactor_done(b->proactor, events);
  } while(!b->finished);
  fprintf(stderr,"ZZZ thread end\n");fflush(stderr);
  return NULL;
}

static void usage(const char *arg0) {
  fprintf(stderr, "Usage: %s [-d] [-a url] [-t thread-count] [-c container-name] -C n-connections \n", arg0);
  exit(1);
}

int main(int argc, char **argv) {
  pmutex_init(&global_mutex);
  //  if (getenv("ZZZCW")) WINDOW=atoi(getenv("ZZZCW"));  window maintained to match peer
  /* Command line options */
  char *urlstr = "0.0.0.0:amqp";
  char container_id[256];
  /* Default container-id is program:pid */
  snprintf(container_id, sizeof(container_id), "%s:%d", argv[0], getpid());
  size_t nthreads = 4;
  size_t n_conns;
  pn_millis_t heartbeat = 0;
  int i = 1;
  while (i < argc) {
    if (argv[i][0] == '-' && argv[i][1] && !argv[i][2]) {
        char opt = argv[i++][1];
        switch (opt) {
        case 'a': if (i < argc) urlstr = argv[i++]; else usage(argv[0]); break;
        case 't': if (i < argc) nthreads = atoi(argv[i++]); else usage(argv[0]); break;
        case 'd': enable_debug = true; break;
        case 'A': sasl_anon = true; break;
        case 'h': if (i < argc) heartbeat = atoi(argv[i++]); else usage(argv[0]); break;
        case 'c': if (i < argc) strncpy(container_id, argv[i++], sizeof(container_id)); else usage(argv[0]); break;
        case 'C': if (i < argc) n_conns = atoi(argv[i++]); else usage(argv[0]); break;
        default: usage(argv[0]); break;
        }
    }
    else break;
  }
  if (i < argc)
    usage(argv[0]);

  if (getenv("ZZZ_EF")) early_flow = true;
  broker_t b;
  broker_init(&b, container_id, nthreads, heartbeat, n_conns);

  /* Parse the URL or use default values */
//  pn_url_t *url = urlstr ? pn_url_parse(urlstr) : NULL;
  /* Listen on IPv6 wildcard. On systems that do not set IPV6ONLY by default,
     this will also listen for mapped IPv4 on the same port.
  */
//  const char *host = url ? pn_url_get_host(url) : "::";
//  const char *port = url ? pn_url_get_port(url) : "amqp";
  pn_proactor_listen(b.proactor, pn_listener(), urlstr, 16);
  printf("listening on '%s' %zd threads\n", urlstr, b.threads);

//  if (url) pn_url_free(url);
  if (b.threads <= 0) {
    fprintf(stderr, "invalid value -t %zu, threads must be > 0\n", b.threads);
    exit(1);
  }
  /* Start n-1 threads and use main thread */
  pneg_thread_t* threads = (pneg_thread_t*)calloc(sizeof(pneg_thread_t), b.threads);
  for (size_t i = 0; i < b.threads-1; ++i) {
    check(pneg_thread_create(&threads[i], broker_thread, &b), "pthread_create");
  }
  fprintf(stderr, "ZZZ early flow is %d\n", early_flow);
  fprintf(stderr,"ZZZ bt1\n");fflush(stderr);
  broker_thread(&b);            /* Use the main thread too. */
  fprintf(stderr,"ZZZ bt2\n");fflush(stderr);
  for (size_t i = 0; i < b.threads-1; ++i) {
    check(pneg_thread_join(&threads[i]), "pthread_join");
  }
  pn_proactor_free(b.proactor);
  free(threads);
  return 0;
}
