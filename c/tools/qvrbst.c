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
 * Quiver "broker" single threaded.  Assumes default quiver run.
 * Cheats.  Buffers nothing except what proton chooses to.
 * Accepts immediately instead of forwarding accept from peer.
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


#endif

pmutex global_mutex;

bool sasl_anon = false;

bool enable_debug = false;

void debug(const char* fmt, ...) {
  if (enable_debug) {
    va_list(ap);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
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


#define Q_NAME_LEN 80
PN_HANDLE(QVRQ_CTX)

struct qvrq {
  pn_link_t *inb;
  pn_link_t *outb;
  struct qvrq* next;
  size_t msg_count;
  size_t accept_count;
  int conn_count;
  char name[Q_NAME_LEN];
};

typedef struct qvrq qvrq_t;

qvrq_t *qvrq_start = NULL;

void set_context(pn_link_t *l, void* value) {
  pn_record_t *record = pn_link_attachments(l);
  pn_record_def(record, QVRQ_CTX, PN_VOID);
  pn_record_set(record, QVRQ_CTX, value);
}

qvrq_t * get_context(pn_link_t *l) {
  return (qvrq_t *) pn_record_get(pn_link_attachments(l), QVRQ_CTX);
}

qvrq_t *qvrq_find(const char *nm) {
  size_t len = strlen(nm);
  qvrq_t *qvrq = qvrq_start;
  qvrq_t *last = NULL;
  while (qvrq) {
    if (!strncmp(qvrq->name, nm, len)) {
      check_true((qvrq->inb == NULL || qvrq->outb == NULL), "more than one sender and one receiver to queue");
      return qvrq;
    }
    last = qvrq;
    qvrq = qvrq->next;
  }
  qvrq_t *neq = calloc(sizeof(qvrq_t), 1);
  strcpy(neq->name, nm);
  if (qvrq_start == NULL)
    qvrq_start = neq;
  else
    last->next = neq;
  return neq;
}


const char* qname(const char* n) {
  // point to last 5 chars
  size_t len = strlen(n);
  check_true(len <= (Q_NAME_LEN - 1), "nm len");
  return n;
}

void qvrq_add_link(pn_link_t *l, qvrq_t **pq) {
  if (pn_link_is_sender(l)) {
    qvrq_t *qvrq = qvrq_find(qname(pn_terminus_get_address(pn_link_remote_source(l))));
    check_true(qvrq->outb == NULL, "addlink out not null");
    qvrq->outb = l;
    set_context(l, qvrq);
    *pq = qvrq;
  } else {
    qvrq_t *qvrq = qvrq_find(qname(pn_terminus_get_address(pn_link_remote_target(l))));
    check_true(qvrq->inb == NULL, "addlink in not null");
    qvrq->inb = l;
    set_context(l, qvrq);
    *pq = qvrq;
  }
}

void qvrq_remove_link(pn_link_t *l) {
  qvrq_t *qvrq = get_context(l);
  if (qvrq) {
    if (qvrq->inb == l) qvrq->inb = NULL;
    else if (qvrq->outb == l) qvrq->outb = NULL;
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

PN_HANDLE(CONNECTION_CONTEXT)

typedef struct connection_context_t {
  size_t buf_size;
  char *buf;
  qvrq_t *q;
  pn_connection_t *connection;
  int cswitch;
  bool update_credit;
  bool messages_sent;
  bool inbound_c;
} connection_context_t;

connection_context_t *new_c_context() {
  connection_context_t *cc = (connection_context_t *) malloc(sizeof(connection_context_t));
  memset(cc, 0, sizeof(*cc));
  return cc;
}

connection_context_t *get_c_context(pn_connection_t *c) {
  pn_record_t *record = pn_connection_attachments(c);
  connection_context_t *cc = (connection_context_t *) pn_record_get(record, CONNECTION_CONTEXT);
  check_true(cc != NULL, "get_c_context");
  return cc;
}

connection_context_t *cc_from_link(pn_link_t *l) {
  pn_connection_t *c = pn_session_connection(pn_link_session(l));
  return get_c_context(c);
}

void set_c_context(pn_connection_t *c, connection_context_t *cc) {
  pn_record_t *record = pn_connection_attachments(c);
  pn_record_def(record, CONNECTION_CONTEXT, PN_VOID);
  pn_record_set(record, CONNECTION_CONTEXT, cc);
}


//const int WINDOW=10;            /* Incoming credit window */
int WINDOW_old=10;            /* Incoming credit window */

static pn_connection_t *current_connection = NULL;  // for current event batch

static inline pn_connection_t *find_current_connection(pn_event_t* e) {
  if (!current_connection) current_connection = pn_event_connection(e);
  return current_connection;
}

static void update_credit(connection_context_t *cc) {
  if (cc->q->conn_count == 2 && cc->q->outb && cc->q->inb) {
    int delta = pn_link_credit(cc->q->outb) - pn_link_credit(cc->q->inb);
    if (delta > 0) {
      pn_link_flow(cc->q->inb, delta);
      pn_connection_t *c = pn_session_connection(pn_link_session(cc->q->inb));
      if (c != cc->connection)
        pn_connection_wake(c);
    }
  }
}

static void context_end(connection_context_t *cc) {
  cc->cswitch++;
  if (cc->update_credit) {
    update_credit(cc);
    cc->update_credit = false;
  }
  else if (cc->messages_sent) {
    if (cc->q->conn_count == 2)
      pn_connection_wake(pn_session_connection(pn_link_session(cc->q->outb)));
    cc->messages_sent = false;
  }
}


static void handle(broker_t* b, pn_event_t* e) {
  pn_connection_t *c = NULL;

  if (!e) {
    if (current_connection) {
      context_end(get_c_context(current_connection));
      current_connection = NULL;
    }
    return;
  }

  switch (pn_event_type(e)) {

   case PN_LISTENER_ACCEPT:
       pn_listener_accept(pn_event_listener(e), pn_connection());
       b->conns++;
     break;

   case PN_CONNECTION_INIT: 
     c = find_current_connection(e);
     pn_connection_set_container(c, b->container_id);
     break;

   case PN_CONNECTION_FINAL: {
     c = find_current_connection(e);
     connection_context_t *cc = get_c_context(c);
     free(cc->buf);
     free(cc);
     if (b->conns >= b->max_conns)
       pn_listener_close(pn_event_listener(e));
     fprintf(stderr, "on final %d %d\n", b->conns, b->max_conns);
     break;
   }
   case PN_CONNECTION_BOUND: {
     c = find_current_connection(e);
     set_c_context(c, new_c_context());
     connection_context_t *cc = get_c_context(c);
     cc->connection = c;
     /* Turn off security */
     pn_transport_t *t = pn_connection_transport(c);
     pn_transport_require_auth(t, sasl_anon);
     pn_sasl_allowed_mechs(pn_sasl(t), "ANONYMOUS");
//ZZZ     fflush(stdout);fprintf(stderr, "ZZZsasl %d anon\n", (int) sasl_anon);fflush(stderr);
     pn_transport_set_idle_timeout(t, 2 * b->heartbeat);
   }
   case PN_CONNECTION_REMOTE_OPEN: {
     c = find_current_connection(e);
     pn_connection_open(pn_event_connection(e)); /* Complete the open */
     break;
   }
   case PN_CONNECTION_WAKE: {
     c = find_current_connection(e);
     // ZZZ count ??
     break;
   }
   case PN_SESSION_REMOTE_OPEN: {
     c = find_current_connection(e);
     pn_session_open(pn_event_session(e));
     break;
   }
   case PN_LINK_REMOTE_OPEN: {
     c = find_current_connection(e);
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
     cc->q->conn_count++;
     update_credit(cc);
     break;
   }
   case PN_LINK_FLOW: {
     c = find_current_connection(e);
     connection_context_t *cc = get_c_context(c);
     cc->update_credit = true;  // defer until context switch
     break;
   }
   case PN_DELIVERY: {
     c = find_current_connection(e);
     pn_delivery_t *d = pn_event_delivery(e);
     pn_link_t *r = pn_delivery_link(d);
     qvrq_t *qvrq = get_context(r);
     if (!qvrq)
       break;
     connection_context_t *cc = cc_from_link(r);
     if (pn_link_is_receiver(r) &&
         pn_delivery_readable(d) && !pn_delivery_partial(d))
     {
       size_t size = pn_delivery_pending(d);
       /* The broker does not decode the message, just forwards it. */
       if (cc->buf == NULL) {
         cc->buf = (char *) malloc(size + 100);
         cc->buf_size = size + 100;
       }
       check_true(cc->buf && size <= cc->buf_size, "internal error on delivery");
       pn_rwbytes_t m = { size, cc->buf };
       pn_link_recv(r, m.start, m.size);
       pn_delivery_update(d, PN_ACCEPTED);//ZZZ should be in response to ack from receiver
       pn_delivery_settle(d);

       pn_link_t *rl = qvrq->outb;
       check_true(pn_link_credit(rl) > 0, "message received without corresponding reply credit");
       size_t tag = ++cc->q->msg_count;
       pn_delivery_t *d = pn_delivery(rl, pn_dtag((char*)&tag, sizeof(tag)));
       pn_link_send(rl, m.start, m.size);
       pn_link_advance(rl);
       cc->messages_sent = true;
//       pn_delivery_settle(d);  /* Pre-settled: unreliable, there will be no ack/ */
     }
     else if (pn_link_is_sender(r)) { /* Message acknowledged */
       connection_context_t *cc = cc_from_link(r);
       check_true(PN_ACCEPTED == pn_delivery_remote_state(d), "bad delivery state");
       pn_delivery_settle(d);
       cc->q->accept_count++;
     }
     break;
   }

   case PN_TRANSPORT_CLOSED:
     c = find_current_connection(e);
     connection_context_t *cc = get_c_context(c);
     check_condition(e, pn_transport_condition(pn_event_transport(e)));
/* ZZZ FINAL???
     free(cc->buf);
     cc->buf_size = 0;
*/
     check_true(cc->q->conn_count > 0, "bad connection count on close");
     cc->q->conn_count--;
     if (cc->q->conn_count == 0) {
       if (cc->q->msg_count) check_true(cc->q->msg_count == cc->q->accept_count, "shutdown accept mismatch");
     }
     fprintf(stderr, "transport is closed look for FINAL message... %d %d \n", (int) cc->cswitch, cc->inbound_c);
    break;

   case PN_CONNECTION_REMOTE_CLOSE:
     c = find_current_connection(e);
    check_condition(e, pn_connection_remote_condition(pn_event_connection(e)));
    pn_connection_close(pn_event_connection(e));
    break;

   case PN_SESSION_REMOTE_CLOSE:
     c = find_current_connection(e);
    check_condition(e, pn_session_remote_condition(pn_event_session(e)));
    pn_session_close(pn_event_session(e));
    pn_session_free(pn_event_session(e));
    break;

   case PN_LINK_REMOTE_CLOSE:
     {
     c = find_current_connection(e);
       pn_link_t *l = pn_event_link(e);
       qvrq_t *qvrq = get_context(l);
       if (qvrq) {
         if (qvrq->outb) set_context(qvrq->outb, NULL);
         if (qvrq->inb) set_context(qvrq->inb, NULL);
         qvrq->outb = NULL;
         qvrq->inb = NULL;
       }
       check_condition(e, pn_link_remote_condition(pn_event_link(e)));
       pn_link_close(pn_event_link(e));
       pn_link_free(pn_event_link(e));
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
  fprintf(stderr,"ZZZ thread start %d\n", bno);fflush(stderr);
  broker_t *b = (broker_t*)void_broker;
  do {
//    fprintf(stderr,"ZZZ wait 1\n");fflush(stderr);
    pn_event_batch_t *events = pn_proactor_wait(b->proactor);
//    fprintf(stderr,"ZZZ wait 2\n");fflush(stderr);
    pn_event_t *e;
    while ((e = pn_event_batch_next(events))) {
/*
      if (e) {
        fprintf(stderr,"ZZZ e %d %s\n", bno, pn_event_type_name(pn_event_type(e))); fflush(stderr);
      } else {
        fprintf(stderr,"ZZZ e %d NULL\n", bno);fflush(stderr);
      }
*/
      handle(b, e);
    }
    handle(b, NULL);
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
