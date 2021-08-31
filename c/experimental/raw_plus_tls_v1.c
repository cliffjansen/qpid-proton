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

#include "thread.h"

#include <proton/raw_connection.h>
#include <proton/tls.h>
#include <proton/listener.h>
#include <proton/netaddr.h>
#include <proton/proactor.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>


/* 
 * Jabberwock raw connection example with and without TLS.
 *
 * One client and one server take turns sending some lines of the poem.
 * The simple "application" logic resides in some_jabber() and gobble_jabber().
 * handle_outgoing() and handle_incoming() handle the application IO
 * plumbing to use Proton raw connections, with or without TLS.
 *
 * See the "no_tls" option.
 *
 * Based on the broker and raw connection examples.  Must be able to find
 * the TLS certificates in the same location as the broker example.
 *
 * The astute reader will realize that the lack of any locking mechanisms
 * works only by luck of the simple nature of this "taking turns" example
 * and may not survive TSAN scrutiny.
 */


/* The ssl-certs subdir must be in the current directory for TLS configuration */
#define SSL_FILE(NAME) "ssl-certs/" NAME
#define SSL_PW "tserverpw"
/* Windows vs. OpenSSL certificates */
#if defined(_WIN32)
#  define CERTIFICATE(NAME) SSL_FILE(NAME "-certificate.p12")
#  define SET_CREDENTIALS(DOMAIN, NAME)                                 \
  pn_tls_domain_set_credentials(DOMAIN, SSL_FILE(NAME "-full.p12"), "", SSL_PW)
#else
#  define CERTIFICATE(NAME) SSL_FILE(NAME "-certificate.pem")
#  define SET_CREDENTIALS(DOMAIN, NAME)                                 \
  pn_tls_domain_set_credentials(DOMAIN, CERTIFICATE(NAME), SSL_FILE(NAME "-private-key.pem"), SSL_PW)
#endif

// A raw buffer "pool", in name only
static void rbuf_pool_get(pn_raw_buffer_t *bufs, uint32_t num) {
  memset(bufs, 0, sizeof(pn_raw_buffer_t) * num);
  while (num--) {
    bufs->bytes = calloc(1, 4096);
    bufs->capacity = 4096;
    bufs++;
  }
}

static void rbuf_pool_return(pn_raw_buffer_t *buf) {
  free(buf->bytes);
}

static void rbuf_pool_multi_return(pn_raw_buffer_t *buf, size_t n) {
  while(n--)
    rbuf_pool_return(buf++);
}


typedef struct jabber_t {
  pn_proactor_t *proactor;
  size_t threads;
  pn_tls_domain_t *srv_domain;
  pn_tls_domain_t *cli_domain;
  const char *host;
  const char *port;
  pn_listener_t *listener;
  size_t current_jline;
  size_t total_bytes_sent;
  size_t total_bytes_recv;
} jabber_t;

typedef struct jabber_connection_t {
  jabber_t *parent;
  pn_raw_connection_t *rawc;
  pn_tls_t *tls;
  bool tls_has_output;
  bool is_server;
  bool jabber_turn;
  bool can_send;
  bool closed;
} jabber_connection_t;

static inline uint32_t room(pn_raw_buffer_t const *rb) {
  if (rb)
    return rb->capacity - (rb->offset + rb->size);
  return 0;
}

static const char* jlines[] = {
                               "Twas brillig, and the slithy toves",
                               "Did gire and gymble in the wabe.",
                               "All mimsy were the borogroves,",
                               "And the mome raths outgrabe."
};

static size_t jlines_count = sizeof(jlines) / sizeof(jlines[0]);

static size_t some_jabber(jabber_connection_t *jc, pn_raw_buffer_t *rbufp, size_t nrbufs) {
  jabber_t *j = jc->parent;
  const char *self = jc->is_server ? "server" : "client";
  size_t actual = 0;
  int desired = (rand() % nrbufs) + 1;
  while (desired && j->current_jline < jlines_count) {
    size_t len = strlen(jlines[j->current_jline]);
    assert(len < room(rbufp));
    memcpy(rbufp->bytes + rbufp->offset, jlines[j->current_jline++], len);
    rbufp->size = len;
    j->total_bytes_sent += len;
    desired--;
    actual++;
    rbufp++;
  }
  printf("-->  %s supplied %d lines\n", self, actual);
  return actual;
}
    
static void gobble_jabber(jabber_connection_t* jc, pn_raw_buffer_t* rbuf) {
  jabber_t *j = jc->parent;
  const char *self = jc->is_server ? "server" : "client";
  assert(rbuf->size != 0);
  printf("<--  %s received:  %.4096s\n", self, rbuf->bytes + rbuf->offset);

  j->total_bytes_recv += rbuf->size;
  if (j->total_bytes_recv == j->total_bytes_sent) {
    if (j->current_jline == jlines_count) {  // All lines sent and received, initiate shutdown
      pn_raw_connection_close(jc->rawc);
      jc->closed = true;
      pn_listener_close(j->listener);
    } else { // This connection sends the next set of lines.
      jc->jabber_turn = true;
      pn_raw_connection_wake(jc->rawc);
    }
  }

  rbuf_pool_return(rbuf);
}

static void recycle_written_buffers(jabber_connection_t* jc) {
  pn_raw_buffer_t rbuf;
  while (1 == pn_raw_connection_take_written_buffers(jc->rawc, &rbuf, 1))
    rbuf_pool_return(&rbuf);
  jc->can_send = (pn_raw_connection_write_buffers_capacity(jc->rawc) >= 4);
}

static void handle_outgoing(jabber_connection_t* jc) {
  recycle_written_buffers(jc);

  if (!jc->can_send)
    return;  // wait for previous writes to complete
  if (!jc->jabber_turn && !jc->tls_has_output)
    return;  // nothing to send

  pn_raw_buffer_t wire_buffers[4];
  rbuf_pool_get(wire_buffers, 4);
  size_t wire_buf_count = 0;

  if (!jc->tls) {
    wire_buf_count = some_jabber(jc, wire_buffers, 4);
    for (size_t tail = 4; tail > wire_buf_count; tail--)
      rbuf_pool_return(wire_buffers + tail - 1);  // not filled by some_jabber
  } else {

    pn_raw_buffer_t unencrypted_buffers[4];
    rbuf_pool_get(unencrypted_buffers, 4);
    size_t unencrypted_buf_count = 0;
    if (pn_tls_can_encrypt(jc->tls))
      unencrypted_buf_count = some_jabber(jc, unencrypted_buffers, 4);
    size_t consumed = pn_tls_encrypt(jc->tls, unencrypted_buffers, unencrypted_buf_count, wire_buffers, 4, &wire_buf_count);
    // TODO: save remaining application buffers for later write, oversubsribe output bufs, or astitcher API suggestion...
    if (consumed < unencrypted_buf_count) abort();
    
    rbuf_pool_multi_return(unencrypted_buffers, 4);  // no longer needed

    for (size_t tail = 4; tail > wire_buf_count; tail--)
      rbuf_pool_return(wire_buffers + tail - 1);  // not filled in encryption step

    // Remember whether we missed some output buffered by openssl and need to come back.
    jc->tls_has_output = pn_tls_encrypted_pending(jc->tls) > 0;
  }

  assert(pn_raw_connection_write_buffers_capacity(jc->rawc) >= wire_buf_count);
  jc->jabber_turn = false;
  jc->can_send = (pn_raw_connection_write_buffers_capacity(jc->rawc) >= 4);
  pn_raw_connection_write_buffers(jc->rawc, wire_buffers, wire_buf_count);
}

static void handle_incoming(jabber_connection_t* jc) {
  bool done = false;
  pn_raw_buffer_t wire_buffers[4];
  bool input_closed = false;

  while (!done) {
    size_t buf_count = pn_raw_connection_take_read_buffers(jc->rawc, wire_buffers, 4);
    if (buf_count < 4)
      done = true;

    if (buf_count) {
      if (wire_buffers[0].size == 0) {
        input_closed = true;
        rbuf_pool_multi_return(wire_buffers, buf_count);
        break;
      }
      
      if (!jc->tls) {
        // Non TLS case, send data directly to application
        for (size_t i = 0; i < buf_count; i++) {
            gobble_jabber(jc, wire_buffers + i);
        }

      } else {

        for (size_t total_consumed = 0; total_consumed < buf_count; ) {
          size_t remaining = buf_count - total_consumed;
          pn_raw_buffer_t decrypted_buffers[4];
          rbuf_pool_get(decrypted_buffers, remaining);
          size_t decrypted_count = 0;
          size_t consumed_count = pn_tls_decrypt(jc->tls, wire_buffers + total_consumed, remaining, decrypted_buffers, remaining, &decrypted_count);
          total_consumed += consumed_count;
          // Decrypted buffers get sent on to the jabber application, unused ones return to pool.
          for (size_t i = 0; i < decrypted_count; i++) {
              gobble_jabber(jc, decrypted_buffers + i);
          }
          for (size_t i = decrypted_count; i < remaining; i++)
            rbuf_pool_return(decrypted_buffers + i);
        }
        // recycle the wire buffers
        for (size_t i = 0; i < buf_count; i++)
          rbuf_pool_multi_return(wire_buffers, buf_count);

        // TLS input can generate non-application output.  Note that here.
        jc->tls_has_output = pn_tls_encrypted_pending(jc->tls) > 0;
      }

    }
  }

  if (input_closed && !jc->closed) {
    pn_raw_connection_close(jc->rawc);
    jc->closed = true;
  }
}

static void create_client_connection(jabber_t *j) {
  char addr[PN_MAX_ADDR];
  pn_raw_connection_t *c = pn_raw_connection();
  jabber_connection_t *jc = calloc(sizeof(*jc), 1);
  jc->rawc = c;
  jc->is_server = false;
  jc->jabber_turn = true;  // Client goes first for purposes of this example.  Arbitrary choice.
  jc->parent = j;
  pn_raw_connection_set_context(c, (void *) jc);

  // Client side TLS can be set up anywhere between here and first write (TLS clienthello).
  if (j->cli_domain) {
    jc->tls = pn_tls(j->cli_domain, "test_server", NULL);
    jc->tls_has_output = true; // always true for initial client side TLS.
  }

  pn_proactor_addr(addr, sizeof(addr), j->host, j->port);
  pn_proactor_raw_connect(j->proactor, c, addr);
}

static void create_server_connection(jabber_t *j, pn_listener_t *listener) {
  pn_raw_connection_t *c = pn_raw_connection();
  jabber_connection_t *jc = calloc(sizeof(*jc), 1);
  jc->rawc = c;
  jc->is_server = true;
  jc->parent = j;
  pn_raw_connection_set_context(c, (void *) jc);

  // Server side TLS can be set up anywhere between here and first read (TLS clienthello).
  if (j->srv_domain)
    jc->tls = pn_tls(j->srv_domain, NULL, NULL);
  
  pn_listener_raw_accept(listener, c);
  printf("**listener accepted %p\n", (void *)jc);
}

static bool handle_raw_connection(jabber_connection_t* jc, pn_event_t* event) {
  switch (pn_event_type(event)) {
    
    case PN_RAW_CONNECTION_CONNECTED: {
      printf("**raw connection %p %d\n", (void *)jc, jc->is_server);
    } break;

    case PN_RAW_CONNECTION_NEED_READ_BUFFERS: {
      pn_raw_buffer_t buffers[4];
      rbuf_pool_get(buffers, 4);
      size_t n = pn_raw_connection_give_read_buffers(jc->rawc, buffers, 4);
      if (n != 4) abort();
    } break;

    case PN_RAW_CONNECTION_WRITTEN:
    case PN_RAW_CONNECTION_NEED_WRITE_BUFFERS:
    case PN_RAW_CONNECTION_WAKE: {
      handle_outgoing(jc);
    } break;

    case PN_RAW_CONNECTION_READ: {
      handle_incoming(jc);
      if (jc->tls_has_output)
        handle_outgoing(jc);
    } break;
  }
  return true;
}

static bool handle(jabber_t* j, pn_event_t* event) {
  switch (pn_event_type(event)) {

    case PN_LISTENER_OPEN: {
      create_client_connection(j);
      break;
    }
    case PN_LISTENER_ACCEPT: {
      pn_listener_t *listener = pn_event_listener(event);
      create_server_connection(j, listener);
    } break;

    case PN_PROACTOR_INACTIVE:
      printf("**shutdown event\n");
      // fall through
    case PN_PROACTOR_INTERRUPT: {
      pn_proactor_t *proactor = pn_event_proactor(event);
      pn_proactor_interrupt(proactor);
      return false;
    } break;

    default: {
      pn_raw_connection_t *c = pn_event_raw_connection(event);
      if (c) {
        jabber_connection_t *jc = (jabber_connection_t *) pn_raw_connection_get_context(c);
        handle_raw_connection(jc, event);
      }
    }
  }
  return true;
}

static void* j_thread(void *void_j) {
  jabber_t *j = (jabber_t*)void_j;
  bool finished = false;
  do {
    pn_event_batch_t *events = pn_proactor_wait(j->proactor);
    pn_event_t *e;
    while ((e = pn_event_batch_next(events))) {
      if (!handle(j, e)) finished = true;
    }
    pn_proactor_done(j->proactor, events);
  } while(!finished);
  return NULL;
}

// main is from broker.c with switch to raw connections versus AMQP connections.
int main(int argc, char **argv) {
  int err;
  srand(time(NULL));
  jabber_t j = {0};
  j.host = (argc > 1) ? argv[1] : "";
  j.port = (argc > 2) ? argv[2] : "15243";  // our default Jabberwock address
  j.listener = pn_listener();
  bool use_tls = true;
  if (argc > 3 && strncmp(argv[3], "no_tls", 6) == 0)
    use_tls = false;

  j.proactor = pn_proactor();
  j.threads = 4;
  if (use_tls) {
    j.srv_domain = pn_tls_domain(PN_TLS_MODE_SERVER);
    if (SET_CREDENTIALS(j.srv_domain, "tserver") != 0) {
      printf("Failed to set up server certificate: %s, private key: %s\n", CERTIFICATE("tserver"), SSL_FILE("tserver-private-key.pem"));
      exit(1);
    }
    j.cli_domain = pn_tls_domain(PN_TLS_MODE_CLIENT); //  PN_TLS_VERIFY_PEER_NAME by default
    if (pn_tls_domain_set_trusted_ca_db(j.cli_domain, CERTIFICATE("tserver")) != 0) {
      printf("CA failure\n");
      exit(1);
    }
  }
  {
  /* Listen on addr */
  char addr[PN_MAX_ADDR];
  pn_proactor_addr(addr, sizeof(addr), j.host, j.port);
  pn_proactor_listen(j.proactor, j.listener, addr, 16);
  }

  {
  /* Start n-1 threads */
  pthread_t* threads = (pthread_t*)calloc(sizeof(pthread_t), j.threads);
  size_t i;
  for (i = 0; i < j.threads-1; ++i) {
    pthread_create(&threads[i], NULL, j_thread, &j);
  }
  j_thread(&j);            /* Use the main thread too. */
  /* Join the other threads */
  for (i = 0; i < j.threads-1; ++i) {
    pthread_join(threads[i], NULL);
  }
  pn_proactor_free(j.proactor);
  free(threads);
  if (j.srv_domain)
    pn_tls_domain_free(j.srv_domain);
  if (j.cli_domain)
    pn_tls_domain_free(j.cli_domain);
  return 0;
  }
}
