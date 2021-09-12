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

static size_t size_t_min(size_t a, size_t b) {
  return (a < b) ? a : b;
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
  // Simuate varying output for each run by choosing a random number of lines.
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

static void handle_outgoing(jabber_connection_t* jc) {
  // Handle here as much outgoing data as possible.  Limits include how much
  // data is available to send, how much data the raw_connection can accept
  // before blocking, and if TLS is involved, how much TLS data can be produced
  // before running out of result buffers.
  //
  // For this simplified example, max 4 buffers of application output are dealt
  // with at a time and "enough" TLS result buffers are always available from
  // the buffer pool.

  // Do accounting for previous raw connection writes and make room for new ones.
  pn_raw_buffer_t rbuf;
  while (1 == pn_raw_connection_take_written_buffers(jc->rawc, &rbuf, 1))
    rbuf_pool_return(&rbuf);
  size_t max_wire_bufs = pn_raw_connection_write_buffers_capacity(jc->rawc);
  if (max_wire_bufs == 0)
    return;  // Nothing to do until notified of future raw connection write completion

  if (!jc->jabber_turn && !jc->tls_has_output)
    return;  // nothing to send at this time

  pn_raw_buffer_t wire_buffers[4];  // An arbitrary chunking size for this example
  size_t wire_buf_count = 0;

  if (!jc->tls) {
    // Initialize wire_buffers from pool and insert available application data.
    // max 4 wanted.  Arbitrary decision for example.
    size_t max_bufs = size_t_min(max_wire_bufs, 4);
    rbuf_pool_get(wire_buffers, max_bufs);
    wire_buf_count = some_jabber(jc, wire_buffers, max_bufs);
    for (size_t tail = 4; tail > wire_buf_count; tail--)
      rbuf_pool_return(wire_buffers + tail - 1);  // not used, back to pool.
    jc->jabber_turn = false;    // Peer gets to do next jabber.
  } else {
    // TLS
    // This example front loads maximum result buffers.  Could instead use
    // a minimum number extracting after pn_tls_process().
    while (pn_tls_encrypt_result_buffers_capacity(jc->tls) > 0) {
      rbuf_pool_get(&rbuf, 1);
      pn_tls_give_encrypt_result_buffers(jc->tls, &rbuf, 1);
    }

    if (pn_tls_can_encrypt(jc->tls)) {
      // Add jabber data if there is room.
      size_t max_bufs_to_encrypt = size_t_min(4, pn_tls_encrypt_input_buffers_capacity(jc->tls));
      if (max_bufs_to_encrypt) {
        pn_raw_buffer_t unencrypted_buffers[4];
        rbuf_pool_get(unencrypted_buffers, max_bufs_to_encrypt);
        size_t unencrypted_buf_count = some_jabber(jc, unencrypted_buffers, max_bufs_to_encrypt);
        jc->jabber_turn = false;  // Peer gets to do next jabber.
        size_t consumed = pn_tls_give_encrypt_input_buffers(jc->tls, unencrypted_buffers, unencrypted_buf_count);
        if (consumed != unencrypted_buf_count) abort();  // Our careful counting was meant to prevent this.
      }
    }

    // Even if no call to pn_tls_give_encrypt_input_buffers(), there may be encrypt result buffers.
    pn_tls_process(jc->tls); // TODO:err check
    size_t results_remaining = pn_tls_encrypted_result_count(jc->tls);
    size_t rawc_capacity = pn_raw_connection_write_buffers_capacity(jc->rawc);
    size_t sendable = size_t_min(results_remaining, rawc_capacity);
    if (sendable) {
      pn_raw_buffer_t rbufs[4];
      size_t n = size_t_min(sendable, 4);
      wire_buf_count = pn_tls_take_encrypted_result_buffers(jc->tls, wire_buffers, n);
      assert(wire_buf_count == n);
    }
    // Reclaim and recycle the plain text input buffers (from the application) proceesed by the TLS library
    while (1 == pn_raw_connection_take_written_buffers(jc->rawc, &rbuf, 1))
      rbuf_pool_return(&rbuf);

    // Remember whether we missed some output buffered in the TLS library and need to come back.
    jc->tls_has_output = pn_tls_encrypted_pending(jc->tls) > 0;
  }

  if (pn_raw_connection_write_buffers(jc->rawc, wire_buffers, wire_buf_count) != wire_buf_count)
    abort();
}

static void handle_incoming(jabber_connection_t* jc) {
  bool done = false;
  pn_raw_buffer_t wire_buffers[4];
  pn_raw_buffer_t rbuf;
  bool input_closed = false;

  while (!done) {
    int max_bufs = 4;
    if (jc->tls) {
      // Don't read more buffers than the TLS lib will accept.
      if (max_bufs > pn_tls_decrypt_input_buffers_capacity(jc->tls))
        max_bufs = pn_tls_decrypt_input_buffers_capacity(jc->tls);
    }

    size_t buf_count = pn_raw_connection_take_read_buffers(jc->rawc, wire_buffers, max_bufs);
    if (buf_count < 4)
      done = true;

    if (buf_count) {
      if (wire_buffers[0].size == 0) {
        input_closed = true;
        rbuf_pool_multi_return(wire_buffers, buf_count);
        break;
      }

      if (!jc->tls) {
        // Non TLS case, use wire data directly
        for (size_t i = 0; i < buf_count; i++) {
            gobble_jabber(jc, wire_buffers + i);  // buffer ownership transferred to application
        }

      } else {
        // TLS case
        // Top up result buffers.
        while (pn_tls_decrypt_result_buffers_capacity(jc->tls) > 0) {
          rbuf_pool_get(&rbuf, 1);
          pn_tls_give_decrypt_result_buffers(jc->tls, &rbuf, 1);
        }
        size_t consumed = pn_tls_give_decrypt_input_buffers(jc->tls, wire_buffers, buf_count);
        if (consumed != buf_count) abort();  // Should never happen if we counted correctly.
        pn_tls_process(jc->tls);

        pn_raw_buffer_t decrypted_buffers[4];
        size_t decrypted_count = pn_tls_take_decrypted_result_buffers(jc->tls, decrypted_buffers, 4);
        for (size_t i = 0; i < decrypted_count; i++) {
          gobble_jabber(jc, decrypted_buffers + i); // buffer ownership transferred to application
        }

        // Reclaim and recycle the TLS encoded input buffers (from the wire) proceesed by the TLS library
        while (pn_tls_take_decrypt_input_buffers(jc->tls, &rbuf, 1) == 1)
          rbuf_pool_return(&rbuf);

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
    jc->tls = pn_tls(j->cli_domain);
    pn_tls_set_peer_hostname(jc->tls, "test_server");
    pn_tls_start(jc->tls);
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
  if (j->srv_domain) {
    jc->tls = pn_tls(j->srv_domain);
    pn_tls_start(jc->tls);
  }
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

    case PN_RAW_CONNECTION_DISCONNECTED: {
      if (jc->tls) {
        pn_tls_stop(jc->tls);
        pn_raw_buffer_t rb;
        // recycle unused result buffers, released by pn_tls_stop()
        while (pn_tls_take_encrypted_result_buffers(jc->tls, &rb, 1) == 1)
          rbuf_pool_return(&rb);
        while (pn_tls_take_decrypted_result_buffers(jc->tls, &rb, 1) == 1)
          rbuf_pool_return(&rb);
        free(jc->tls);
        jc->tls = NULL;
      }
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
