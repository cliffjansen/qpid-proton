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

#include "./pn_test.hpp"

#include <proton/engine.h>
#include <cstring>

using namespace pn_test;

// push data from one transport to another
static int xfer(pn_transport_t *src, pn_transport_t *dest) {
  ssize_t out = pn_transport_pending(src);
  if (out > 0) {
    ssize_t in = pn_transport_capacity(dest);
    if (in > 0) {
      size_t count = (size_t)((out < in) ? out : in);
      pn_transport_push(dest, pn_transport_head(src), count);
      pn_transport_pop(src, count);
      return (int)count;
    }
  }
  return 0;
}

// transfer all available data between two transports
static int pump(pn_transport_t *t1, pn_transport_t *t2) {
  int total = 0;
  int work;
  do {
    work = xfer(t1, t2) + xfer(t2, t1);
    total += work;
  } while (work);
  return total;
}

// handle state changes of the endpoints
static void process_endpoints(pn_connection_t *conn) {
  pn_session_t *ssn = pn_session_head(conn, PN_LOCAL_UNINIT);
  while (ssn) {
    // fprintf(stderr, "Opening session %p\n", (void*)ssn);
    pn_session_open(ssn);
    ssn = pn_session_next(ssn, PN_LOCAL_UNINIT);
  }

  pn_link_t *link = pn_link_head(conn, PN_LOCAL_UNINIT);
  while (link) {
    pn_link_open(link);
    link = pn_link_next(link, PN_LOCAL_UNINIT);
  }

  link = pn_link_head(conn, PN_LOCAL_ACTIVE | PN_REMOTE_CLOSED);
  while (link) {
    pn_link_close(link);
    link = pn_link_next(link, PN_LOCAL_ACTIVE | PN_REMOTE_CLOSED);
  }

  ssn = pn_session_head(conn, PN_LOCAL_ACTIVE | PN_REMOTE_CLOSED);
  while (ssn) {
    pn_session_close(ssn);
    ssn = pn_session_next(ssn, PN_LOCAL_ACTIVE | PN_REMOTE_CLOSED);
  }
}

// bring up a session and a link between the two connections
static void test_setup(pn_connection_t *c1, pn_transport_t *t1,
                       pn_connection_t *c2, pn_transport_t *t2) {
  pn_connection_open(c1);
  pn_connection_open(c2);

  pn_session_t *s1 = pn_session(c1);
  pn_session_open(s1);

  pn_link_t *tx = pn_sender(s1, "sender");
  pn_link_open(tx);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // session and link should be up, c2 should have a receiver link:

  REQUIRE(pn_session_state(s1) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(pn_link_state(tx) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));

  pn_link_t *rx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(rx);
  REQUIRE(pn_link_is_receiver(rx));
}

// test that free'ing the connection should free all contained
// resources (session, links, deliveries)
TEST_CASE("engine_free_connection") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  pn_transport_bind(t2, c2);

  // pn_transport_trace(t1, PN_TRACE_FRM);
  test_setup(c1, t1, c2, t2);

  pn_link_t *tx = pn_link_head(c1, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(tx);
  pn_link_t *rx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(rx);

  // transfer some data across the link:
  pn_link_flow(rx, 10);
  pn_delivery_t *d1 = pn_delivery(tx, pn_dtag("tag-1", 6));
  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }
  REQUIRE(pn_delivery_writable(d1));
  pn_link_send(tx, "ABC", 4);
  pn_link_advance(tx);

  // now free the connection, but keep processing the transport
  process_endpoints(c1);
  pn_connection_free(c1);
  while (pump(t1, t2)) {
    process_endpoints(c2);
  }

  // delivery should have transfered:
  REQUIRE(pn_link_current(rx));
  REQUIRE(pn_delivery_readable(pn_link_current(rx)));

  pn_transport_unbind(t1);
  pn_transport_free(t1);

  pn_connection_free(c2);
  pn_transport_unbind(t2);
  pn_transport_free(t2);
}

TEST_CASE("engine_free_session") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  pn_transport_bind(t2, c2);

  // pn_transport_trace(t1, PN_TRACE_FRM);
  test_setup(c1, t1, c2, t2);

  pn_session_t *ssn = pn_session_head(c1, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(ssn);
  pn_link_t *tx = pn_link_head(c1, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(tx);
  pn_link_t *rx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(rx);

  // prepare for transfer: request some credit
  pn_link_flow(rx, 10);
  pn_delivery_t *d1 = pn_delivery(tx, pn_dtag("tag-1", 6));
  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }
  REQUIRE(pn_delivery_writable(d1));

  // send some data, but also close the session:
  pn_link_send(tx, "ABC", 4);
  pn_link_advance(tx);

  pn_session_close(ssn);
  pn_session_free(ssn);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // delivery should have transfered:
  REQUIRE(pn_link_current(rx));
  REQUIRE(pn_delivery_readable(pn_link_current(rx)));

  // c2's session should see the close:
  pn_session_t *ssn2 = pn_session_head(c2, 0);
  REQUIRE(ssn2);
  REQUIRE(pn_session_state(ssn2) == (PN_LOCAL_CLOSED | PN_REMOTE_CLOSED));

  pn_transport_unbind(t1);
  pn_transport_free(t1);
  pn_connection_free(c1);

  pn_transport_unbind(t2);
  pn_transport_free(t2);
  pn_connection_free(c2);
}

TEST_CASE("engine_free_link)") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  pn_transport_bind(t2, c2);

  // pn_transport_trace(t1, PN_TRACE_FRM);
  test_setup(c1, t1, c2, t2);

  pn_link_t *tx = pn_link_head(c1, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(tx);
  pn_link_t *rx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(rx);

  // prepare for transfer: request some credit
  pn_link_flow(rx, 10);
  pn_delivery_t *d1 = pn_delivery(tx, pn_dtag("tag-1", 6));
  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }
  REQUIRE(pn_delivery_writable(d1));

  // send some data, then close and destroy the link:
  pn_link_send(tx, "ABC", 4);
  pn_link_advance(tx);

  pn_link_close(tx);
  pn_link_free(tx);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // the data transfer will complete and the link close
  // should have been sent to the peer
  REQUIRE(pn_link_current(rx));
  REQUIRE(pn_link_state(rx) == (PN_LOCAL_CLOSED | PN_REMOTE_CLOSED));

  pn_transport_unbind(t1);
  pn_transport_free(t1);
  pn_connection_free(c1);

  pn_transport_unbind(t2);
  pn_transport_free(t2);
  pn_connection_free(c2);
}

// regression test fo PROTON-1466 - confusion between links with prefix names
TEST_CASE("engine_link_name_prefix)") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  pn_transport_bind(t2, c2);

  pn_connection_open(c1);
  pn_connection_open(c2);

  pn_session_t *s1 = pn_session(c1);
  pn_session_open(s1);

  pn_link_t *l = pn_receiver(s1, "l");
  pn_link_open(l);
  pn_link_t *lll = pn_receiver(s1, "lll");
  pn_link_open(lll);
  pn_link_t *ll = pn_receiver(s1, "ll");
  pn_link_open(ll);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // session and link should be up, c2 should have a receiver link:
  REQUIRE(pn_session_state(s1) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(pn_link_state(l) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(pn_link_state(lll) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(pn_link_state(ll) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));

  pn_link_t *r = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(std::string("l") == pn_link_name(r));
  r = pn_link_next(r, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(std::string("lll") == pn_link_name(r));
  r = pn_link_next(r, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(std::string("ll") == pn_link_name(r));

  pn_transport_unbind(t1);
  pn_transport_free(t1);
  pn_connection_free(c1);

  pn_transport_unbind(t2);
  pn_transport_free(t2);
  pn_connection_free(c2);
}


TEST_CASE("link_properties)") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  pn_transport_bind(t2, c2);

  pn_connection_open(c1);
  pn_connection_open(c2);

  pn_session_t *s1 = pn_session(c1);
  pn_session_open(s1);

  pn_link_t *rx = pn_receiver(s1, "props");
  pn_data_t *props = pn_link_properties(rx);
  REQUIRE(props != NULL);

  pn_data_clear(props);
  pn_data_fill(props, "{S[iii]SI}", "foo", 1, 987, 3, "bar", 965);
  pn_link_open(rx);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // session and link should be up, c2 should have a sender link:
  REQUIRE(pn_link_state(rx) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(pn_link_remote_properties(rx) == NULL);

  pn_link_t *tx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));

  REQUIRE(pn_link_remote_properties(tx) != NULL);
  CHECK("{\"foo\"=[1, 987, 3], \"bar\"=965}" == pn_test::inspect(pn_link_remote_properties(tx)));

  pn_transport_unbind(t1);
  pn_transport_free(t1);
  pn_connection_free(c1);

  pn_transport_unbind(t2);
  pn_transport_free(t2);
  pn_connection_free(c2);
}

static ssize_t link_send(pn_link_t *s, size_t n) {
  char buf[5120];
  if (n > 5120) return PN_ARG_ERR;
  memset(buf, 'x', n);
  return pn_link_send(s, buf, n);
}

static ssize_t link_recv(pn_link_t *r, size_t n) {
  char buf[5120];
  if (n > 5120) return PN_ARG_ERR;
  return pn_link_recv(r, buf, n);
}

TEST_CASE("session_flow") {
  pn_connection_t *c1 = pn_connection();
  pn_transport_t *t1 = pn_transport();
  pn_transport_bind(t1, c1);

  pn_connection_t *c2 = pn_connection();
  pn_transport_t *t2 = pn_transport();
  pn_transport_set_server(t2);
  // Use 1K max frame size for test.
  pn_transport_set_max_frame(t2, 1024);
  pn_transport_bind(t2, c2);

  pn_connection_open(c1);
  pn_connection_open(c2);

  pn_session_t *s1 = pn_session(c1);
  pn_session_open(s1);
  REQUIRE(pn_session_get_incoming_capacity(s1) == 0);
  REQUIRE(pn_session_get_incoming_window(s1) == 0);
  REQUIRE(pn_session_get_incoming_window_lwm(s1) == 0);
  
  pn_link_t *tx = pn_sender(s1, "tx");
  pn_link_open(tx);

  while (pump(t1, t2)) {
    process_endpoints(c1);
    process_endpoints(c2);
  }

  // session and link should be up, c2 should have a receiver link:
  REQUIRE(pn_link_state(tx) == (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  pn_session_t *s2 = pn_session_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  pn_link_t *rx = pn_link_head(c2, (PN_LOCAL_ACTIVE | PN_REMOTE_ACTIVE));
  REQUIRE(s2 != NULL);
  REQUIRE(rx != NULL);

  REQUIRE(pn_session_get_incoming_capacity(s2) == 0);
  REQUIRE(pn_session_get_incoming_window(s2) == 0);
  REQUIRE(pn_session_get_incoming_window_lwm(s2) == 0);

  pn_link_flow(rx, 1);
  pn_session_set_incoming_capacity(s2, 10240);
  REQUIRE(pn_session_get_incoming_capacity(s2) == 10240);
  while (pump(t1, t2));
  REQUIRE(pn_session_remote_incoming_window(s1) == 10);

  // Don't count partial max frame.
  pn_session_set_incoming_capacity(s2, 5120 + 1);
  while (pump(t1, t2));
  REQUIRE(pn_session_remote_incoming_window(s1) == 5);

  // default lwm
  pn_session_set_incoming_window_and_lwm(s2, 4, 0);
  REQUIRE(pn_session_get_incoming_window(s2) == 4);
  REQUIRE(pn_session_get_incoming_window_lwm(s2) == 0);
  REQUIRE(pn_session_get_incoming_capacity(s2) == 0);
  while (pump(t1, t2));
  REQUIRE(pn_session_remote_incoming_window(s1) == 4);

  // Send frames and check window.

  // This is complicated by messy accounting: max_frame_size is a proxy for frames buffered on the
  // receiver side, but payload per transfer frame is strictly less than max frame size due to
  // frame headers.  For this test 997 bytes of payload fits in a 1024 byte transfer frame.
  // Senders and receivers count/update frames a bit differently.

  size_t payloadsz = 997;
  size_t onefrm = 1 * payloadsz;
  size_t fourfrm = 4 * payloadsz;
  size_t fivefrm = 5 * payloadsz;

  REQUIRE(pn_link_credit(tx) > 0);
  pn_delivery_t *d1 = pn_delivery(tx, pn_dtag("tag-1", 6));
  REQUIRE(link_send(tx, fivefrm) == (ssize_t) fivefrm);
  while (pump(t1, t2));
  // Expect 4 frames sent and 1 remaining, window 0
  pn_delivery_t *d2 = pn_link_current(rx);
  REQUIRE(d2);
  REQUIRE(pn_delivery_pending(d2) == fourfrm);
  REQUIRE(pn_delivery_partial(d2));
  REQUIRE(pn_delivery_pending(d1) == onefrm);
  REQUIRE(pn_session_remote_incoming_window(s1) == 0);

  // Extract 3 frames, tx can send remaining bytes in one frame.
  REQUIRE(link_recv(rx, 3072) == 3072);
  while (pump(t1, t2));
  // Window should be 2
  REQUIRE(pn_delivery_pending(d1) == 0);
  REQUIRE(pn_session_remote_incoming_window(s1) == 2);

  // Confirm lwm is 2.  Increase window but should not be communicated to peer
  int remaining = pn_delivery_pending(d2);
  REQUIRE(link_recv(rx, 5120) == remaining);
  while (pump(t1, t2));
  // Window should still be 2, no flow frame
  REQUIRE(pn_session_remote_incoming_window(s1) == 2);

  // Decrease window by 1, to below lwm
  REQUIRE(link_send(tx, onefrm) == (ssize_t) onefrm);
  REQUIRE(xfer(t1,t2) > 0);
  REQUIRE(pn_session_remote_incoming_window(s1) == 1);
  remaining = pn_delivery_pending(d2);
  REQUIRE(link_recv(rx, 5120) == remaining);
  while (pump(t1, t2));
  // Flow frame received by t1
  REQUIRE(pn_session_remote_incoming_window(s1) == 4);

  // User specified lwm:
  pn_session_set_incoming_window_and_lwm(s2, 5, 4);
  REQUIRE(pn_session_get_incoming_window(s2) == 5);
  REQUIRE(pn_session_get_incoming_window_lwm(s2) == 4);
  REQUIRE(pn_session_get_incoming_capacity(s2) == 0);
  while (pump(t1, t2));
  REQUIRE(pn_session_remote_incoming_window(s1) == 5);

  REQUIRE(link_send(tx, onefrm) == (ssize_t) onefrm);
  REQUIRE(xfer(t1,t2) > 0);
  REQUIRE(pn_session_remote_incoming_window(s1) == 4);
  remaining = pn_delivery_pending(d2);
  REQUIRE(link_recv(rx, 5120) == remaining);
  while (pump(t1, t2));
  // No flow frame.
  REQUIRE(pn_session_remote_incoming_window(s1) == 4);

  // Decrease window by 1, to below lwm
  REQUIRE(link_send(tx, onefrm) == (ssize_t) onefrm);
  REQUIRE(xfer(t1,t2) > 0);
  REQUIRE(pn_session_remote_incoming_window(s1) == 3);
  remaining = pn_delivery_pending(d2);
  REQUIRE(link_recv(rx, 5120) == remaining);
  while (pump(t1, t2));
  // Flow frame received by t1
  REQUIRE(pn_session_remote_incoming_window(s1) == 5);

  pn_transport_unbind(t1);
  pn_transport_free(t1);
  pn_connection_free(c1);

  pn_transport_unbind(t2);
  pn_transport_free(t2);
  pn_connection_free(c2);
}
