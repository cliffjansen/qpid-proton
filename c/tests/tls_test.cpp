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

#include <proton/tls.h>

#include "pn_test.hpp"

#ifdef _WIN32
#include <errno.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#endif
// ZZZ strlen only
#include <cstring>

using namespace pn_test;
using Catch::Matchers::Contains;
using Catch::Matchers::Equals;

/* Note must be run in the current directory to find certificate files */
#define SSL_FILE(NAME) "ssl-certs/" NAME
#define SSL_PW(NAME) NAME "pw"
/* Windows vs. OpenSSL certificates */
#if defined(_WIN32)
#  define CERTIFICATE(NAME) SSL_FILE(NAME "-certificate.p12")
#  define SET_CREDENTIALS(DOMAIN, NAME)                                 \
  pn_tls_config_set_credentials(DOMAIN, SSL_FILE(NAME "-full.p12"), "", SSL_PW(NAME))
#else
#  define CERTIFICATE(NAME) SSL_FILE(NAME "-certificate.pem")
#  define SET_CREDENTIALS(DOMAIN, NAME)                                 \
  pn_tls_config_set_credentials(DOMAIN, CERTIFICATE(NAME), SSL_FILE(NAME "-private-key.pem"), SSL_PW(NAME))
#endif



TEST_CASE("tls foo and bar") {
  pn_tls_config_t *client_domain = pn_tls_config(PN_TLS_MODE_CLIENT);
  REQUIRE(client_domain);
  pn_tls_config_t *server_domain = pn_tls_config(PN_TLS_MODE_SERVER);
  REQUIRE(server_domain);
  pn_tls_t *cli_tls = pn_tls(client_domain);
  CHECK(cli_tls == NULL); // No default domain configuration
  pn_tls_t *srv_tls = pn_tls(server_domain);
  CHECK(srv_tls == NULL); // No default domain configuration for server either

  pn_tls_free(cli_tls);
  pn_tls_free(srv_tls);
  pn_tls_config_free(client_domain);
  pn_tls_config_free(server_domain);
}

TEST_CASE("plain old fubar") {
  pn_tls_config_t *client_domain = pn_tls_config(PN_TLS_MODE_CLIENT);
  REQUIRE(client_domain);
  pn_tls_config_t *server_domain = pn_tls_config(PN_TLS_MODE_SERVER);
  REQUIRE(server_domain);

  REQUIRE(SET_CREDENTIALS(server_domain, "tserver") == 0);  
  REQUIRE(pn_tls_config_set_peer_authentication(client_domain, PN_TLS_VERIFY_PEER, NULL) == 0);


  pn_tls_t *cli_tls = pn_tls(client_domain);
  pn_tls_set_peer_hostname(cli_tls, "test_server");
  pn_tls_t *srv_tls = pn_tls(server_domain);

  CHECK(false);
  pn_tls_free(cli_tls);
  pn_tls_free(srv_tls);
  pn_tls_config_free(client_domain);
  pn_tls_config_free(server_domain);
}

