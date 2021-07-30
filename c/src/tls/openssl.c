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

#include "platform/platform.h"
#include "platform/platform_fmt.h"
#include "core/util.h"
#include <proton/error.h>
#include <proton/tls.h>

// openssl on windows expects the user to have already included
// winsock.h

#ifdef _MSC_VER
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#if _WIN32_WINNT < 0x0501
#error "Proton requires Windows API support for XP or later."
#endif
#include <winsock2.h>
#include <mswsock.h>
#include <Ws2tcpip.h>
#endif


#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

/** @file
 * Standalone raw buffer based SSL/TLS support API.
 *
 * This file is heavily based on the original Proton SSL layer for AMQP connections.
 */

typedef struct pn_tls_session_t pn_tls_session_t;

static int tls_ex_data_index;

struct pn_tls_domain_t {

  SSL_CTX       *ctx;

  char *keyfile_pw;

  // settings used for all connections
  char *trusted_CAs;

  char *ciphers;

  int   ref_count;
#ifdef SSL_SECOP_PEER
  int default_seclevel;
#endif
  pn_tls_mode_t mode;
  pn_tls_verify_mode_t verify_mode;

  bool has_certificate; // true when certificate configured
  bool allow_unsecured;
};

// Bold guess of medium size of data chunks to work with.
// May evolve for different values for encrypt and decrypt,
// or for best latency versus max throughput.  TBD.
// Currently assume that feeding the BIO amounts between
// JRSIZE and 2*JRSIZE is a reasonable tradeoff of memory
// buffering and TLS max record size.
#define JRSIZE    (4*1024)

struct pn_tls_t {
  pn_tls_mode_t mode;
  pn_tls_verify_mode_t verify_mode;
  const char    *session_id;
  const char *peer_hostname;
  SSL *ssl;

  BIO *bio_ssl;         // i/o from/to SSL socket layer
  BIO *bio_ssl_io;      // SSL "half" of network-facing BIO
  BIO *bio_net_io;      // socket-side "half" of network-facing BIO
  // buffers for holding unprocessed bytes to be en/decoded when BIO is able to process them.
  char *q4enc_bytes;
  char *q4dec_bytes;

  ssize_t app_input_closed;   // error code returned by upper layer process input
  ssize_t app_output_closed;  // error code returned by upper layer process output

  uint32_t q4enc_capacity;
  uint32_t q4enc_size;
  uint32_t q4dec_capacity;
  uint32_t q4dec_size;
  // BIO processed bytes available for extraction.
  uint32_t bio_encrypted;
  uint32_t bio_decrypted;

  bool ssl_shutdown;    // BIO_ssl_shutdown() called on socket.
  bool ssl_closed;      // shutdown complete, or SSL error
  bool read_blocked;    // SSL blocked until more network data is read
  bool write_blocked;   // SSL blocked until data is written to network

  char *subject;
  X509 *peer_certificate;
};

// define two sets of allowable ciphers: those that require authentication, and those
// that do not require authentication (anonymous).  See ciphers(1).
#define CIPHERS_AUTHENTICATE    "ALL:!aNULL:!eNULL:@STRENGTH"
#define CIPHERS_ANONYMOUS       "ALL:aNULL:!eNULL:@STRENGTH"

/* */
static int keyfile_pw_cb(char *buf, int size, int rwflag, void *userdata);
static int init_ssl_socket(pn_tls_t *, pn_tls_domain_t *);
static void release_ssl_socket( pn_tls_t * );
static X509 *get_peer_certificate(pn_tls_t *ssl);


//ZZZ dump these wih log replacement
#define     PN_LEVEL_NONE      0
#define     PN_LEVEL_CRITICAL  1
#define     PN_LEVEL_ERROR     2
#define     PN_LEVEL_WARNING   4
#define     PN_LEVEL_INFO      8
#define     PN_LEVEL_DEBUG     16
#define     PN_LEVEL_TRACE     32
#define     PN_LEVEL_FRAME     64
#define     PN_LEVEL_RAW       128
#define     PN_LEVEL_ALL       65535


static void ssl_log(void *v, int sev, const char *fmt, ...)
{
  //ZZZ
}

static void ssl_log_flush(void *v, int sev)
{
}

// log an error and dump the SSL error stack
static void ssl_log_error(const char *fmt, ...)
{
}

#ifdef laterZZZ
// unrecoverable SSL failure occurred, notify transport and generate error code.
static int ssl_failed(pn_tls_t *ssl)
{
  SSL_set_shutdown(ssl->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
  ssl->ssl_closed = true;
  ssl->app_input_closed = ssl->app_output_closed = PN_EOS;
  // fake a shutdown so the i/o processing code will close properly
  SSL_set_shutdown(ssl->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
  // try to grab the first SSL error to add to the failure log
  char buf[256] = "Unknown error";
  unsigned long ssl_err = ERR_get_error();
  if (ssl_err) {
    ERR_error_string_n( ssl_err, buf, sizeof(buf) );
  }
  ssl_log_flush(transport, PN_LEVEL_ERROR);    // spit out any remaining errors to the log file
  pn_do_error(transport, "amqp:connection:framing-error", "SSL Failure: %s", buf);
  return PN_EOS;
}
#endif

static char *pni_strdup(const char *src)
{
  if (!src) return NULL;
  char *dest = (char *) malloc(strlen(src)+1);
  if (!dest) return NULL;
  return strcpy(dest, src);
}

static int pni_strcasecmp(const char *a, const char *b)
{
  int diff;
  while (*b) {
    char aa = *a++, bb = *b++;
    diff = tolower(aa)-tolower(bb);
    if ( diff!=0 ) return diff;
  }
  return *a;
}

static int pni_strncasecmp(const char* a, const char* b, size_t len)
{
  int diff = 0;
  while (*b && len > 0) {
    char aa = *a++, bb = *b++;
    diff = tolower(aa)-tolower(bb);
    if ( diff!=0 ) return diff;
    --len;
  };
  return len==0 ? diff : *a;
}


/* match the DNS name pattern from the peer certificate against our configured peer
   hostname */
static bool match_dns_pattern( const char *hostname,
                               const char *pattern, int plen )
{
  int slen = (int) strlen(hostname);
  if (memchr( pattern, '*', plen ) == NULL)
    return (plen == slen &&
            pni_strncasecmp( pattern, hostname, plen ) == 0);

  /* dns wildcarded pattern - RFC2818 */
  char plabel[64];   /* max label length < 63 - RFC1034 */
  char slabel[64];

  while (plen > 0 && slen > 0) {
    const char *cptr;
    int len;

    cptr = (const char *) memchr( pattern, '.', plen );
    len = (cptr) ? cptr - pattern : plen;
    if (len > (int) sizeof(plabel) - 1) return false;
    memcpy( plabel, pattern, len );
    plabel[len] = 0;
    if (cptr) ++len;    // skip matching '.'
    pattern += len;
    plen -= len;

    cptr = (const char *) memchr( hostname, '.', slen );
    len = (cptr) ? cptr - hostname : slen;
    if (len > (int) sizeof(slabel) - 1) return false;
    memcpy( slabel, hostname, len );
    slabel[len] = 0;
    if (cptr) ++len;    // skip matching '.'
    hostname += len;
    slen -= len;

    char *star = strchr( plabel, '*' );
    if (!star) {
      if (pni_strcasecmp( plabel, slabel )) return false;
    } else {
      *star = '\0';
      char *prefix = plabel;
      int prefix_len = strlen(prefix);
      char *suffix = star + 1;
      int suffix_len = strlen(suffix);
      if (prefix_len && pni_strncasecmp( prefix, slabel, prefix_len )) return false;
      if (suffix_len && pni_strncasecmp( suffix,
                                        slabel + (strlen(slabel) - suffix_len),
                                        suffix_len )) return false;
    }
  }

  return plen == slen;
}

// Certificate chain verification callback: return 1 if verified,
// 0 if remote cannot be verified (fail handshake).
//
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  if (!preverify_ok || X509_STORE_CTX_get_error_depth(ctx) != 0)
    // already failed, or not at peer cert in chain
    return preverify_ok;

  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
  SSL *ssn = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  if (!ssn) {
    ssl_log(NULL, PN_LEVEL_ERROR, "Error: unexpected error - SSL session info not available for peer verify!");
    return 0;  // fail connection
  }

  pn_tls_t *ssl = (pn_tls_t *)SSL_get_ex_data(ssn, tls_ex_data_index);
  if (!ssl) {
    //ZZZ ssl_log(transport, PN_LEVEL_ERROR, "Error: unexpected error - SSL context info not available for peer verify!");
    return 0;  // fail connection
  }

  if (ssl->verify_mode != PN_TLS_VERIFY_PEER_NAME) return preverify_ok;
  if (!ssl->peer_hostname) {
    ssl_log(NULL, PN_LEVEL_ERROR, "Error: configuration error: PN_TLS_VERIFY_PEER_NAME configured, but no peer hostname set!");
    return 0;  // fail connection
  }

  ssl_log(NULL, PN_LEVEL_TRACE, "Checking identifying name in peer cert against '%s'", ssl->peer_hostname);

  bool matched = false;

  /* first check any SubjectAltName entries, as per RFC2818 */
  GENERAL_NAMES *sans = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (sans) {
    int name_ct = sk_GENERAL_NAME_num( sans );
    int i;
    for (i = 0; !matched && i < name_ct; ++i) {
      GENERAL_NAME *name = sk_GENERAL_NAME_value( sans, i );
      if (name->type == GEN_DNS) {
        ASN1_STRING *asn1 = name->d.dNSName;
        if (asn1 && asn1->data && asn1->length) {
          unsigned char *str;
          int len = ASN1_STRING_to_UTF8( &str, asn1 );
          if (len >= 0) {
            ssl_log(NULL, PN_LEVEL_TRACE, "SubjectAltName (dns) from peer cert = '%.*s'", len, str );
            matched = match_dns_pattern( ssl->peer_hostname, (const char *)str, len );
            OPENSSL_free( str );
          }
        }
      }
    }
    GENERAL_NAMES_free( sans );
  }

  /* if no general names match, try the CommonName from the subject */
  X509_NAME *name = X509_get_subject_name(cert);
  int i = -1;
  while (!matched && (i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0) {
    X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, i);
    ASN1_STRING *name_asn1 = X509_NAME_ENTRY_get_data(ne);
    if (name_asn1) {
      unsigned char *str;
      int len = ASN1_STRING_to_UTF8( &str, name_asn1);
      if (len >= 0) {
        ssl_log(NULL, PN_LEVEL_TRACE, "commonName from peer cert = '%.*s'", len, str);
        matched = match_dns_pattern( ssl->peer_hostname, (const char *)str, len );
        OPENSSL_free(str);
      }
    }
  }

  if (!matched) {
    ssl_log(NULL, PN_LEVEL_ERROR, "Error: no name matching %s found in peer cert - rejecting handshake.",
            ssl->peer_hostname);
    preverify_ok = 0;
#ifdef X509_V_ERR_APPLICATION_VERIFICATION
    X509_STORE_CTX_set_error( ctx, X509_V_ERR_APPLICATION_VERIFICATION );
#endif
  } else {
    ssl_log(NULL, PN_LEVEL_TRACE, "Name from peer cert matched - peer is valid.");
  }
  return preverify_ok;
}

// This was introduced in v1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
  dh->p = p;
  dh->q = q;
  dh->g = g;
  return 1;
}
#endif

// this code was generated using the command:
// "openssl dhparam -C -2 2048"
static DH *get_dh2048(void)
{
  static const unsigned char dhp_2048[]={
    0xAE,0xF7,0xE9,0x66,0x26,0x7A,0xAC,0x0A,0x6F,0x1E,0xCD,0x81,
    0xBD,0x0A,0x10,0x7E,0xFA,0x2C,0xF5,0x2D,0x98,0xD4,0xE7,0xD9,
    0xE4,0x04,0x8B,0x06,0x85,0xF2,0x0B,0xA3,0x90,0x15,0x56,0x0C,
    0x8B,0xBE,0xF8,0x48,0xBB,0x29,0x63,0x75,0x12,0x48,0x9D,0x7E,
    0x7C,0x24,0xB4,0x3A,0x38,0x7E,0x97,0x3C,0x77,0x95,0xB0,0xA2,
    0x72,0xB6,0xE9,0xD8,0xB8,0xFA,0x09,0x1B,0xDC,0xB3,0x80,0x6E,
    0x32,0x0A,0xDA,0xBB,0xE8,0x43,0x88,0x5B,0xAB,0xC3,0xB2,0x44,
    0xE1,0x95,0x85,0x0A,0x0D,0x13,0xE2,0x02,0x1E,0x96,0x44,0xCF,
    0xA0,0xD8,0x46,0x32,0x68,0x63,0x7F,0x68,0xB3,0x37,0x52,0xCE,
    0x3A,0x4E,0x48,0x08,0x7F,0xD5,0x53,0x00,0x59,0xA8,0x2C,0xCB,
    0x51,0x64,0x3D,0x5F,0xEF,0x0E,0x5F,0xE6,0xAF,0xD9,0x1E,0xA2,
    0x35,0x64,0x37,0xD7,0x4C,0xC9,0x24,0xFD,0x2F,0x75,0xBB,0x3A,
    0x15,0x82,0x76,0x4D,0xC2,0x8B,0x1E,0xB9,0x4B,0xA1,0x33,0xCF,
    0xAA,0x3B,0x7C,0xC2,0x50,0x60,0x6F,0x45,0x69,0xD3,0x6B,0x88,
    0x34,0x9B,0xE4,0xF8,0xC6,0xC7,0x5F,0x10,0xA1,0xBA,0x01,0x8C,
    0xDA,0xD1,0xA3,0x59,0x9C,0x97,0xEA,0xC3,0xF6,0x02,0x55,0x5C,
    0x92,0x1A,0x39,0x67,0x17,0xE2,0x9B,0x27,0x8D,0xE8,0x5C,0xE9,
    0xA5,0x94,0xBB,0x7E,0x16,0x6F,0x53,0x5A,0x6D,0xD8,0x03,0xC2,
    0xAC,0x7A,0xCD,0x22,0x98,0x8E,0x33,0x2A,0xDE,0xAB,0x12,0xC0,
    0x0B,0x7C,0x0C,0x20,0x70,0xD9,0x0B,0xAE,0x0B,0x2F,0x20,0x9B,
    0xA4,0xED,0xFD,0x49,0x0B,0xE3,0x4A,0xF6,0x28,0xB3,0x98,0xB0,
    0x23,0x1C,0x09,0x33,
  };
  static const unsigned char dhg_2048[]={
    0x02,
  };
  DH *dh = DH_new();
  BIGNUM *dhp_bn, *dhg_bn;

  if (dh == NULL)
    return NULL;
  dhp_bn = BN_bin2bn(dhp_2048, sizeof (dhp_2048), NULL);
  dhg_bn = BN_bin2bn(dhg_2048, sizeof (dhg_2048), NULL);
  if (dhp_bn == NULL || dhg_bn == NULL
      || !DH_set0_pqg(dh, dhp_bn, NULL, dhg_bn)) {
    DH_free(dh);
    BN_free(dhp_bn);
    BN_free(dhg_bn);
    return NULL;
  }
  return dh;
}

typedef struct {
  char *id;
  SSL_SESSION *session;
} ssl_cache_data;

#define SSL_CACHE_SIZE 4
static int ssl_cache_ptr = 0;
static ssl_cache_data ssl_cache[SSL_CACHE_SIZE];

static void ssn_init(void) {
  ssl_cache_data s = {NULL, NULL};
  for (int i=0; i<SSL_CACHE_SIZE; i++) {
    ssl_cache[i] = s;
  }
}

static void ssn_restore(pn_tls_t *ssl) {
  if (!ssl->session_id) return;
  for (int i = ssl_cache_ptr;;) {
    i = (i==0) ? SSL_CACHE_SIZE-1 : i-1;
    if (ssl_cache[i].id == NULL) return;
    if (strcmp(ssl_cache[i].id, ssl->session_id) == 0) {
      ssl_log( NULL, PN_LEVEL_TRACE, "Restoring previous session id=%s", ssl->session_id );
      int rc = SSL_set_session( ssl->ssl, ssl_cache[i].session );
      if (rc != 1) {
        ssl_log( NULL, PN_LEVEL_WARNING, "Session restore failed, id=%s", ssl->session_id );
      }
      return;
    }
    if (i == ssl_cache_ptr) return;
  }
}

#ifdef laterZZZ
static void ssn_save(pn_tls_t *ssl) {
  if (ssl->session_id) {
    // Attach the session id to the session before we close the connection
    // So that if we find it in the cache later we can figure out the session id
    SSL_SESSION *session = SSL_get1_session( ssl->ssl );
    if (session) {
      ssl_log(NULL, PN_LEVEL_TRACE, "Saving SSL session as %s", ssl->session_id );
      // If we're overwriting a value, need to free it
      free(ssl_cache[ssl_cache_ptr].id);
      if (ssl_cache[ssl_cache_ptr].session) SSL_SESSION_free(ssl_cache[ssl_cache_ptr].session);

      char *id = pni_strdup( ssl->session_id );
      ssl_cache_data s = {id, session};
      ssl_cache[ssl_cache_ptr++] = s;
      if (ssl_cache_ptr==SSL_CACHE_SIZE) ssl_cache_ptr = 0;
    }
  }
}
#endif

/** Public API - visible to application code */

bool pn_tls_present(void)
{
  return true;
}

static bool ensure_initialized(void);

static bool pni_init_ssl_domain( pn_tls_domain_t * domain, pn_tls_mode_t mode )
{
  if (!ensure_initialized()) {
      ssl_log_error("Unable to initialize OpenSSL library");
      return false;
  }

  domain->ref_count = 1;
  domain->mode = mode;

  // enable all supported protocol versions, then explicitly disable the
  // known vulnerable ones.  This should allow us to use the latest version
  // of the TLS standard that the installed library supports.
  switch(mode) {
   case PN_TLS_MODE_CLIENT:
    domain->ctx = SSL_CTX_new(SSLv23_client_method()); // and TLSv1+
    if (!domain->ctx) {
      ssl_log_error("Unable to initialize OpenSSL context.");
      return false;
    }
    SSL_CTX_set_session_cache_mode(domain->ctx, SSL_SESS_CACHE_CLIENT);

    // By default, require peer name verification - this is a safe default
    if (pn_tls_domain_set_peer_authentication( domain, PN_TLS_VERIFY_PEER_NAME, NULL )) {
      SSL_CTX_free(domain->ctx);
      return false;
    }
    break;

   case PN_TLS_MODE_SERVER:
    domain->ctx = SSL_CTX_new(SSLv23_server_method()); // and TLSv1+
    if (!domain->ctx) {
      ssl_log_error("Unable to initialize OpenSSL context.");
      return false;
    }
    // By default, allow anonymous ciphers and do no authentication so certificates are
    // not required 'out of the box'; authenticating the client can be done by SASL.
    if (pn_tls_domain_set_peer_authentication( domain, PN_TLS_ANONYMOUS_PEER, NULL )) {
      SSL_CTX_free(domain->ctx);
      return false;
    }
    break;

   default:
    ssl_log(NULL, PN_LEVEL_ERROR, "Invalid value for pn_tls_mode_t: %d", mode);
    return false;
  }

  // By default set up system default certificates
  if (!SSL_CTX_set_default_verify_paths(domain->ctx)){
    ssl_log_error("Failed to set default certificate paths");
    SSL_CTX_free(domain->ctx);
    return false;
  };

  const long reject_insecure =
      SSL_OP_NO_SSLv2
    | SSL_OP_NO_SSLv3
    // Mitigate the CRIME vulnerability
#   ifdef SSL_OP_NO_COMPRESSION
    | SSL_OP_NO_COMPRESSION
#   endif
    ;
  SSL_CTX_set_options(domain->ctx, reject_insecure);

# ifdef SSL_SECOP_PEER
  domain->default_seclevel = SSL_CTX_get_security_level(domain->ctx);
# endif

  DH *dh = get_dh2048();
  if (dh) {
    SSL_CTX_set_tmp_dh(domain->ctx, dh);
    DH_free(dh);
    SSL_CTX_set_options(domain->ctx, SSL_OP_SINGLE_DH_USE);
  }

  return true;
}

pn_tls_domain_t *pn_tls_domain( pn_tls_mode_t mode )
{
  pn_tls_domain_t *domain = (pn_tls_domain_t *) calloc(1, sizeof(pn_tls_domain_t));
  if (!domain) return NULL;

  if (!pni_init_ssl_domain(domain, mode)) {
    free(domain);
    return NULL;
  }

  return domain;
}

void pn_tls_domain_free( pn_tls_domain_t *domain )
{
  if (--domain->ref_count == 0) {

    SSL_CTX_free(domain->ctx);
    free(domain->keyfile_pw);
    free(domain->trusted_CAs);
    free(domain->ciphers);
    free(domain);
  }
}


int pn_tls_domain_set_credentials( pn_tls_domain_t *domain,
                                   const char *certificate_file,
                                   const char *private_key_file,
                                   const char *password)
{
  if (!domain || !domain->ctx) return -1;

  if (SSL_CTX_use_certificate_chain_file(domain->ctx, certificate_file) != 1) {
    ssl_log_error("SSL_CTX_use_certificate_chain_file( %s ) failed", certificate_file);
    return -3;
  }

  if (password) {
    domain->keyfile_pw = pni_strdup(password);  // @todo: obfuscate me!!!
    SSL_CTX_set_default_passwd_cb(domain->ctx, keyfile_pw_cb);
    SSL_CTX_set_default_passwd_cb_userdata(domain->ctx, domain->keyfile_pw);
  }

  if (SSL_CTX_use_PrivateKey_file(domain->ctx, private_key_file, SSL_FILETYPE_PEM) != 1) {
    ssl_log_error("SSL_CTX_use_PrivateKey_file( %s ) failed", private_key_file);
    return -4;
  }

  if (SSL_CTX_check_private_key(domain->ctx) != 1) {
    ssl_log_error("The key file %s is not consistent with the certificate %s",
                  private_key_file, certificate_file);
    return -5;
  }

  domain->has_certificate = true;

  // bug in older versions of OpenSSL: servers may request client cert even if anonymous
  // cipher was negotiated.  TLSv1 will reject such a request.  Hack: once a cert is
  // configured, allow only authenticated ciphers.
  if (!domain->ciphers && !SSL_CTX_set_cipher_list( domain->ctx, CIPHERS_AUTHENTICATE )) {
    ssl_log_error("Failed to set cipher list to %s", CIPHERS_AUTHENTICATE);
    return -6;
  }

  return 0;
}

int pn_tls_domain_set_ciphers(pn_tls_domain_t *domain, const char *ciphers)
{
  if (!SSL_CTX_set_cipher_list(domain->ctx, ciphers)) {
    ssl_log_error("Failed to set cipher list to %s", ciphers);
    return -6;
  }
  if (domain->ciphers) free(domain->ciphers);
  domain->ciphers = pni_strdup(ciphers);
  return 0;
}

int pn_tls_domain_set_protocols(pn_tls_domain_t *domain, const char *protocols)
{
  static const struct {
    const char *name;
    const long option;
  } protocol_options[] =
  {
    {"TLSv1",   SSL_OP_NO_TLSv1},
    {"TLSv1.1", SSL_OP_NO_TLSv1_1},
    {"TLSv1.2", SSL_OP_NO_TLSv1_2},
#ifdef SSL_OP_NO_TLSv1_3
    {"TLSv1.3", SSL_OP_NO_TLSv1_3},
#endif
  };
  static const char seps[]    = " ,;";
  static const long all_prots =
    SSL_OP_NO_TLSv1
    | SSL_OP_NO_TLSv1_1
    | SSL_OP_NO_TLSv1_2
#ifdef SSL_OP_NO_TLSv1_3
    | SSL_OP_NO_TLSv1_3
#endif
    ;

  // Start with all protocols turned off
  long options = all_prots;

  // For each separate token in protocols
  const char *token = protocols;
  while (*token!=0) {
    // Find next separator
    size_t tsize = strcspn(token, seps);
    while (tsize==0 && *token!=0) {
      ++token;
      tsize = strcspn(token, seps);
    }
    if (tsize==0) break; // No more tokens

    // Linear search the possibilities for the option to set
    for (size_t i = 0; i<sizeof(protocol_options)/sizeof(*protocol_options); ++i) {
      if (strncmp(token, protocol_options[i].name, tsize)==0) {
        options &= ~protocol_options[i].option;
        goto found;
      }
    }
    // Didn't find any match - error
    return PN_ARG_ERR;

found:
    token += tsize;
  }

  // Check if we found anything
  if (options==all_prots) return PN_ARG_ERR;

  SSL_CTX_clear_options(domain->ctx, all_prots);
  SSL_CTX_set_options(domain->ctx, options);
  return 0;
}

int pn_tls_domain_set_trusted_ca_db(pn_tls_domain_t *domain,
                                    const char *certificate_db)
{
  if (!domain) return -1;

  // certificates can be either a file or a directory, which determines how it is passed
  // to SSL_CTX_load_verify_locations()
  struct stat sbuf;
  if (stat( certificate_db, &sbuf ) != 0) {
    ssl_log(NULL, PN_LEVEL_ERROR, "stat(%s) failed: %s", certificate_db, strerror(errno));
    return -1;
  }

  const char *file;
  const char *dir;
  if (S_ISDIR(sbuf.st_mode)) {
    dir = certificate_db;
    file = NULL;
  } else {
    dir = NULL;
    file = certificate_db;
  }

  if (SSL_CTX_load_verify_locations( domain->ctx, file, dir ) != 1) {
    ssl_log_error("SSL_CTX_load_verify_locations( %s ) failed", certificate_db);
    return -1;
  }

  return 0;
}


int pn_tls_domain_set_peer_authentication(pn_tls_domain_t *domain,
                                          const pn_tls_verify_mode_t mode,
                                          const char *trusted_CAs)
{
  if (!domain) return -1;

  switch (mode) {
   case PN_TLS_VERIFY_PEER:
   case PN_TLS_VERIFY_PEER_NAME:

#ifdef SSL_SECOP_PEER
    SSL_CTX_set_security_level(domain->ctx, domain->default_seclevel);
#endif

    if (domain->mode == PN_TLS_MODE_SERVER) {
      // openssl requires that server connections supply a list of trusted CAs which is
      // sent to the client
      if (!trusted_CAs) {
        ssl_log(NULL, PN_LEVEL_ERROR, "Error: a list of trusted CAs must be provided.");
        return -1;
      }
      if (!domain->has_certificate) {
        ssl_log(NULL, PN_LEVEL_ERROR, "Error: Server cannot verify peer without configuring a certificate, use pn_tls_domain_set_credentials()");
        return -1;
      }

      if (domain->trusted_CAs) free(domain->trusted_CAs);
      domain->trusted_CAs = pni_strdup( trusted_CAs );
      STACK_OF(X509_NAME) *cert_names;
      cert_names = SSL_load_client_CA_file( domain->trusted_CAs );
      if (cert_names != NULL)
        SSL_CTX_set_client_CA_list(domain->ctx, cert_names);
      else {
        ssl_log(NULL, PN_LEVEL_ERROR, "Error: Unable to process file of trusted CAs: %s", trusted_CAs);
        return -1;
      }
    }

    SSL_CTX_set_verify( domain->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                        verify_callback);
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(domain->ctx, 1);
#endif

    // A bit of a hack - If we asked for peer verification then disallow anonymous ciphers
    // A much more robust thing would be to ensure that we actually have a peer certificate
    // when we've finished the SSL handshake
    if (!domain->ciphers && !SSL_CTX_set_cipher_list( domain->ctx, CIPHERS_AUTHENTICATE )) {
      ssl_log_error("Failed to set cipher list to %s", CIPHERS_AUTHENTICATE);
      return -1;
    }
    break;

   case PN_TLS_ANONYMOUS_PEER:   // hippie free love mode... :)
#ifdef SSL_SECOP_PEER
    // Must use lowest OpenSSL security level to enable anonymous ciphers.
    SSL_CTX_set_security_level(domain->ctx, 0);
#endif
    SSL_CTX_set_verify( domain->ctx, SSL_VERIFY_NONE, NULL );
    // Only allow anonymous ciphers if we allow anonymous peers
    if (!domain->ciphers && !SSL_CTX_set_cipher_list( domain->ctx, CIPHERS_ANONYMOUS )) {
      ssl_log_error("Failed to set cipher list to %s", CIPHERS_ANONYMOUS);
      return -1;
    }
    break;

   default:
    ssl_log(NULL, PN_LEVEL_ERROR, "Invalid peer authentication mode given." );
    return -1;
  }

  domain->verify_mode = mode;
  return 0;
}

void pn_tls_free(pn_tls_t *ssl)
{
  if (!ssl) return;
  ssl_log(NULL, PN_LEVEL_TRACE, "SSL socket freed." );
  release_ssl_socket( ssl );
  if (ssl->session_id) free((void *)ssl->session_id);
  if (ssl->peer_hostname) free((void *)ssl->peer_hostname);
  if (ssl->q4dec_bytes) free((void *)ssl->q4dec_bytes);
  if (ssl->q4enc_bytes) free((void *)ssl->q4enc_bytes);
  if (ssl->subject) free(ssl->subject);
  if (ssl->peer_certificate) X509_free(ssl->peer_certificate);
  free(ssl);
}

static int pni_tls_init(pn_tls_t *ssl, pn_tls_domain_t *domain, const char *session_id)
{
  if (!ssl) return -1;

  ssl->mode = domain->mode;
  ssl->verify_mode = domain->verify_mode;

  if (session_id && domain->mode == PN_TLS_MODE_CLIENT)
    ssl->session_id = pni_strdup(session_id);

  // ZZZ allow unsecured?
  // If SSL doesn't specifically allow skipping encryption, require SSL
  // TODO: This is a probably a stop-gap until allow_unsecured is removed
  //  if (!domain->allow_unsecured) transport->encryption_required = true;

  return init_ssl_socket(ssl, domain);
}

pn_tls_t *pn_tls(pn_tls_domain_t *domain, const char* hostname, const char *session_id) {
  if (!domain) return NULL;
  if (domain->mode == PN_TLS_MODE_SERVER && (hostname || session_id))
    return NULL;
  pn_tls_t *tls = (pn_tls_t *) calloc(1, sizeof(pn_tls_t));
  if (!tls) return NULL;

  tls->q4enc_capacity = JRSIZE;
  tls->q4dec_capacity =  JRSIZE;
  tls->q4enc_bytes = (char *)malloc(tls->q4enc_capacity);
  if (!tls->q4enc_bytes) {
    pn_tls_free(tls);
    return NULL;
  }
  tls->q4dec_bytes =  (char *)malloc(tls->q4dec_capacity);
  if (!tls->q4dec_bytes) {
    pn_tls_free(tls);
    return NULL;
  }

  if (hostname && *hostname) {
    // ZZZ hostname illegal if session_id?
    pn_tls_set_peer_hostname(tls, hostname);
  }

  if (pni_tls_init(tls, domain, session_id) < 0) {
    pn_tls_free(tls);
    return(NULL);
  }
  return tls;
}

int pn_tls_domain_allow_unsecured_client(pn_tls_domain_t *domain)
{
  if (!domain) return -1;
  if (domain->mode != PN_TLS_MODE_SERVER) {
    ssl_log(NULL, PN_LEVEL_ERROR, "Cannot permit unsecured clients - not a server.");
    return -1;
  }
  domain->allow_unsecured = true;
  return 0;
}

int pn_tls_get_ssf(pn_tls_t *ssl)
{
  const SSL_CIPHER *c;

  if (ssl && ssl->ssl && (c = SSL_get_current_cipher( ssl->ssl ))) {
    return SSL_CIPHER_get_bits(c, NULL);
  }
  return 0;
}

bool pn_tls_get_cipher_name(pn_tls_t *ssl, char *buffer, size_t size )
{
  const SSL_CIPHER *c;

  if (buffer && size) *buffer = '\0';
  if (ssl->ssl && (c = SSL_get_current_cipher( ssl->ssl ))) {
    const char *v = SSL_CIPHER_get_name(c);
    if (buffer && v) {
      snprintf( buffer, size, "%s", v );
      return true;
    }
  }
  return false;
}

bool pn_tls_get_protocol_name(pn_tls_t *ssl, char *buffer, size_t size )
{
  const SSL_CIPHER *c;

  if (buffer && size) *buffer = '\0';
  if (ssl->ssl && (c = SSL_get_current_cipher( ssl->ssl ))) {
    const char *v = SSL_CIPHER_get_version(c);
    if (buffer && v) {
      snprintf( buffer, size, "%s", v );
      return true;
    }
  }
  return false;
}


/** Private: */

static int keyfile_pw_cb(char *buf, int size, int rwflag, void *userdata)
{
  strncpy(buf, (char *)userdata, size);   // @todo: un-obfuscate me!!!
  buf[size - 1] = '\0';
  return(strlen(buf));
}


#ifdef laterZZZ
static int start_ssl_shutdown(pn_tls_t *ssl)
{
  if (!ssl->ssl_shutdown) {
    ssl_log(NULL, PN_LEVEL_TRACE, "Shutting down SSL connection...");
    ssn_save(ssl);
    ssl->ssl_shutdown = true;
    BIO_ssl_shutdown( ssl->bio_ssl );
  }
  return 0;
}
#endif

//////// SSL Connections



static int init_ssl_socket(pn_tls_t *ssl, pn_tls_domain_t *domain)
{
  if (ssl->ssl) return 0;
  if (!domain) return -1;

  ssl->ssl = SSL_new(domain->ctx);
  if (!ssl->ssl) {
    ssl_log(NULL, PN_LEVEL_ERROR, "SSL socket setup failure." );
    ssl_log_flush(NULL, PN_LEVEL_ERROR);
    return -1;
  }

  // store backpointer
  SSL_set_ex_data(ssl->ssl, tls_ex_data_index, ssl);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if (ssl->peer_hostname && ssl->mode == PN_TLS_MODE_CLIENT) {
    SSL_set_tlsext_host_name(ssl->ssl, ssl->peer_hostname);
  }
#endif

  // restore session, if available
  ssn_restore(ssl);

  // now layer a BIO over the SSL socket
  ssl->bio_ssl = BIO_new(BIO_f_ssl());
  if (!ssl->bio_ssl) {
    ssl_log(NULL, PN_LEVEL_ERROR, "BIO setup failure." );
    return -1;
  }
  (void)BIO_set_ssl(ssl->bio_ssl, ssl->ssl, BIO_NOCLOSE);

  // create the "lower" BIO "pipe", and attach it below the SSL layer
  if (!BIO_new_bio_pair(&ssl->bio_ssl_io, 0, &ssl->bio_net_io, 0)) {
    ssl_log(NULL, PN_LEVEL_ERROR, "BIO setup failure." );
    return -1;
  }
  SSL_set_bio(ssl->ssl, ssl->bio_ssl_io, ssl->bio_ssl_io);

  if (ssl->mode == PN_TLS_MODE_SERVER) {
    SSL_set_accept_state(ssl->ssl);
    BIO_set_ssl_mode(ssl->bio_ssl, 0);  // server mode
    ssl_log( NULL, PN_LEVEL_TRACE, "Server SSL socket created." );
  } else {      // client mode
    SSL_set_connect_state(ssl->ssl);
    BIO_set_ssl_mode(ssl->bio_ssl, 1);  // client mode
    ssl_log( NULL, PN_LEVEL_TRACE, "Client SSL socket created." );
    // track the client hello
    ssl->bio_encrypted = BIO_ctrl_pending(ssl->bio_net_io);
  }
  ssl->subject = NULL;
  ssl->peer_certificate = NULL;
  return 0;
}

static void release_ssl_socket(pn_tls_t *ssl)
{
  if (ssl->bio_ssl) BIO_free(ssl->bio_ssl);
  if (ssl->ssl) {
    SSL_free(ssl->ssl);       // will free bio_ssl_io
  } else {
    if (ssl->bio_ssl_io) BIO_free(ssl->bio_ssl_io);
  }
  if (ssl->bio_net_io) BIO_free(ssl->bio_net_io);
  ssl->bio_ssl = NULL;
  ssl->bio_ssl_io = NULL;
  ssl->bio_net_io = NULL;
  ssl->ssl = NULL;
}



pn_tls_resume_status_t pn_tls_resume_status(pn_tls_t *ssl)
{
  if (!ssl || !ssl->ssl) return PN_TLS_RESUME_UNKNOWN;
  switch (SSL_session_reused( ssl->ssl )) {
   case 0: return PN_TLS_RESUME_NEW;
   case 1: return PN_TLS_RESUME_REUSED;
   default: break;
  }
  return PN_TLS_RESUME_UNKNOWN;
}


int pn_tls_set_peer_hostname(pn_tls_t *ssl, const char *hostname)
{
  if (!ssl) return -1;

  if (ssl->peer_hostname) free((void *)ssl->peer_hostname);
  ssl->peer_hostname = NULL;
  if (hostname) {
    ssl->peer_hostname = pni_strdup(hostname);
    if (!ssl->peer_hostname) return -2;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (ssl->ssl && ssl->mode == PN_TLS_MODE_CLIENT) {
      SSL_set_tlsext_host_name(ssl->ssl, ssl->peer_hostname);
    }
#endif
  }
  return 0;
}

int pn_tls_get_peer_hostname(pn_tls_t *ssl, char *hostname, size_t *bufsize)
{
  if (!ssl) return -1;
  if (!ssl->peer_hostname) {
    *bufsize = 0;
    if (hostname) *hostname = '\0';
    return 0;
  }
  unsigned len = strlen(ssl->peer_hostname);
  if (hostname) {
    if (len >= *bufsize) return -1;
    strcpy( hostname, ssl->peer_hostname );
  }
  *bufsize = len;
  return 0;
}

static X509 *get_peer_certificate(pn_tls_t *ssl)
{
  // Cache for multiple use and final X509_free
  if (!ssl->peer_certificate && ssl->ssl) {
    ssl->peer_certificate = SSL_get_peer_certificate(ssl->ssl);
    // May still be NULL depending on timing or type of SSL connection
  }
  return ssl->peer_certificate;
}

const char* pn_tls_get_remote_subject(pn_tls_t *ssl)
{
  if (!ssl || !ssl->ssl) return NULL;
  if (!ssl->subject) {
    X509 *cert = get_peer_certificate(ssl);
    if (!cert) return NULL;
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject) return NULL;

    BIO *out = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(out, subject, 0, XN_FLAG_RFC2253);
    int len = BIO_number_written(out);
    ssl->subject = (char*) malloc(len+1);
    ssl->subject[len] = 0;
    BIO_read(out, ssl->subject, len);
    BIO_free(out);
  }
  return ssl->subject;
}

int pn_tls_get_cert_fingerprint(pn_tls_t *ssl, char *fingerprint, size_t fingerprint_length, pn_tls_hash_alg hash_alg)
{
  const char *digest_name = NULL;
  size_t min_required_length;

  // old versions of python expect fingerprint to contain a valid string on
  // return from this function
  fingerprint[0] = 0;

  // Assign the correct digest_name value based on the enum values.
  switch (hash_alg) {
   case PN_TLS_SHA1 :
    min_required_length = 41; // 40 hex characters + 1 '\0' character
    digest_name = "sha1";
    break;
   case PN_TLS_SHA256 :
    min_required_length = 65; // 64 hex characters + 1 '\0' character
    digest_name = "sha256";
    break;
   case PN_TLS_SHA512 :
    min_required_length = 129; // 128 hex characters + 1 '\0' character
    digest_name = "sha512";
    break;
   case PN_TLS_MD5 :
    min_required_length = 33; // 32 hex characters + 1 '\0' character
    digest_name = "md5";
    break;
   default:
    ssl_log_error("Unknown or unhandled hash algorithm %i ", hash_alg);
    return PN_ERR;

  }

  if(fingerprint_length < min_required_length) {
    ssl_log_error("Insufficient fingerprint_length %" PN_ZU ". fingerprint_length must be %" PN_ZU " or above for %s digest",
                  fingerprint_length, min_required_length, digest_name);
    return PN_ERR;
  }

  const EVP_MD  *digest = EVP_get_digestbyname(digest_name);

  X509 *cert = get_peer_certificate(ssl);

  if(cert) {
    unsigned int len;

    unsigned char bytes[64]; // sha512 uses 64 octets, we will use that as the maximum.

    if (X509_digest(cert, digest, bytes, &len) != 1) {
      ssl_log_error("Failed to extract X509 digest");
      return PN_ERR;
    }

    char *cursor = fingerprint;

    for (size_t i=0; i<len ; i++) {
      cursor +=  snprintf((char *)cursor, fingerprint_length, "%02x", bytes[i]);
      fingerprint_length = fingerprint_length - 2;
    }

    return PN_OK;
  }
  else {
    ssl_log_error("No certificate is available yet ");
    return PN_ERR;
  }

  return 0;
}


const char* pn_tls_get_remote_subject_subfield(pn_tls_t *ssl, pn_tls_cert_subject_subfield field)
{
  int openssl_field = 0;

  // Assign openssl internal representations of field values to openssl_field
  switch (field) {
   case PN_TLS_CERT_SUBJECT_COUNTRY_NAME :
    openssl_field = NID_countryName;
    break;
   case PN_TLS_CERT_SUBJECT_STATE_OR_PROVINCE :
    openssl_field = NID_stateOrProvinceName;
    break;
   case PN_TLS_CERT_SUBJECT_CITY_OR_LOCALITY :
    openssl_field = NID_localityName;
    break;
   case PN_TLS_CERT_SUBJECT_ORGANIZATION_NAME :
    openssl_field = NID_organizationName;
    break;
   case PN_TLS_CERT_SUBJECT_ORGANIZATION_UNIT :
    openssl_field = NID_organizationalUnitName;
    break;
   case PN_TLS_CERT_SUBJECT_COMMON_NAME :
    openssl_field = NID_commonName;
    break;
   default:
    ssl_log_error("Unknown or unhandled certificate subject subfield %i", field);
    return NULL;
  }

  X509 *cert = get_peer_certificate(ssl);
  if (!cert) return NULL;

  X509_NAME *subject_name = X509_get_subject_name(cert);

  // TODO (gmurthy) - A server side cert subject field can have more than one common name like this - Subject: CN=www.domain1.com, CN=www.domain2.com, see https://bugzilla.mozilla.org/show_bug.cgi?id=380656
  // For now, we will only return the first common name if there is more than one common name in the cert
  int index = X509_NAME_get_index_by_NID(subject_name, openssl_field, -1);

  if (index > -1) {
    X509_NAME_ENTRY *ne = X509_NAME_get_entry(subject_name, index);
    if(ne) {
      ASN1_STRING *name_asn1 = X509_NAME_ENTRY_get_data(ne);
      return (char *) name_asn1->data;
    }
  }

  return NULL;
}


size_t pn_tls_encrypted_pending(pn_tls_t *ssl)
{
  if (ssl && ssl->bio_net_io)
    return BIO_ctrl_pending(ssl->bio_net_io);
  return 0;
}

size_t pn_tls_decrypted_pending(pn_tls_t *ssl)
{
  if (ssl && ssl->bio_ssl)
    return BIO_ctrl_pending(ssl->bio_ssl);
  return 0;
}

static inline uint32_t room(pn_raw_buffer_t const *rb) {
  if (rb)
    return rb->capacity - (rb->offset + rb->size);
  return 0;
}

static inline size_t size_min(uint32_t a, uint32_t b) {
  return (a <= b) ? a : b;
}

ssize_t pn_tls_encrypt(pn_tls_t *tls, pn_raw_buffer_t const *unencrypted_buffers_in, size_t in_count, pn_raw_buffer_t *encrypted_destination_bufs, size_t dest_count, size_t *dest_written) {
  size_t inbufs_processed = 0;
  size_t outbufs_processed = 0;
  bool input_read = false;
  if (!tls || !dest_count) return 0;
  pn_raw_buffer_t *inbufp;
  pn_raw_buffer_t inbuf;
  if (tls->q4enc_size) {
    inbufp = &inbuf;
    inbufp->bytes = tls->q4enc_bytes;
    inbufp->size = inbufp->capacity = tls->q4enc_size;
    inbufp->context = 0;
    inbufp->offset = 0;
  } else if (in_count == 0) {
    inbufp = NULL;
  } else {
    inbufp = &inbuf;
    inbuf = unencrypted_buffers_in[0];
    in_count--;
  }
  pn_raw_buffer_t *outbufp = dest_count ? &encrypted_destination_bufs[0] : NULL;
  bool outbuf_written = false;

  while (true) {
    // Extract encrypted data from BIO
    // bio_encrypted set for client on init?
    if (tls->bio_encrypted) {
      size_t n = size_min(tls->bio_encrypted, room(outbufp));
      if (n) {
        int rcount = BIO_read(tls->bio_net_io, outbufp->bytes + outbufp->offset + outbufp->size, n);
        if (rcount > 0) {
          outbufp->size += rcount;
          if (!outbuf_written) {
            outbuf_written = true;
            outbufs_processed++;
          }
          if (room(outbufp) == 0) {
            if (--dest_count) {
              outbufp++;
              outbuf_written = false;
            }
            else
              outbufp = NULL; // No more output buffers
          }
        }
      }
    }
    
    // Insert unencrypted data into BIO
    if (inbufp) {
      size_t n = size_min(inbufp->size, JRSIZE);
      if (n) {
        int wcount = BIO_write(tls->bio_ssl, inbufp->bytes + inbufp->offset, n);
        if (wcount > 0) {
          inbufp->offset += wcount;
          inbufp->size -= wcount;
          if (!input_read) {
            input_read = true;
            if (inbufp->bytes != tls->q4enc_bytes)
              inbufs_processed++;
          }
          if (inbufp->size == 0) {
            input_read = false;
            if (inbufs_processed < in_count)
              inbuf = unencrypted_buffers_in[inbufs_processed];
            else
              inbufp = NULL;
          }
        }
      }
    }

    tls->bio_encrypted = BIO_ctrl_pending(tls->bio_net_io);
    // Done if outbufs exhausted or all inbufs decrypted
    if (!outbufp || (!inbufp && !tls->bio_encrypted))
      break;
  }

  // Straggler bytes from partially consumed input buffer?
  if (inbufp && input_read) {
    assert(inbufp->size > 0);
    if (tls->q4enc_capacity < inbufp->size) {
      tls->q4enc_bytes = (char *) realloc(tls->q4enc_bytes, inbufp->size);
      tls->q4enc_capacity = inbufp->size;
    }
    memmove(tls->q4enc_bytes, inbufp->bytes + inbufp->offset, inbufp->size);
    tls->q4enc_size = inbufp->size;
  }

  *dest_written = outbufs_processed;
  return inbufs_processed;
}

ssize_t pn_tls_decrypt(pn_tls_t *tls, pn_raw_buffer_t const *encrypted_buffers_in, size_t in_count, pn_raw_buffer_t *decrypted_destination_bufs, size_t dest_count, size_t *dest_written) {
  size_t inbufs_processed = 0;
  size_t outbufs_processed = 0;
  bool input_read = false;
  if (!tls || !dest_count) return 0;
  pn_raw_buffer_t *inbufp;
  pn_raw_buffer_t inbuf;
  if (tls->q4dec_size) {
    inbufp = &inbuf;
    inbufp->bytes = tls->q4dec_bytes;
    inbufp->size = inbufp->capacity = tls->q4dec_size;
    inbufp->context = 0;
    inbufp->offset = 0;
  } else if (in_count == 0) {
    inbufp = NULL;
  } else {
    inbufp = &inbuf;
    inbuf = encrypted_buffers_in[0];
    in_count--;
  }
  pn_raw_buffer_t *outbufp = dest_count ? &decrypted_destination_bufs[0] : NULL;
  bool outbuf_written = false;

  while (true) {
    // Extract decrypted data from BIO
    if (tls->bio_decrypted) {
      size_t n = size_min(tls->bio_decrypted, room(outbufp));
      if (n) {
        int rcount = BIO_read(tls->bio_ssl, outbufp->bytes + outbufp->offset + outbufp->size, n);
        if (rcount > 0) {
          outbufp->size += rcount;
          if (!outbuf_written) {
            outbuf_written = true;
            outbufs_processed++;
          }
          if (room(outbufp) == 0) {
            if (--dest_count) {
              outbufp++;
              outbuf_written = false;
            }
            else
              outbufp = NULL; // No more output buffers
          }
        }
      }
    }
    
    // Insert encrypted data into BIO
    if (inbufp) {
      size_t n = size_min(inbufp->size, JRSIZE);
      if (n) {
        int wcount = BIO_write(tls->bio_net_io, inbufp->bytes + inbufp->offset, n);
        if (wcount > 0) {
          inbufp->offset += wcount;
          inbufp->size -= wcount;
          if (!input_read) {
            input_read = true;
            if (inbufp->bytes != tls->q4dec_bytes)
              inbufs_processed++;
          }
          if (inbufp->size == 0) {
            input_read = false;
            if (inbufs_processed < in_count)
              inbuf = encrypted_buffers_in[inbufs_processed];
            else
              inbufp = NULL;
          }
        }
      }
    }

    tls->bio_decrypted = BIO_ctrl_pending(tls->bio_ssl);
    // Done if outbufs exhausted or all inbufs decrypted
    if (!outbufp || (!inbufp && !tls->bio_decrypted))
      break;
  }

  // Straggler bytes from partially consumed input buffer?
  if (inbufp && input_read) {
    assert(inbufp->size > 0);
    if (tls->q4dec_capacity < inbufp->size) {
      tls->q4dec_bytes = (char *) realloc(tls->q4dec_bytes, inbufp->size);
      tls->q4dec_capacity = inbufp->size;
    }
    memmove(tls->q4dec_bytes, inbufp->bytes + inbufp->offset, inbufp->size);
    tls->q4dec_size = inbufp->size;
  }

  *dest_written = outbufs_processed;
  return inbufs_processed;
}


/* Thread-safe locking and initialization for POSIX and Windows */

static bool init_ok = false;

#ifdef _WIN32

typedef CRITICAL_SECTION pni_mutex_t;
static inline void pni_mutex_init(pni_mutex_t *m) { InitializeCriticalSection(m); }
static inline void pni_mutex_lock(pni_mutex_t *m) { EnterCriticalSection(m); }
static inline void pni_mutex_unlock(pni_mutex_t *m) { LeaveCriticalSection(m); }
static inline unsigned long id_callback(void) { return (unsigned long)GetCurrentThreadId(); }
INIT_ONCE initialize_once = INIT_ONCE_STATIC_INIT;
static inline bool ensure_initialized(void) {
  void* dummy;
  InitOnceExecuteOnce(&initialize_once, &initialize, NULL, &dummy);
  return init_ok;
}

#else  /* POSIX */

#include <pthread.h>

static void initialize(void);

typedef pthread_mutex_t pni_mutex_t;
static inline int pni_mutex_init(pni_mutex_t *m) { return pthread_mutex_init(m, NULL); }
static inline int pni_mutex_lock(pni_mutex_t *m) { return pthread_mutex_lock(m); }
static inline int pni_mutex_unlock(pni_mutex_t *m) { return pthread_mutex_unlock(m); }
static inline unsigned long id_callback(void) { return (unsigned long)pthread_self(); }
static pthread_once_t initialize_once = PTHREAD_ONCE_INIT;
static inline bool ensure_initialized(void) {
  pthread_once(&initialize_once, &initialize);
  return init_ok;
}

#endif

static pni_mutex_t *locks = NULL;     /* Lock array for openssl */

/* Callback function for openssl locking */
static void locking_callback(int mode, int n, const char *file, int line) {
  if(mode & CRYPTO_LOCK)
    pni_mutex_lock(&locks[n]);
  else
    pni_mutex_unlock(&locks[n]);
}

static void initialize(void) {
  int i;
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  tls_ex_data_index = SSL_get_ex_new_index( 0, (void *) "org.apache.qpid.proton.ssl",
                                            NULL, NULL, NULL);
  ssn_init();
  locks = (pni_mutex_t*)malloc(CRYPTO_num_locks() * sizeof(pni_mutex_t));
  if (!locks) return;
  for(i = 0;  i < CRYPTO_num_locks();  i++)
    pni_mutex_init(&locks[i]);
  CRYPTO_set_id_callback(&id_callback);
  CRYPTO_set_locking_callback(&locking_callback);
  /* In recent versions of openssl, the set_callback functions are no-op macros,
     so we need to take steps to stop the compiler complaining about unused functions. */
  (void)&id_callback;
  (void)&locking_callback;
  init_ok = true;
}

/* TODO aconway 2017-10-16: There is no opportunity to clean up the locks as proton has no
   final shut-down call. If it did, we should call this: */
/*
static void shutdown(void) {
ZZZ opportunity here.
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  if(locks)  {
    int i;
    for(i = 0;  i < CRYPTO_num_locks();  i++)
      pni_mutex_destroy(&locks[i]);
    free(locks);
    locks = NULL;
  }
}
*/
