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
 * This file is heavily based on the original Proton SSL layer for
 * AMQP connections and the buffer management logic in
 * raw_connection.c.
 */

enum {
  eresult_buffer_count = 4,
  dresult_buffer_count = 4,
  decrypt_buffer_count = 4,
  encrypt_buffer_count = 4
};

typedef enum {
  buff_empty    = 0,

  buff_decrypt_pending    = 1, // application buffers for decryption
  buff_decrypt_done       = 2,

  buff_encrypt_pending    = 3, // application buffers for encryption
  buff_encrypt_done       = 4,

  buff_eresult_blank       = 5,
  buff_eresult_encrypted   = 6,

  buff_dresult_blank       = 7,
  buff_dresult_decrypted   = 8
} buff_type;


typedef uint16_t buff_ptr; // This is always the index+1 so that 0 can be special

typedef struct pbuffer_t {
  uintptr_t context;
  char *bytes;
  uint32_t capacity;
  uint32_t size;
  uint32_t offset;
  buff_ptr next;
  uint8_t type; // For debugging
} pbuffer_t;



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

// Our internal straggler buffer size.
// TODO: make more robust or (better) switch to a model where the
// TLS session takes ownership of output buffers until released
// to application.  Stay tuned.
#define JRSIZE    (4*1024)

struct pn_tls_t {
  pbuffer_t eresult_buffers[eresult_buffer_count];
  pbuffer_t dresult_buffers[dresult_buffer_count];
  pbuffer_t encrypt_buffers[encrypt_buffer_count];
  pbuffer_t decrypt_buffers[decrypt_buffer_count];

  uint16_t encrypt_buffer_empty_count;
  uint16_t decrypt_buffer_empty_count;
  uint16_t eresult_encrypted_count;
  uint16_t eresult_empty_count;
  uint16_t dresult_decrypted_count;
  uint16_t dresult_empty_count;

  // Lists within encrypt_buffers
  buff_ptr encrypt_first_empty;   // unordered: no encryp_last_empty
  buff_ptr encrypt_first_pending;
  buff_ptr encrypt_last_pending;
  buff_ptr encrypt_first_done;
  buff_ptr encrypt_last_done;

  // Lists within decrypt_buffers
  buff_ptr decrypt_first_empty;  // unordered.
  buff_ptr decrypt_first_pending;
  buff_ptr decrypt_last_pending;
  buff_ptr decrypt_first_done;
  buff_ptr decrypt_last_done;

  // Lists within eresult_buffers
  buff_ptr eresult_first_empty;  // unordered.
  buff_ptr eresult_first_blank;  // unordered.
  buff_ptr eresult_first_encrypted;
  buff_ptr eresult_last_encrypted;

  // Lists within dresult_buffers
  buff_ptr dresult_first_empty;  // unordered.
  buff_ptr dresult_first_blank;  // unordered.
  buff_ptr dresult_first_decrypted;
  buff_ptr dresult_last_decrypted;

  uint32_t encrypt_pending_offset;  // if set, points to remaining bytes to consume in working buffer.
  uint32_t decrypt_pending_offset;

  pn_tls_mode_t mode;
  pn_tls_verify_mode_t verify_mode;
  pn_tls_domain_t *domain;
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

  bool ssl_shutdown;    // BIO_ssl_shutdown() called on socket.
  bool ssl_closed;      // shutdown complete, or SSL error
  bool read_blocked;    // SSL blocked until more network data is read
  bool write_blocked;   // SSL blocked until data is written to network
  bool enc_rblocked;
  bool enc_wblocked;
  bool dec_rblocked;
  bool dec_wblocked;
  bool can_encrypt;
  bool started;
  bool stopped;

  char *subject;
  X509 *peer_certificate;
};

static void encrypt(pn_tls_t *);
static void decrypt(pn_tls_t *);

static void tls_initialize_buffers(pn_tls_t *tls) {
  // Link together free lists
  for (buff_ptr i = 1; i<=encrypt_buffer_count; i++) {
    tls->encrypt_buffers[i-1].next = i==encrypt_buffer_count ? 0 : i+1;
    tls->encrypt_buffers[i-1].type = buff_empty;
    tls->decrypt_buffers[i-1].next = i==decrypt_buffer_count ? 0 : i+1;
    tls->decrypt_buffers[i-1].type = buff_empty;
  }

  for (buff_ptr i = 1; i<=eresult_buffer_count; i++) {
    tls->eresult_buffers[i-1].next = i==eresult_buffer_count ? 0 : i+1;
    tls->eresult_buffers[i-1].type = buff_empty;
    tls->dresult_buffers[i-1].next = i==eresult_buffer_count ? 0 : i+1;
    tls->dresult_buffers[i-1].type = buff_empty;
  }

  tls->encrypt_buffer_empty_count = encrypt_buffer_count;
  tls->decrypt_buffer_empty_count = decrypt_buffer_count;
  tls->eresult_empty_count = eresult_buffer_count;
  tls->dresult_empty_count = dresult_buffer_count;

  tls->eresult_first_empty = 1;
  tls->dresult_first_empty = 1;
  tls->encrypt_first_empty = 1;
  tls->decrypt_first_empty = 1;
}

size_t pn_tls_encrypt_input_buffers_capacity(pn_tls_t *tls) { return tls->encrypt_buffer_empty_count; }
size_t pn_tls_decrypt_input_buffers_capacity(pn_tls_t *tls) { return tls->decrypt_buffer_empty_count; }
size_t pn_tls_encrypt_result_buffers_capacity(pn_tls_t *tls) { return tls->eresult_empty_count; }
size_t pn_tls_decrypt_result_buffers_capacity(pn_tls_t *tls) { return tls->dresult_empty_count; }

size_t pn_tls_decrypted_result_count(pn_tls_t *tls) {
  return tls->dresult_decrypted_count;
}

size_t pn_tls_encrypted_result_count(pn_tls_t *tls) {
  return tls->eresult_encrypted_count;
}


uint32_t pn_tls_last_decrypted_buffer_size(pn_tls_t *tls) {
  return tls->dresult_last_decrypted ? tls->dresult_buffers[tls->dresult_last_decrypted-1].size : 0;
}

uint32_t pn_tls_last_encrypted_buffer_size(pn_tls_t *tls) {
  return tls->eresult_last_encrypted ? tls->eresult_buffers[tls->eresult_last_encrypted-1].size : 0;
}


// define two sets of allowable ciphers: those that require authentication, and those
// that do not require authentication (anonymous).  See ciphers(1).
#define CIPHERS_AUTHENTICATE    "ALL:!aNULL:!eNULL:@STRENGTH"
#define CIPHERS_ANONYMOUS       "ALL:aNULL:!eNULL:@STRENGTH"

/* */
static int keyfile_pw_cb(char *buf, int size, int rwflag, void *userdata);
static int init_ssl_socket(pn_tls_t *, pn_tls_domain_t *);
static void release_ssl_socket( pn_tls_t * );
static X509 *get_peer_certificate(pn_tls_t *ssl);


//TODO: convenience for embedded existing logging. Replace ASAP.
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
#ifdef at_least_some_logging
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
#endif
}

static void ssl_log_flush(void *v, int sev)
{
  char buf[128];        // see "man ERR_error_string_n()"
  unsigned long err = ERR_get_error();
  while (err) {
    ERR_error_string_n(err, buf, sizeof(buf));
    ssl_log(v, sev, "%s", buf);
    err = ERR_get_error();
  }
}
// log an error and dump the SSL error stack
static void ssl_log_error(const char *fmt, ...)
{
}

// Next three not exported from Proton core.  Copied for now.
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
    // TODO: replace: ssl_log(transport, PN_LEVEL_ERROR, "Error: unexpected error - SSL context info not available for peer verify!");
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

static int pni_tls_init(pn_tls_t *ssl, pn_tls_domain_t *domain, const char *unused)
{
  if (!ssl) return -1;

  ssl->mode = domain->mode;
  ssl->verify_mode = domain->verify_mode;

  // TODO: confirm allow_unsecured is not necessary.
  // If SSL doesn't specifically allow skipping encryption, require SSL
  // TODO: This is a probably a stop-gap until allow_unsecured is removed
  //  if (!domain->allow_unsecured) transport->encryption_required = true;

  tls_initialize_buffers(ssl);
  return init_ssl_socket(ssl, domain);
}

pn_tls_t *pn_tls_v1(pn_tls_domain_t *domain, const char* hostname, const char *session_id) {
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
    pn_tls_set_peer_hostname(tls, hostname);
  }

  if (pni_tls_init(tls, domain, session_id) < 0) {
    pn_tls_free(tls);
    return(NULL);
  }
  return tls;
}

pn_tls_t *pn_tls(pn_tls_domain_t *domain) {
  if (!domain) return NULL;
  pn_tls_t *tls = (pn_tls_t *) calloc(1, sizeof(pn_tls_t));
  if (!tls) return NULL;
  tls->domain = domain;

  return tls;
}

int pn_tls_start(pn_tls_t *tls) {
  if (tls->started)
    return PN_ARG_ERR;
  tls->started = true;
  return pni_tls_init(tls, tls->domain, tls->session_id);
}

int pn_tls_stop(pn_tls_t *tls) {
  if (tls->stopped)
    return PN_ARG_ERR;
  tls->stopped = true;
  return 0;
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
    ssl->enc_rblocked = true;
    ssl->dec_rblocked = true;
  } else {      // client mode
    SSL_set_connect_state(ssl->ssl);
    BIO_set_ssl_mode(ssl->bio_ssl, 1);  // client mode
    ssl_log( NULL, PN_LEVEL_TRACE, "Client SSL socket created." );

    // The following dummy IO action activates the BIO.
    // Without it bio_net_io calls fail.  TODO: substitute for a more
    // normal OpenSSL initialization.
    char c;
    int fakerc = BIO_read(ssl->bio_ssl, &c, 1);
    if (fakerc != -1)
      abort();

    ssl->enc_rblocked = false;  // client hello starts the whole process
    ssl->dec_rblocked = true;
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

bool pn_tls_encrypted_pending(pn_tls_t *tls)
{
  if (tls && tls->started) {
    return tls->eresult_first_encrypted;
  }
  return 0;
}

bool pn_tls_decrypted_pending(pn_tls_t *tls)
{
  if (tls && tls->started) {
    return tls->dresult_first_decrypted;
  }
  return 0;
}

static inline uint32_t room_v1(pn_raw_buffer_t const *rb) {
  //ZZZ confirm V1 obsoleted.
  if (rb)
    return rb->capacity - (rb->offset + rb->size);
  return 0;
}

static inline uint32_t room(pbuffer_t const *b) {
  if (b)
    return b->capacity - (b->offset + b->size);
  return 0;
}

static inline size_t size_min(uint32_t a, uint32_t b) {
  return (a <= b) ? a : b;
}

ssize_t pn_tls_encrypt_v1(pn_tls_t *tls, pn_raw_buffer_t const *unencrypted_buffers_in, size_t in_count, pn_raw_buffer_t *encrypted_destination_bufs, size_t dest_count, size_t *dest_written) {
  bool shutdown_input = false;  // TODO: missing close() call?
  size_t inbufs_processed = 0;
  size_t outbufs_processed = 0;
  bool input_read = false;
  if (!tls || !dest_count) return 0;
  pn_raw_buffer_t *inbufp;
  pn_raw_buffer_t inbuf;

  // Determine our "first" input buffer.
  if (tls->q4enc_size) {
    // Straggler bytes not processed but saved in previous call.
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
  }
  pn_raw_buffer_t *outbufp = dest_count ? &encrypted_destination_bufs[0] : NULL;
  bool outbuf_written = false;

  while (true) {
    // Insert unencrypted data into BIO
    while (inbufp && !tls->enc_wblocked) {
      size_t n = inbufp->size;
      if (n) {
        int wcount = BIO_write(tls->bio_ssl, inbufp->bytes + inbufp->offset, n);
        if (wcount < (int) n)
          tls->enc_wblocked = true;
        if (wcount > 0) {
          tls->enc_rblocked = false;
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

        } else if (shutdown_input) {
          ssl_log( NULL, PN_LEVEL_TRACE, "shutting down BIO write side");
          (void)BIO_shutdown_wr( tls->bio_net_io );
          shutdown_input = false;
        }
      }
    }

    // Extract encrypted data from BIO
    while (outbufp && !tls->enc_rblocked) {
      size_t n = room_v1(outbufp);
      if (n) {
        int rcount = BIO_read(tls->bio_net_io, outbufp->bytes + outbufp->offset + outbufp->size, n);
        if (rcount < (int) n)
          tls->enc_rblocked = true;
        if (rcount > 0) {
          tls->write_blocked = false;
          tls->enc_wblocked = false;
          outbufp->size += rcount;
          if (!outbuf_written) {
            outbuf_written = true;
            outbufs_processed++;
          }
          if (room_v1(outbufp) == 0) {
            if (--dest_count) {
              outbufp++;
              outbuf_written = false;
            }
            else
              outbufp = NULL; // No more output buffers
          }
        } else if (!BIO_should_retry(tls->bio_ssl)) {
          int reason = SSL_get_error( tls->ssl, rcount );
          switch (reason) {
          case SSL_ERROR_ZERO_RETURN:
            // SSL closed cleanly
            ssl_log(NULL, PN_LEVEL_TRACE, "SSL connection has closed");
            // TODO: replacement for:       start_ssl_shutdown(transport);  // KAG: not sure - this may not be necessary
            tls->ssl_closed = true;
            break;
          default:
            // unexpected error
            // TODO: proper error communication to app layer and shutdown
            abort();
          }
        }        
      }
    }
    
    // Done if outbufs exhausted or all inbufs decrypted
    if (!outbufp || tls->enc_rblocked)
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

ssize_t pn_tls_decrypt_v1(pn_tls_t *tls, pn_raw_buffer_t const *encrypted_buffers_in, size_t in_count, pn_raw_buffer_t *decrypted_destination_bufs, size_t dest_count, size_t *dest_written) {
  size_t inbufs_processed = 0;
  size_t outbufs_processed = 0;
  bool input_read = false;
  if (!tls || !dest_count)
    return 0;
  pn_raw_buffer_t *inbufp;
  pn_raw_buffer_t inbuf;

  // Select first buffer to process.
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

    // Insert encrypted data into ssl filter chain
    while (inbufp && !tls->dec_wblocked) {
      size_t n = inbufp->size;
      if (n) {
        int wcount = BIO_write(tls->bio_net_io, inbufp->bytes + inbufp->offset, n);
        if (wcount < (int) n)
          tls->dec_wblocked = true;
        if (wcount > 0) {
          tls->dec_rblocked = false;
          tls->enc_rblocked = false;
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

    // Extract decrypted data from ssl filter chain
    while (outbufp && !tls->dec_rblocked) {
      size_t n = room_v1(outbufp);
      if (n) {
        int rcount = BIO_read(tls->bio_ssl, outbufp->bytes + outbufp->offset + outbufp->size, n);
        if (rcount > 0) {
          tls->dec_wblocked = false;
          outbufp->size += rcount;
          if (!outbuf_written) {
            outbuf_written = true;
            outbufs_processed++;
          }
          if (room_v1(outbufp) == 0) {
            if (--dest_count) {
              outbufp++;
              outbuf_written = false;
            }
            else
              outbufp = NULL; // No more output buffers
          }
        } else {
          if (!BIO_should_retry(tls->bio_ssl)) {
            int reason = SSL_get_error( tls->ssl, rcount );
            switch (reason) {
            case SSL_ERROR_ZERO_RETURN:
              // SSL closed cleanly
              ssl_log(NULL, PN_LEVEL_TRACE, "SSL connection has closed");
              tls->ssl_closed = true;
              break;
            default:
              // TODO: communicate error and shutdown.
              // unexpected error
              // ssl_failed(transport);
              ERR_print_errors_fp(stderr);
              ssl_log_flush(NULL, 1);
              abort();
            }
          } else {
            if (rcount == -1 && BIO_should_read(tls->bio_ssl))
              tls->dec_rblocked = true;
          }
        }
      }
    }
    
    // Done if outbufs exhausted or all inbufs decrypted
    if (!outbufp || tls->dec_rblocked)
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
  if (!tls->can_encrypt && SSL_do_handshake(tls->ssl) == 1)
    tls->can_encrypt = true;
  return inbufs_processed;
}


bool pn_tls_can_encrypt(pn_tls_t * tls) {
  return tls->can_encrypt;
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
  tls_ex_data_index = SSL_get_ex_new_index( 0, (void *) "org.apache.qpid.proton.tls",
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

static void raw_buffer_to_pbuffer(pn_raw_buffer_t const* rbuf, pbuffer_t *pbuf, buff_type type) {
  pbuf->context = rbuf->context;
  pbuf->bytes = rbuf->bytes;
  pbuf->capacity = rbuf->capacity;
  pbuf->size = rbuf->size;
  pbuf->offset = rbuf->offset;
  pbuf->type = type;
}

static void pbuffer_to_raw_buffer(pbuffer_t *pbuf, pn_raw_buffer_t *rbuf) {
  rbuf->context = pbuf->context;
  rbuf->bytes = pbuf->bytes;
  rbuf->capacity = pbuf->capacity;
  rbuf->size = pbuf->size;
  rbuf->offset = pbuf->offset;
}


size_t pn_tls_give_encrypt_input_buffers(pn_tls_t* tls, pn_raw_buffer_t const* bufs, size_t count_bufs) {
  assert(tls);

  size_t can_take = pn_min(count_bufs, pn_tls_encrypt_input_buffers_capacity(tls));
  if ( can_take==0 ) return 0;

  buff_ptr current = tls->encrypt_first_empty;
  assert(current);

  buff_ptr previous;
  for (size_t i = 0; i < can_take; i++) {
    // Get next free
    assert(tls->encrypt_buffers[current-1].type == buff_empty);
    raw_buffer_to_pbuffer(bufs + i, &tls->encrypt_buffers[current-1], buff_encrypt_pending);
    previous = current;
    current = tls->encrypt_buffers[current-1].next;
  }

  if (!tls->encrypt_first_pending) {
    tls->encrypt_first_pending = tls->encrypt_first_empty;
  }
  if (tls->encrypt_last_pending) {
    tls->encrypt_buffers[tls->encrypt_last_pending-1].next = tls->encrypt_first_empty;
  }

  tls->encrypt_last_pending = previous;
  tls->encrypt_buffers[previous-1].next = 0;
  tls->encrypt_first_empty = current;

  tls->encrypt_buffer_empty_count -= can_take;
  return can_take;
}

size_t pn_tls_give_decrypt_input_buffers(pn_tls_t* tls, pn_raw_buffer_t const* bufs, size_t count_bufs) {
  assert(tls);

  size_t can_take = pn_min(count_bufs, pn_tls_decrypt_input_buffers_capacity(tls));
  if ( can_take==0 ) return 0;

  buff_ptr current = tls->decrypt_first_empty;
  assert(current);

  buff_ptr previous;
  for (size_t i = 0; i < can_take; i++) {
    // Get next free
    assert(tls->decrypt_buffers[current-1].type == buff_empty);
    raw_buffer_to_pbuffer(bufs + i, &tls->decrypt_buffers[current-1], buff_decrypt_pending);
    previous = current;
    current = tls->decrypt_buffers[current-1].next;
  }

  if (!tls->decrypt_first_pending) {
    tls->decrypt_first_pending = tls->decrypt_first_empty;
  }
  if (tls->decrypt_last_pending) {
    tls->decrypt_buffers[tls->decrypt_last_pending-1].next = tls->decrypt_first_empty;
  }

  tls->decrypt_last_pending = previous;
  tls->decrypt_buffers[previous-1].next = 0;
  tls->decrypt_first_empty = current;

  tls->decrypt_buffer_empty_count -= can_take;
  return can_take;
}

size_t pn_tls_give_encrypt_result_buffers(pn_tls_t* tls, pn_raw_buffer_t const* bufs, size_t count_bufs) {
  assert(tls);

  size_t can_take = pn_min(count_bufs, pn_tls_encrypt_result_buffers_capacity(tls));
  if ( can_take==0 ) return 0;

  buff_ptr current = tls->eresult_first_empty;
  assert(current);

  buff_ptr previous;
  for (size_t i = 0; i < can_take; i++) {
    // Get next free
    assert(tls->eresult_buffers[current-1].type == buff_empty);
    raw_buffer_to_pbuffer(bufs + i, &tls->eresult_buffers[current-1], buff_eresult_blank);
    previous = current;
    current = tls->eresult_buffers[current-1].next;
  }

  tls->eresult_buffers[previous-1].next = tls->eresult_first_blank;
  tls->eresult_first_blank = tls->eresult_first_empty;
  tls->eresult_first_empty = current;

  tls->eresult_empty_count -= can_take;
  return can_take;
}

size_t pn_tls_give_decrypt_result_buffers(pn_tls_t* tls, pn_raw_buffer_t const* bufs, size_t count_bufs) {
  assert(tls);

  size_t can_take = pn_min(count_bufs, pn_tls_decrypt_result_buffers_capacity(tls));
  if ( can_take==0 ) return 0;

  buff_ptr current = tls->dresult_first_empty;
  assert(current);

  buff_ptr previous;
  for (size_t i = 0; i < can_take; i++) {
    // Get next free
    assert(tls->dresult_buffers[current-1].type == buff_empty);
    raw_buffer_to_pbuffer(bufs + i, &tls->dresult_buffers[current-1], buff_dresult_blank);
    previous = current;
    current = tls->dresult_buffers[current-1].next;
  }

  tls->dresult_buffers[previous-1].next = tls->dresult_first_blank;
  tls->dresult_first_blank = tls->dresult_first_empty;
  tls->dresult_first_empty = current;

  tls->dresult_empty_count -= can_take;
  return can_take;
}

size_t pn_tls_take_decrypt_input_buffers(pn_tls_t *tls, pn_raw_buffer_t *buffers, size_t num) {
  assert(tls);
  size_t count = 0;

  buff_ptr current = tls->decrypt_first_done;
  if (!current) return 0;

  buff_ptr previous;
  for (; current && count < num; count++) {
    assert(tls->decrypt_buffers[current-1].type == buff_decrypt_done);
    pbuffer_to_raw_buffer(&tls->decrypt_buffers[current-1], buffers + count);
    tls->decrypt_buffers[current-1].type = buff_empty;

    previous = current;
    current = tls->decrypt_buffers[current-1].next;
  }
  if (!count) return 0;

  tls->decrypt_buffers[previous-1].next = tls->decrypt_first_empty;
  tls->decrypt_first_empty = tls->decrypt_first_done;

  tls->decrypt_first_done = current;
  if (!current) {
    tls->decrypt_last_done = 0;
  }
  tls->decrypt_buffer_empty_count += count;
  return count;
}

size_t pn_tls_take_encrypt_input_buffers(pn_tls_t *tls, pn_raw_buffer_t *buffers, size_t num) {
  assert(tls);
  size_t count = 0;

  buff_ptr current = tls->encrypt_first_done;
  if (!current) return 0;

  buff_ptr previous;
  for (; current && count < num; count++) {
    assert(tls->encrypt_buffers[current-1].type == buff_encrypt_done);
    pbuffer_to_raw_buffer(&tls->encrypt_buffers[current-1], buffers + count);
    tls->encrypt_buffers[current-1].type = buff_empty;

    previous = current;
    current = tls->encrypt_buffers[current-1].next;
  }
  if (!count) return 0;

  tls->encrypt_buffers[previous-1].next = tls->encrypt_first_empty;
  tls->encrypt_first_empty = tls->encrypt_first_done;

  tls->encrypt_first_done = current;
  if (!current) {
    tls->encrypt_last_done = 0;
  }
  tls->encrypt_buffer_empty_count += count;
  return count;
}

size_t pn_tls_take_decrypted_result_buffers(pn_tls_t *tls, pn_raw_buffer_t *buffers, size_t num) {
  assert(tls);
  size_t count = 0;

  buff_ptr current = tls->dresult_first_decrypted;
  if (!current) return 0;

  buff_ptr previous;
  for (; current && count < num; count++) {
    assert(tls->dresult_buffers[current-1].type == buff_dresult_decrypted);
    pbuffer_to_raw_buffer(&tls->dresult_buffers[current-1], buffers + count);
    tls->dresult_buffers[current-1].type = buff_empty;

    previous = current;
    current = tls->dresult_buffers[current-1].next;
  }
  if (!count) return 0;

  tls->dresult_buffers[previous-1].next = tls->dresult_first_empty;
  tls->dresult_first_empty = tls->dresult_first_decrypted;

  tls->dresult_first_decrypted = current;
  if (!current) {
    tls->dresult_last_decrypted = 0;
  }
  tls->dresult_empty_count += count;
  tls->dresult_decrypted_count -= count;
  return count;
}

size_t pn_tls_take_encrypted_result_buffers(pn_tls_t *tls, pn_raw_buffer_t *buffers, size_t num) {
  assert(tls);
  size_t count = 0;

  buff_ptr current = tls->eresult_first_encrypted;
  if (!current) return 0;

  buff_ptr previous;
  for (; current && count < num; count++) {
    assert(tls->eresult_buffers[current-1].type == buff_eresult_encrypted);
    pbuffer_to_raw_buffer(&tls->eresult_buffers[current-1], buffers + count);
    tls->eresult_buffers[current-1].type = buff_empty;

    previous = current;
    current = tls->eresult_buffers[current-1].next;
  }
  if (!count) return 0;

  tls->eresult_buffers[previous-1].next = tls->eresult_first_empty;
  tls->eresult_first_empty = tls->eresult_first_encrypted;

  tls->eresult_first_encrypted = current;
  if (!current) {
    tls->eresult_last_encrypted = 0;
  }
  tls->eresult_empty_count += count;
  tls->eresult_encrypted_count -= count;
  return count;
}

static pbuffer_t *next_encrypt_pending(pn_tls_t *tls) {
  if (!tls->encrypt_first_pending) return NULL;
  buff_ptr p = tls->encrypt_first_pending;
  pbuffer_t *current = &tls->encrypt_buffers[p-1];
  if (current->size > tls->encrypt_pending_offset)
    return current;
  // current is full, convert from pending to done
  assert(current->type == buff_encrypt_pending);
  tls->encrypt_pending_offset = 0;
  if (!tls->encrypt_first_done) {
    tls->encrypt_first_done = p;
  }
  if (tls->encrypt_last_done) {
    tls->encrypt_buffers[tls->encrypt_last_done-1].next = p;
  }
  tls->encrypt_last_done = p;
  tls->encrypt_first_pending = current->next;
  if (!tls->encrypt_first_pending)
    tls->encrypt_last_pending = 0;
  current->next = 0;
  current->type = buff_encrypt_done;

  // Advance
  p = tls->encrypt_first_pending;
  pbuffer_t *next = p ? &tls->encrypt_buffers[p-1] : NULL;
  assert(!next || next->type == buff_encrypt_pending);
  
  return next;
}

static pbuffer_t *next_decrypt_pending(pn_tls_t *tls) {
  if (!tls->decrypt_first_pending) return NULL;
  buff_ptr p = tls->decrypt_first_pending;
  pbuffer_t *current = &tls->decrypt_buffers[p-1];
  if (current->size > tls->decrypt_pending_offset)
    return current;
  // current is full, convert from pending to done
  assert(current->type == buff_decrypt_pending);
  tls->decrypt_pending_offset = 0;
  if (!tls->decrypt_first_done) {
    tls->decrypt_first_done = p;
  }
  if (tls->decrypt_last_done) {
    tls->decrypt_buffers[tls->decrypt_last_done-1].next = p;
  }
  tls->decrypt_last_done = p;
  tls->decrypt_first_pending = current->next;
  if (!tls->decrypt_first_pending)
    tls->decrypt_last_pending = 0;
  current->next = 0;
  current->type = buff_decrypt_done;

  // Advance
  p = tls->decrypt_first_pending;
  pbuffer_t *next = p ? &tls->decrypt_buffers[p-1] : NULL;
  assert(!next || next->type == buff_decrypt_pending);

  return next;
}

static void blank_eresult_pop(pn_tls_t *tls, buff_ptr p) {
  assert (p && p == tls->eresult_first_blank);  // From front only.
  tls->eresult_first_blank = tls->eresult_buffers[p-1].next;
  tls->eresult_buffers[p-1].next = 0;
}

static void blank_dresult_pop(pn_tls_t *tls, buff_ptr p) {
  assert (p && p == tls->dresult_first_blank);  // From front only.
  tls->dresult_first_blank = tls->dresult_buffers[p-1].next;
  tls->dresult_buffers[p-1].next = 0;
}

static void encrypted_result_add(pn_tls_t *tls, buff_ptr p) {
  tls->eresult_buffers[p-1].type = buff_eresult_encrypted;
  if (!tls->eresult_first_encrypted)
    tls->eresult_first_encrypted = p;
  if (tls->eresult_last_encrypted)
    tls->eresult_buffers[tls->eresult_last_encrypted-1].next = p;
  tls->eresult_last_encrypted = p;
  tls->eresult_encrypted_count++;
}

static void decrypted_result_add(pn_tls_t *tls, buff_ptr p) {
  tls->dresult_buffers[p-1].type = buff_dresult_decrypted;
  if (!tls->dresult_first_decrypted)
    tls->dresult_first_decrypted = p;
  if (tls->dresult_last_decrypted)
    tls->dresult_buffers[tls->dresult_last_decrypted-1].next = p;
  tls->dresult_last_decrypted = p;
  tls->dresult_decrypted_count--;
}

static buff_ptr current_encrypted_result(pn_tls_t *tls) {
  buff_ptr p = tls->eresult_last_encrypted;
  if (p && room(&tls->eresult_buffers[p-1]))
    return p;  //  Has room so keep filling.
  // Otherwise, use a blank reult if available.
  return tls->eresult_first_blank;
}

static buff_ptr current_decrypted_result(pn_tls_t *tls) {
  buff_ptr p = tls->dresult_last_decrypted;
  if (p && room(&tls->dresult_buffers[p-1]))
    return p;  //  Has room so keep filling.
  // Otherwise, use a blank reult if available.
  return tls->dresult_first_blank;
}


static void encrypt(pn_tls_t *tls) {
  assert(tls);
  buff_ptr curr_result = current_encrypted_result(tls);
  if (!curr_result) return;  // No where to place encrypted data
  pbuffer_t *pending = next_encrypt_pending(tls);
  bool shutdown_input = false;  // TODO: missing close() call?
    
  while (true) {
    // Insert unencrypted data into BIO.
    // OpenSSL maps each BIO_write to a separate TLS record.
    // The BIO can take 16KB + a bit before blocking.
    // TODO: consider allowing application to configure BIO buffer size on encrypt side.
    while (pending && !tls->enc_wblocked) {
      size_t n = pending->size - tls->encrypt_pending_offset;
      if (n) {
        char *bytes = pending->bytes + pending->offset + tls->encrypt_pending_offset;
        int wcount = BIO_write(tls->bio_ssl, bytes, n);
        if (wcount < (int) n)
          tls->enc_wblocked = true;
        if (wcount > 0) {
          tls->enc_rblocked = false;
          tls->encrypt_pending_offset += wcount;
        } else if (shutdown_input) {
          ssl_log( NULL, PN_LEVEL_TRACE, "shutting down BIO write side");
          (void)BIO_shutdown_wr( tls->bio_net_io );
          shutdown_input = false;
        }
      }
      pending = next_encrypt_pending(tls);
    }

    // Extract encrypted data from other side of BIO.
    while (curr_result && !tls->enc_rblocked) {
      pbuffer_t *result = &tls->eresult_buffers[curr_result-1];
      size_t n = room(result);
      assert(n);
      int rcount = BIO_read(tls->bio_net_io, result->bytes + result->offset + result->size, n);
      if (rcount < (int) n)
        tls->enc_rblocked = true;
      if (rcount > 0) {
        tls->write_blocked = false;
        tls->enc_wblocked = false;
        if (result->size == 0) {
          // first data inserted: convert from blank type to encrypted type
          assert(result->type == buff_eresult_blank);
          blank_eresult_pop(tls, curr_result);
          encrypted_result_add(tls, curr_result);
        }
        result->size += rcount;
        if (room(result) == 0) {
          // Tentatively set a blank buffer for future output without popping.
          curr_result = tls->eresult_first_blank;
        }
      } else if (!BIO_should_retry(tls->bio_ssl)) {
        int reason = SSL_get_error( tls->ssl, rcount );
        switch (reason) {
        case SSL_ERROR_ZERO_RETURN:
          // SSL closed cleanly
          ssl_log(NULL, PN_LEVEL_TRACE, "SSL connection has closed");
          // TODO: replacement for:       start_ssl_shutdown(transport);  // KAG: not sure - this may not be necessary
          tls->ssl_closed = true;
          break;
        default:
          // unexpected error
          // TODO: proper error communication to app layer and shutdown
          abort();
        }
      }       
    }
    
    // Done if output buffers exhausted or all available encrypted bytes drained from BIO.
    if (!curr_result || tls->enc_rblocked)
      break;
  }
}

static void decrypt(pn_tls_t *tls) {
  assert(tls);
  buff_ptr curr_result = current_decrypted_result(tls);
  if (!curr_result) return;  // No where to place decrypted data
  pbuffer_t *pending = next_decrypt_pending(tls);

  while (true) {

    // Insert encrypted data into openssl filter chain.
    while (pending && !tls->dec_wblocked) {
      size_t n = pending->size - tls->decrypt_pending_offset;
      if (n) {
        char *bytes = pending->bytes + pending->offset + tls->decrypt_pending_offset;
        int wcount = BIO_write(tls->bio_net_io, bytes, n);
        if (wcount < (int) n)
          tls->dec_wblocked = true;
        if (wcount > 0) {
          tls->dec_rblocked = false;
          tls->enc_rblocked = false;
          tls->decrypt_pending_offset += wcount;
        }
        // ZZZ else error? shutdown one BIO side?
      }
      pending = next_decrypt_pending(tls);
    }

    // Extract decrypted data from other side of filter chain.
    while (curr_result && !tls->dec_rblocked) {
      pbuffer_t *result = &tls->dresult_buffers[curr_result-1];
      size_t n = room(result);
      assert(n);
      int rcount = BIO_read(tls->bio_ssl, result->bytes + result->offset + result->size, n);
      if (rcount > 0) {
        tls->dec_wblocked = false;
        if (result->size == 0) {
          // first data inserted: convert from blank type to encrypted type
          assert(result->type == buff_dresult_blank);
          blank_dresult_pop(tls, curr_result);
          decrypted_result_add(tls, curr_result);
        }
        result->size += rcount;
        if (room(result) == 0) {
          // Tentatively set a blank buffer for future output without popping.
          curr_result = tls->dresult_first_blank;
        }
      } else {
        if (!BIO_should_retry(tls->bio_ssl)) {
          int reason = SSL_get_error( tls->ssl, rcount );
          switch (reason) {
          case SSL_ERROR_ZERO_RETURN:
            // SSL closed cleanly
            ssl_log(NULL, PN_LEVEL_TRACE, "SSL connection has closed");
            tls->ssl_closed = true;
            break;
          default:
            // TODO: communicate error and shutdown.
            // unexpected error
            // ssl_failed(transport);
            ERR_print_errors_fp(stderr);
            ssl_log_flush(NULL, 1);
            abort();
          }
        } else {
          if (rcount == -1 && BIO_should_read(tls->bio_ssl))
            tls->dec_rblocked = true;
        }
      }
    }
    
    // Done if outbufs exhausted or all inbufs decrypted
    if (!curr_result || tls->dec_rblocked)
      break;
  }

  if (!tls->can_encrypt && SSL_do_handshake(tls->ssl) == 1)
    tls->can_encrypt = true;
}

int pn_tls_process(pn_tls_t* tls) {
  if (!tls->started || tls->stopped)
    return PN_ARG_ERR;
  decrypt(tls);  // First.  May generate handshake or other on encrypt side.
  encrypt(tls);
  // Error logic here please.
  return 0;
}

bool pn_tls_need_encrypt_result_buffers(pn_tls_t* tls) {
  if (tls && tls->started && tls->eresult_empty_count) {
    if (!current_encrypted_result(tls)) {
      // Existing result buffers all full.  Check if OpenSSL has data to read.
      return (BIO_pending(tls->bio_net_io) > 0);
    }
  }
  return false;
}

bool pn_tls_need_decrypt_result_buffers(pn_tls_t* tls) {
  if (tls && tls->started && tls->dresult_empty_count) {
    if (!current_decrypted_result(tls)) {
      // Existing result buffers all full.  Check if OpenSSL has data to read.
      return (BIO_pending(tls->bio_ssl) > 0);
    }
  }
  return false;
}
