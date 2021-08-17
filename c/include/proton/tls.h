#ifndef PROTON_TLS_H
#define PROTON_TLS_H 1

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

#include <proton/import_export.h>
// ZZZ next two needed?
#include <proton/type_compat.h>
#include <proton/types.h>
#include <proton/raw_connection.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * @copybrief tls
 *
 * @addtogroup tls
 * @{
 */

/**
 * API for using TLS separate from AMQP connections.
 *
 * Based heavily on the original Proton SSL API for configuring TLS over AMQP connections,
 * this implementation separates the encryption/decryption of data from the network IO
 * operations.
 *
 * A Transport can be configured as either an "TLS client" or an "TLS server".  An TLS
 * client is the party that proactively establishes a connection to an TLS server.  An TLS
 * server is the party that accepts a connection request from a remote TLS client.
 *
 * This TLS implementation defines the following objects:

 * @li A top-level object that stores the configuration used by one or more TLS
 * sessions (pn_tls_domain_t).
 * @li A per-connection TLS session object that performs the encryption/authentication
 * associated with the transport (pn_tls_t).
 *
 * The pn_tls_domain_t is used to construct an TLS session (pn_tls_t).  The
 * session "adopts" its configuration from the pn_tls_domain_t that was used to create it.
 * For example, pn_tls_domain_t can be configured as either a "client" or a "server".  TLS
 * sessions constructed from this domain will perform the corresponding role (either
 * client or server).
 *
 * If an TLS session is created without a pn_tls_domain_t object then a default will be used
 * (see ::pn_tls_init()).
 *
 * If either an TLS server or client needs to identify itself with the remote node, it
 * must have its TLS certificate configured (see ::pn_tls_domain_set_credentials()).
 *
 * If either an TLS server or client needs to verify the identity of the remote node, it
 * must have its database of trusted CAs configured. By default this will be set up to use
 * the default system database of trusted CA. But this can be changed
 * (see ::pn_tls_domain_set_trusted_ca_db()).
 *
 * The level of verification required of the remote may be configured (see
 * ::pn_tls_domain_set_peer_authentication)
 *
 * Support for TLS Client Session resume is provided (see ::pn_tls_init,
 * ::pn_tls_resume_status).
 */
typedef struct pn_tls_domain_t pn_tls_domain_t;

/**
 * @see pn_tls
 */
typedef struct pn_tls_t pn_tls_t;

/**
 * Determines the type of TLS endpoint.
 */
typedef enum {
  PN_TLS_MODE_CLIENT = 1, /**< Local connection endpoint is an TLS client */
  PN_TLS_MODE_SERVER      /**< Local connection endpoint is an TLS server */
} pn_tls_mode_t;

/**
 * Indicates whether an TLS session has been resumed.
 */
typedef enum {
  PN_TLS_RESUME_UNKNOWN,        /**< Session resume state unknown/not supported */
  PN_TLS_RESUME_NEW,            /**< Session renegotiated - not resumed */
  PN_TLS_RESUME_REUSED          /**< Session resumed from previous session. */
} pn_tls_resume_status_t;

/**
 * Tests for TLS implementation present
 *
 *  @return true if we support TLS, false if not
 */
PN_TLS_EXTERN bool pn_tls_present( void );

/**
 * Create an TLS configuration domain
 *
 * This method allocates an TLS domain object.  This object is used to hold the TLS
 * configuration for one or more TLS sessions.  The TLS session object (pn_tls_t) is
 * allocated from this object.
 *
 * @param[in] mode the role, client or server, assumed by all TLS sessions created
 * with this domain.
 * @return a pointer to the TLS domain, if TLS support is present.
 */
PN_TLS_EXTERN pn_tls_domain_t *pn_tls_domain(pn_tls_mode_t mode);

/**
 * Release an TLS configuration domain
 *
 * This method frees an TLS domain object allocated by ::pn_tls_domain.
 * @param[in] domain the domain to destroy.
 */
PN_TLS_EXTERN void pn_tls_domain_free(pn_tls_domain_t *domain);

/**
 * Set the certificate that identifies the local node to the remote.
 *
 * This certificate establishes the identity for the local node for all TLS sessions
 * created from this domain.  It will be sent to the remote if the remote needs to verify
 * the identity of this node.  This may be used for both TLS servers and TLS clients (if
 * client authentication is required by the server).
 *
 * @note This setting effects only those pn_tls_t objects created after this call
 * returns.  pn_tls_t objects created before invoking this method will use the domain's
 * previous setting.
 *
 * @param[in] domain the tls domain that will use this certificate.
 * @param[in] credential_1 specifier for the file/database containing the identifying
 * certificate. For Openssl users, this is a PEM file. For Windows SChannel users, this is
 * the PKCS#12 file or system store.
 * @param[in] credential_2 an optional key to access the identifying certificate. For
 * Openssl users, this is an optional PEM file containing the private key used to sign the
 * certificate. For Windows SChannel users, this is the friendly name of the
 * self-identifying certificate if there are multiple certificates in the store.
 * @param[in] password the password used to sign the key, else NULL if key is not
 * protected.
 * @return 0 on success
 */
PN_TLS_EXTERN int  pn_tls_domain_set_credentials(pn_tls_domain_t *domain,
                                            const char *credential_1,
                                            const char *credential_2,
                                            const char *password);

/**
 * Configure the set of trusted CA certificates used by this domain to verify peers.
 *
 * If the local TLS client/server needs to verify the identity of the remote, it must
 * validate the signature of the remote's certificate.  This function sets the database of
 * trusted CAs that will be used to verify the signature of the remote's certificate.
 *
 * @note This setting effects only those pn_tls_t objects created after this call
 * returns.  pn_tls_t objects created before invoking this method will use the domain's
 * previous setting.
 *
 * @note By default the list of trusted CA certificates will be set to the system default.
 * What this is is depends on the OS and the TLS implementation used: For OpenTLS the default
 * will depend on how the OS is set up. When using the Windows SChannel implementation the default
 * will be the users default trusted certificate store.
 *
 * @param[in] domain the tls domain that will use the database.
 * @param[in] certificate_db database of trusted CAs, used to authenticate the peer.
 * @return 0 on success
 */
PN_TLS_EXTERN int pn_tls_domain_set_trusted_ca_db(pn_tls_domain_t *domain,
                                const char *certificate_db);

/**
 * Determines the level of peer validation.
 *
 * ANONYMOUS_PEER does not require a valid certificate, and permits
 * use of ciphers that do not provide authentication.
 *
 * VERIFY_PEER will only connect to those peers that provide a valid
 * identifying certificate signed by a trusted CA and are using an
 * authenticated cipher.
 *
 * VERIFY_PEER_NAME is like VERIFY_PEER, but also requires the peer's
 * identity as contained in the certificate to be valid (see
 * ::pn_tls_set_peer_hostname).
 *
 * VERIFY_PEER_NAME is configured by default.
 */
typedef enum {
  PN_TLS_VERIFY_NULL = 0,   /**< internal use only */
  PN_TLS_VERIFY_PEER,       /**< require peer to provide a valid identifying certificate */
  PN_TLS_ANONYMOUS_PEER,    /**< do not require a certificate nor cipher authorization */
  PN_TLS_VERIFY_PEER_NAME   /**< require valid certificate and matching name */
} pn_tls_verify_mode_t;

/**
 * Configure the level of verification used on the peer certificate.
 *
 * This method controls how the peer's certificate is validated, if at all.  By default,
 * servers do not attempt to verify their peers (PN_TLS_ANONYMOUS_PEER) but
 * clients attempt to verify both the certificate and peer name (PN_TLS_VERIFY_PEER_NAME).
 * Once certificates and trusted CAs are configured, peer verification can be enabled.
 *
 * @note In order to verify a peer, a trusted CA must be configured. See
 * ::pn_tls_domain_set_trusted_ca_db().
 *
 * @note Servers must provide their own certificate when verifying a peer.  See
 * ::pn_tls_domain_set_credentials().
 *
 * @note This setting effects only those pn_tls_t objects created after this call
 * returns.  pn_tls_t objects created before invoking this method will use the domain's
 * previous setting.
 *
 * @param[in] domain the tls domain to configure.
 * @param[in] mode the level of validation to apply to the peer
 * @param[in] trusted_CAs path to a database of trusted CAs that the server will advertise
 * to the peer client if the server has been configured to verify its peer.
 * @return 0 on success
 */
PN_TLS_EXTERN int pn_tls_domain_set_peer_authentication(pn_tls_domain_t *domain,
                                                    const pn_tls_verify_mode_t mode,
                                                    const char *trusted_CAs);

/**
 * Configure the list of permitted TLS protocols
 *
 * @param[in] domain the tls domain to configure.
 * @param[in] protocols string representing the protocol list.
 * This list is a space separated string of the allowed TLS protocols,
 * The current possibilities are TLSv1 TLSv1.1 TLSv1.2 TLSv1.3. None of the earlier TLS
 * protocols are allowed for security reason.
 *
 * @note If this API not called then all the TLS protocols are allowed. The API only acts to
 * restrict the allowed protocols to the specified set.
 * @return 0 on success
 */
PN_TLS_EXTERN int pn_tls_domain_set_protocols(pn_tls_domain_t *domain, const char *protocols);

/**
 * Configure the list of permitted ciphers
 *
 * @note The syntax of the permitted list is undefined and will depend on the
 * underlying TLS implementation.
 *
 * @param[in] domain the tls domain to configure.
 * @param[in] ciphers string representing the cipher list
 * @return 0 on success
 */
PN_TLS_EXTERN int pn_tls_domain_set_ciphers(pn_tls_domain_t *domain, const char *ciphers);

/**
 * **Deprecated** - Use ::pn_transport_require_encryption()
 *
 * Permit a server to accept connection requests from non-TLS clients.
 *
 * This configures the server to "sniff" the incoming client data stream, and dynamically
 * determine whether TLS/TLS is being used.  This option is disabled by default: only
 * clients using TLS/TLS are accepted.
 *
 * @param[in] domain the domain (server) that will accept the client connections.
 * @return 0 on success
 */
PN_TLS_EXTERN int pn_tls_domain_allow_unsecured_client(pn_tls_domain_t *domain);

/**
 * Create a new TLS session object derived from a domain and optional session_id.
 *
 * @param[in] domain the domain that configures the TLS session.
 * @param[in] session_id an opaque identifier of a previous TLS session domain that configures the TLS session.
 * @return a pointer to the TLS object.  Returns NULL memory allocation fails.
 */
PN_TLS_EXTERN pn_tls_t *pn_tls(pn_tls_domain_t *domain,
                          const char *hostname,
                          const char *session_id);


PN_TLS_EXTERN void pn_tls_free(pn_tls_t *tls);

/**
 * Get the name of the Cipher that is currently in use.
 *
 * Gets a text description of the cipher that is currently active, or
 * returns FALSE if TLS is not active (no cipher).  Note that the
 * cipher in use may change over time due to renegotiation or other
 * changes to the TLS state.
 *
 * @param[in] tls the tls client/server to query.
 * @param[in,out] buffer buffer of size bytes to hold cipher name
 * @param[in] size maximum number of bytes in buffer.
 * @return True if cipher name written to buffer, False if no cipher in use.
 */
PN_TLS_EXTERN bool pn_tls_get_cipher_name(pn_tls_t *tls, char *buffer, size_t size);

/**
 * Get the SSF (security strength factor) of the Cipher that is currently in use.
 *
 * @param[in] tls the tls client/server to query.
 * @return the ssf, note that 0 means no security.
 */
PN_TLS_EXTERN int pn_tls_get_ssf(pn_tls_t *tls);

/**
 * Get the name of the TLS protocol that is currently in use.
 *
 * Gets a text description of the TLS protocol that is currently active, or returns FALSE if TLS
 * is not active.  Note that the protocol may change over time due to renegotiation.
 *
 * @param[in] tls the tls client/server to query.
 * @param[in,out] buffer buffer of size bytes to hold the version identifier
 * @param[in] size maximum number of bytes in buffer.
 * @return True if the version information was written to buffer, False if TLS connection
 * not ready.
 */
PN_TLS_EXTERN bool pn_tls_get_protocol_name(pn_tls_t *tls, char *buffer, size_t size);

/**
 * Check whether the state has been resumed.
 *
 * Used for client session resume.  When called on an active session, indicates whether
 * the state has been resumed from a previous session.
 *
 * @note This is a best-effort service - there is no guarantee that the remote server will
 * accept the resumed parameters.  The remote server may choose to ignore these
 * parameters, and request a re-negotiation instead.
 *
 * @param[in] tls the tls session to check
 * @return status code indicating whether or not the session has been resumed.
 */
PN_TLS_EXTERN pn_tls_resume_status_t pn_tls_resume_status(pn_tls_t *tls);

/**
 * Set the expected identity of the remote peer.
 *
 * By default, TLS will use the hostname associated with the connection that
 * the transport is bound to (see ::pn_connection_set_hostname).  This method
 * allows the caller to override that default.
 *
 * The hostname is used for two purposes: 1) when set on an TLS client, it is sent to the
 * server during the handshake (if Server Name Indication is supported), and 2) it is used
 * to check against the identifying name provided in the peer's certificate. If the
 * supplied name does not exactly match a SubjectAltName (type DNS name), or the
 * CommonName entry in the peer's certificate, the peer is considered unauthenticated
 * (potential imposter), and the TLS connection is aborted.
 *
 * @note Verification of the hostname is only done if PN_TLS_VERIFY_PEER_NAME is enabled.
 * See ::pn_tls_domain_set_peer_authentication.
 *
 * @param[in] tls the tls session.
 * @param[in] hostname the expected identity of the remote. Must conform to the syntax as
 * given in RFC1034, Section 3.5.
 * @return 0 on success.
 */
PN_TLS_EXTERN int pn_tls_set_peer_hostname(pn_tls_t *tls, const char *hostname);

/**
 * Access the configured peer identity.
 *
 * Return the expected identity of the remote peer, as set by ::pn_tls_set_peer_hostname.
 *
 * @param[in] tls the tls session.
 * @param[out] hostname buffer to hold the null-terminated name string. If null, no string
 * is written.
 * @param[in,out] bufsize on input set to the number of octets in hostname. On output, set
 * to the number of octets needed to hold the value of hostname plus a null byte.  Zero if
 * no hostname set.
 * @return 0 on success.
 */
PN_TLS_EXTERN int pn_tls_get_peer_hostname(pn_tls_t *tls, char *hostname, size_t *bufsize);

/**
 * Get the subject from the peers certificate.
 *
 * @param[in] tls the tls client/server to query.
 * @return A null terminated string representing the full subject,
 * which is valid until the tls object is destroyed.
 */
PN_TLS_EXTERN const char* pn_tls_get_remote_subject(pn_tls_t *tls);

/**
 * Enumeration identifying the sub fields of the subject field in the tls certificate.
 */
typedef enum {
  PN_TLS_CERT_SUBJECT_COUNTRY_NAME,
  PN_TLS_CERT_SUBJECT_STATE_OR_PROVINCE,
  PN_TLS_CERT_SUBJECT_CITY_OR_LOCALITY,
  PN_TLS_CERT_SUBJECT_ORGANIZATION_NAME,
  PN_TLS_CERT_SUBJECT_ORGANIZATION_UNIT,
  PN_TLS_CERT_SUBJECT_COMMON_NAME
} pn_tls_cert_subject_subfield;

/**
 * Enumeration identifying hashing algorithm.
 */
typedef enum {
  PN_TLS_SHA1,   /* Produces hash that is 20 bytes long */
  PN_TLS_SHA256, /* Produces hash that is 32 bytes long */
  PN_TLS_SHA512, /* Produces hash that is 64 bytes long */
  PN_TLS_MD5     /* Produces hash that is 16 bytes long */
} pn_tls_hash_alg;

/**
 * Get the fingerprint of the certificate. The certificate fingerprint (as displayed in the Fingerprints section when
 * looking at a certificate with say the Firefox browser) is the hexadecimal hash of the entire certificate.
 * The fingerprint is not part of the certificate, rather it is computed from the certificate and can be used to uniquely identify a certificate.
 * @param[in] tls0 the tls client/server to query
 * @param[in] fingerprint char pointer. The certificate fingerprint (in hex format) will be populated in this array.
 *            If sha1 is the digest name, the fingerprint is 41 characters long (40 + 1 '\0' character), 65 characters long for
 *            sha256 and 129 characters long for sha512 and 33 characters for md5.
 * @param[in] fingerprint_length - Must be at >= 33 for md5, >= 41 for sha1, >= 65 for sha256 and >=129 for sha512.
 * @param[in] hash_alg the hash algorithm to use. Must be of type pn_tls_hash_alg (currently supports sha1, sha256, sha512 and md5)
 * @return error code - Returns 0 on success. Return a value less than zero if there were any errors. Upon execution of this function,
 *                      char *fingerprint will contain the appropriate null terminated hex fingerprint
 */
PN_TLS_EXTERN int pn_tls_get_cert_fingerprint(pn_tls_t *tls0,
                                          char *fingerprint,
                                          size_t fingerprint_length,
                                          pn_tls_hash_alg hash_alg);

/**
 * Returns a char pointer that contains the value of the sub field of the subject field in the tls certificate. The subject field usually contains the following sub fields -
 * C = ISO3166 two character country code
 * ST = state or province
 * L = Locality; generally means city
 * O = Organization - Company Name
 * OU = Organization Unit - division or unit
 * CN = CommonName
 * @param[in] tls0 the tls client/server to query
 * @param[in] field The enumeration pn_tls_cert_subject_subfield representing the required sub field.
 * @return A null terminated string which contains the requested sub field value which is valid until the tls object is destroyed.
 */
PN_TLS_EXTERN const char* pn_tls_get_remote_subject_subfield(pn_tls_t *tls, pn_tls_cert_subject_subfield field);

PN_TLS_EXTERN bool pn_tls_encrypted_pending(pn_tls_t *tls);
PN_TLS_EXTERN bool pn_tls_decrypted_pending(pn_tls_t *tls);


// return number of input buffers processed and encrypted buffers produced.  -1 if error.
// unencrypted_buffers_in:  array of buffers to encrypt.  const values copied
// encrypted destination_bufs (inout) array of buffers to hold encrypted data.  encrypted_destination_bufs[i].size updated.
// Not all input buffers necessarily processed, but always complete buffers.
PN_TLS_EXTERN ssize_t pn_tls_encrypt(pn_tls_t *tls, pn_raw_buffer_t const *unencrypted_buffers_in, size_t in_count, pn_raw_buffer_t *encrypted_destination_bufs, size_t dest_count, size_t *dest_written);

// return number of input buffers processed and decrypted buffers produced.  -1 if error.
PN_TLS_EXTERN ssize_t pn_tls_decrypt(pn_tls_t *tls, pn_raw_buffer_t const *encrypted_buffers_in, size_t in_count, pn_raw_buffer_t *decrypted_destination_bufs, size_t dest_count, size_t *dest_written);

// True if peers have negotiated a TLS session.  False indicates handshake in progress.
PN_TLS_EXTERN bool pn_tls_can_encrypt(pn_tls_t *tls);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* tls.h */
