#ifndef PROTON_SESSION_H
#define PROTON_SESSION_H 1

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
#include <proton/type_compat.h>
#include <proton/types.h>
#include <proton/error.h>
#include <proton/condition.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * @copybrief session
 *
 * @addtogroup session
 * @{
 */

/**
 * Factory for creating a new session on a given connection object.
 *
 * Creates a new session object and adds it to the set of sessions
 * maintained by the connection object.
 *
 * @param[in] connection the connection object
 * @return a pointer to the new session
 */
PN_EXTERN pn_session_t *pn_session(pn_connection_t *connection);

/**
 * Free a session object.
 *
 * When a session is freed it will no longer be retained by the
 * connection once any internal references to the session are no
 * longer needed. Freeing a session will free all links on that
 * session and settle any deliveries on those links.
 *
 * @param[in] session the session object to free (or NULL)
 */
PN_EXTERN void pn_session_free(pn_session_t *session);

/**
 * Get the application context that is associated with a session
 * object.
 *
 * The application context for a session may be set using
 * ::pn_session_set_context.
 *
 * @param[in] session the session whose context is to be returned.
 * @return the application context for the session object
 */
PN_EXTERN void *pn_session_get_context(pn_session_t *session);

/**
 * Set a new application context for a session object.
 *
 * The application context for a session object may be retrieved
 * using ::pn_session_get_context.
 *
 * @param[in] session the session object
 * @param[in] context the application context
 */
PN_EXTERN void pn_session_set_context(pn_session_t *session, void *context);

/**
 * Get the attachments that are associated with a session object.
 *
 * @param[in] session the session whose attachments are to be returned.
 * @return the attachments for the session object
 */
PN_EXTERN pn_record_t *pn_session_attachments(pn_session_t *session);

/**
 * Get the endpoint state flags for a session.
 *
 * @param[in] session the session object
 * @return the session's state flags
 */
PN_EXTERN pn_state_t pn_session_state(pn_session_t *session);

/**
 * **Deprecated** - Use ::pn_session_condition().
 *
 * Get additional error information associated with the session.
 *
 * Whenever a session operation fails (i.e. returns an error code),
 * additional error details can be obtained using this function. The
 * error object that is returned may also be used to clear the error
 * condition.
 *
 * The pointer returned by this operation is valid until the
 * session object is freed.
 *
 * Deprecation notice: note that this will always return an empty
 * error object
 *
 * @param[in] session the session object
 * @return the session's error object
 */
/* PN_DEPRECATED("Use pn_session_condition") */
PN_EXTERN pn_error_t *pn_session_error(pn_session_t *session);

/**
 * Get the local condition associated with the session endpoint.
 *
 * The ::pn_condition_t object retrieved may be modified prior to
 * closing the session in order to indicate a particular condition
 * exists when the session closes. This is normally used to
 * communicate error conditions to the remote peer, however it may
 * also be used in non error cases. See ::pn_condition_t for more
 * details.
 *
 * The pointer returned by this operation is valid until the session
 * object is freed.
 *
 * @param[in] session the session object
 * @return the session's local condition object
 */
PN_EXTERN pn_condition_t *pn_session_condition(pn_session_t *session);

/**
 * Get the remote condition associated with the session endpoint.
 *
 * The ::pn_condition_t object retrieved may be examined in order to
 * determine whether the remote peer was indicating some sort of
 * exceptional condition when the remote session endpoint was
 * closed. The ::pn_condition_t object returned may not be modified.
 *
 * The pointer returned by this operation is valid until the
 * session object is freed.
 *
 * @param[in] session the session object
 * @return the session's remote condition object
 */
PN_EXTERN pn_condition_t *pn_session_remote_condition(pn_session_t *session);

/**
 * Get the parent connection for a session object.
 *
 * This operation retrieves the parent pn_connection_t object that
 * contains the given pn_session_t object.
 *
 * @param[in] session the session object
 * @return the parent connection object
 */
PN_EXTERN pn_connection_t *pn_session_connection(pn_session_t *session);

/**
 * Open a session.
 *
 * Once this operation has completed, the PN_LOCAL_ACTIVE state flag
 * will be set.
 *
 * @param[in] session the session object
 */
PN_EXTERN void pn_session_open(pn_session_t *session);

/**
 * Close a session.
 *
 * Once this operation has completed, the PN_LOCAL_CLOSED state flag
 * will be set. This may be called without calling
 * ::pn_session_open, in this case it is equivalent to calling
 * ::pn_session_open followed by ::pn_session_close.
 *
 * @param[in] session the session object
 */
PN_EXTERN void pn_session_close(pn_session_t *session);

/**
 * Get the incoming capacity of the session measured in bytes.
 *
 * The incoming capacity of a session determines how much incoming
 * message data the session can buffer.
 *
 * @param[in] session the session object
 * @return the incoming capacity of the session in bytes
 */
PN_EXTERN size_t pn_session_get_incoming_capacity(pn_session_t *session);

/**
 * Set the incoming capacity for a session object.
 *
 * See ::pn_session_set_incoming_window_and_lwm for finer grained control of
 * session input buffering.  The use of
 * ::pn_session_set_incoming_window_and_lwm and
 * ::pn_session_set_incoming_capacity at the same time is not supported.
 *
 * The incoming capacity of a session determines how much incoming message
 * data the session can buffer, by governing the size of the session
 * incoming-window for transfer frames. This happens in concert with the
 * transport max frame size, and only when both values have been set.
 *
 * NOTE: If set, this value must be greater than or equal to the negotiated
 * frame size of the transport. The window is computed as a whole number of
 * frames when dividing remaining capacity at a given time by the connection
 * max frame size. As such, capacity and max frame size should be chosen so
 * as to ensure the frame window isn't unduly small and limiting performance.
 *
 * @param[in] session the session object
 * @param[in] capacity the incoming capacity for the session in bytes
 *
 * @internal XXX Deprecate in future.
 */
PN_EXTERN void pn_session_set_incoming_capacity(pn_session_t *session, size_t capacity);

/**
 * Get the maximum incoming window window for a session object.
 *
 * The maximum incoming window can be set by ::pn_session_set_incoming_window_and_lwm.
 *
 * @param[in] session the session object
 * @return the maximum size of the incoming window or 0 if not set.
 **/
PN_EXTERN pn_frame_count_t pn_session_get_incoming_window(pn_session_t *session);

/**
 * Get the low water mark for the session incoming window.
 *
 * The low water mark governs how frequently the session updates the remote
 * peer with changes to the incoming window.
 *
 * A value of zero indicates that Proton will choose a default strategy for
 * updating the peer.
 *
 * The low water mark can be set by ::pn_session_set_incoming_window_and_lwm.
 *
 * @param[in] session the session object
 * @return the low water mark of incoming window.
 **/
PN_EXTERN pn_frame_count_t pn_session_get_incoming_window_lwm(pn_session_t *session);

/**
 * Set the maximum incoming window and low water mark for a session object.
 *
 * The session incoming window is a count of the number of transfer
 * frames that can be accepted and buffered locally by the session
 * object until processed by the application (i.e. consumed by ::pn_link_recv
 * or dropped by ::pn_link_advance).  This window frame count decreases 1-1
 * with incoming frames.  It increases proportionally to the bytes processed
 * by the application such that if the peer uses up the incoming window, the
 * session object will buffer at most incoming_window * max_frame_size bytes.
 *
 * The low water mark (lwm) specifies the lowest incoming window count
 * monitored by the session before it starts sending flow frames to the peer
 * to inform it when the window has changed.  Too many flow frames can delay
 * other traffic on the connection without providing improved performance on
 * the session.  Too few can leave the remote sender frequently unable to send
 * due to a closed window.  The best balance is application specific and can
 * vary with time.  Note that the session incoming window is always updated
 * along with the link credit on any of its child links, so the frequency of
 * link credit updates is also a consideration when choosing a low water mark.
 *
 * The low water mark must be less than or equal to the incoming window.  If
 * set to zero, Proton will choose a default strategy for updating the
 * incoming window.
 *
 * This setting can be changed at any time during the life of the session.  If
 * the inbound maximum frame size for the connection/transport is not set at
 * the time the session is started, this setting has no effect.
 *
 * @param[in] session the session object
 * @param[in] window the maximum incoming window buffered by the session
 * @param[in] lwm the low water mark (or 0 for default window updating)
 * @return 0 on success, PN_ARG_ERROR if window is zero or lwm is greater than window
 */
PN_EXTERN int pn_session_set_incoming_window_and_lwm(pn_session_t *session, pn_frame_count_t window, pn_frame_count_t lwm);

/**
 * Get the remote view of the incoming window for the session.
 *
 * This evaluates to the most recent incoming window value communicated by the
 * peer minus any subsequent transfer frames for the session that have been
 * sent.  It does not include transfer frames that may be created in future
 * for locally buffered content tracked by @ref pn_session_outgoing_bytes.
 *
 * @param[in] session the session object
 * @return the remote incoming window
 */
PN_EXTERN pn_frame_count_t pn_session_remote_incoming_window(pn_session_t *session);

/**
 * Get the outgoing window for a session object.
 *
 * @param[in] session the session object
 * @return  the outgoing window for the session
 */
PN_EXTERN size_t pn_session_get_outgoing_window(pn_session_t *session);

/**
 * Set the outgoing window for a session object.
 *
 * @param[in] session the session object
 * @param[in] window the outgoing window for the session
 */
PN_EXTERN void pn_session_set_outgoing_window(pn_session_t *session, size_t window);

/**
 * Get the number of outgoing bytes currently buffered by a session.
 *
 * @param[in] session the session object
 * @return the number of outgoing bytes currently buffered
 */
PN_EXTERN size_t pn_session_outgoing_bytes(pn_session_t *session);

/**
 * Get the number of incoming bytes currently buffered by a session.
 *
 * @param[in] session the session object
 * @return the number of incoming bytes currently buffered
 */
PN_EXTERN size_t pn_session_incoming_bytes(pn_session_t *session);

/**
 * Retrieve the first session from a given connection that matches the
 * specified state mask.
 *
 * Examines the state of each session owned by the connection, and
 * returns the first session that matches the given state mask. If
 * state contains both local and remote flags, then an exact match
 * against those flags is performed. If state contains only local or
 * only remote flags, then a match occurs if any of the local or
 * remote flags are set respectively.
 *
 * @param[in] connection to be searched for matching sessions
 * @param[in] state mask to match
 * @return the first session owned by the connection that matches the
 * mask, else NULL if no sessions match
 */
PN_EXTERN pn_session_t *pn_session_head(pn_connection_t *connection, pn_state_t state);

/**
 * Retrieve the next session from a given connection that matches the
 * specified state mask.
 *
 * When used with ::pn_session_head, application can access all
 * sessions on the connection that match the given state. See
 * ::pn_session_head for description of match behavior.
 *
 * @param[in] session the previous session obtained from
 *                    ::pn_session_head or ::pn_session_next
 * @param[in] state mask to match.
 * @return the next session owned by the connection that matches the
 * mask, else NULL if no sessions match
 */
PN_EXTERN pn_session_t *pn_session_next(pn_session_t *session, pn_state_t state);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* session.h */
