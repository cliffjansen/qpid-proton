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
#include "proton/transport.hpp"
#include "proton/connection.hpp"
#include "msg.hpp"
#include "proton/transport.h"
#include "proton/error.h"

namespace proton {

connection* transport::connection() const {
    return connection::cast(pn_transport_connection(pn_cast(this)));
}

void transport::unbind() {
    if (pn_transport_unbind(pn_cast(this)))
        throw error(MSG("transport::unbind failed " << pn_error_text(pn_transport_error(pn_cast(this)))));
}

void transport::bind(class connection &conn) {
    if (pn_transport_bind(pn_cast(this), pn_cast(&conn)))
        throw error(MSG("transport::bind failed " << pn_error_text(pn_transport_error(pn_cast(this)))));
}

uint32_t transport::max_frame_size() const {
    return pn_transport_get_max_frame(pn_cast(this));
}

uint32_t transport::remote_max_frame_size() const {
    return pn_transport_get_remote_max_frame(pn_cast(this));
}

uint16_t transport::max_channels() const {
    return pn_transport_get_channel_max(pn_cast(this));
}

uint16_t transport::remote_max_channels() const {
    return pn_transport_remote_channel_max(pn_cast(this));
}

uint32_t transport::idle_timeout() const {
    return pn_transport_get_idle_timeout(pn_cast(this));
}

uint32_t transport::remote_idle_timeout() const {
    return pn_transport_get_remote_idle_timeout(pn_cast(this));
}

}
