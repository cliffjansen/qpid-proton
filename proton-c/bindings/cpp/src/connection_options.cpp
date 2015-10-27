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
#include "proton/connection_options.hpp"
#include "proton/reconnect_timer.hpp"
#include "proton/transport.hpp"
#include "contexts.hpp"
#include "connector.hpp"

#include "proton/transport.h"

namespace proton {

connection_options::connection_options(bool cloned) : cloned_(cloned) {}

connection_options::~connection_options() {
    if (cloned_)
        for (connection_options::const_iterator option = begin(); option != end(); ++option)
            delete *option;
}

connection_options::connection_options(const connection_option &o1) : cloned_(false) {
    append(o1);
}

connection_options::connection_options(const connection_option &o1, const connection_option &o2) : cloned_(false) {
    append(o1);
    append(o2);
}

connection_options::connection_options(const connection_option &o1, const connection_option &o2,
        const connection_option &o3) : cloned_(false) {
    append(o1);
    append(o2);
    append(o3);
}

connection_options::connection_options(const connection_option &o1, const connection_option &o2,
        const connection_option &o3, const connection_option &o4) : cloned_(false) {
    append(o1);
    append(o2);
    append(o3);
    append(o4);
}

connection_options::connection_options(const connection_option &o1, const connection_option &o2,
        const connection_option &o3, const connection_option &o4, const connection_option &o5) : cloned_(false) {
    append(o1);
    append(o2);
    append(o3);
    append(o4);
    append(o5);
}

connection_options::connection_options(const connection_option &o1, const connection_option &o2,
        const connection_option &o3, const connection_option &o4, const connection_option &o5,
        const connection_option &o6) : cloned_(false) {
    append(o1);
    append(o2);
    append(o3);
    append(o4);
    append(o5);
    append(o6);
}

void connection_options::apply(connection &connection) const {
    for (connection_options::const_iterator option = begin(); option != end(); ++option) {
        if ((*option)->test(connection))
            (*option)->apply(connection);
    }
}

bool connection_options::test(connection &connection) const {
    // True if any options are aplicable
    for (connection_options::const_iterator option = begin(); option != end(); ++option) {
        if ((*option)->test(connection))
            return true;
    }
    return false;
}

connection_option* connection_options::clone() const {
    connection_options *opts = new connection_options(true); // cloned = true
    opts->options_.reserve(options_.size());
    for (connection_options::const_iterator option = begin(); option != end(); ++option) {
        opts->append(**option);  // cloned copy
    }
    return opts;
}

void connection_options::append(const connection_option &opt) {
    if (cloned_)
        options_.push_back(opt.clone());
    else
        options_.push_back(const_cast<connection_option*>(&opt));
}

// The handler can't be "applied" after connection creation without
// mis-directing some early events.  This call looks for any
// connection_handler options to find the handler.
handler* connection_options::connection_handler() const {
    handler *h = 0;
    // Walk all options in order.  Last connection_handler trumps earlier ones.
    for (connection_options::const_iterator option = begin(); option != end(); ++option) {
        connection_options *co = dynamic_cast<connection_options*>(*option);
        if (co)
            h = co->connection_handler();
        else {
            class connection_handler *ch = dynamic_cast<class connection_handler*>(*option);
            if (ch)
                h = ch->get();
        }
    }
    return h;
}


bool transport_option::test(connection &connection) const {
    pn_transport_t *pnt = pn_connection_transport(pn_cast(&connection));
    // pnt is NULL between reconnect attempts
    if (!pnt) return false;
    connector *connector = dynamic_cast<class connector*>(connection_context::get(pn_cast(&connection)).handler.get());
    if (connector)
        // For outbound, transport bind can follow pn_connection_open
        return !connector->transport_configured();
    else
        return connection.state() & endpoint::LOCAL_UNINIT;
}


void max_frame_size::apply(connection &connection) const {
    pn_transport_set_max_frame(pn_cast(&connection.transport()), max_frame_size_);
}
connection_option* max_frame_size::clone() const { return new max_frame_size(max_frame_size_); }


void max_channels::apply(connection &connection) const {
    pn_transport_set_channel_max(pn_cast(&connection.transport()), max_channels_);
}
connection_option* max_channels::clone() const { return new max_channels(max_channels_); }


void idle_timeout::apply(connection &connection) const {
    pn_transport_set_idle_timeout(pn_cast(&connection.transport()), idle_timeout_);
}
connection_option* idle_timeout::clone() const { return new idle_timeout(idle_timeout_); }



reconnect::reconnect(const reconnect_timer &t) : reconnect_timer_(t) {}

bool reconnect::test(connection &connection) const {
    connector *connector = dynamic_cast<class connector*>(connection_context::get(pn_cast(&connection)).handler.get());
    // Apply only to outgoing connections prior to open
    return connector && connection.state() & endpoint::LOCAL_UNINIT;
}

void reconnect::apply(connection &connection) const {
    connector *connector = dynamic_cast<class connector*>(connection_context::get(pn_cast(&connection)).handler.get());
    connector->reconnect_timer(reconnect_timer_);
}

connection_option* reconnect::clone() const { return new reconnect(reconnect_timer_); }


connection_handler::connection_handler(handler *h) : handler_(h) {}

bool connection_handler::test(connection &connection) const {
    // Handler "applied" separately.  Must be provided at connection creation.
    return false;
}

void connection_handler::apply(connection &connection) const {}

connection_option* connection_handler::clone() const { return new connection_handler(handler_); }
handler* connection_handler::get() const { return handler_; }


bool container_id::test(connection &connection) const {
    return connection.state() & endpoint::LOCAL_UNINIT;
}
void container_id::apply(connection &connection) const {
    pn_connection_set_container(pn_cast(&connection), container_id_.c_str());
}
connection_option* container_id::clone() const { return new container_id(container_id_); }

} // namespace proton
