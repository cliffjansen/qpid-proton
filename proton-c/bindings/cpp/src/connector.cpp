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

#include "proton/connection.hpp"
#include "proton/transport.hpp"
#include "proton/container.hpp"
#include "proton/event.hpp"
#include "proton/connection.h"
#include "proton/url.hpp"
#include "proton/reconnect_timer.hpp"
#include "connector.hpp"
#include "container_impl.hpp"

#include "proton/transport.h"

namespace proton {

connector::connector(connection &c, const connection_options *opts) : connection_(&c), options_(true),
        reconnect_timer_(0), transport_configured_(false) {
    const connection_options &defaults = connection_->container().impl_->client_connection_options();
    if (defaults.size())
        options_.append(defaults);  // clone so that later changes to defaults do not affect reconnects
    if (opts && opts->size())
        options_.append(*opts);
}

connector::~connector() { delete reconnect_timer_; }

void connector::address(const url &a) {
    address_ = a;
}

void connector::apply_options() {
    if (connection_)
        options_.apply(*connection_);
}

bool connector::transport_configured() { return transport_configured_; }

void connector::reconnect_timer(const class reconnect_timer &rt) {
    delete reconnect_timer_;
    reconnect_timer_ = new class reconnect_timer(rt);
    reconnect_timer_->reactor_ = &connection_->container().reactor();
}

void connector::connect() {
    pn_connection_t *conn = pn_cast(connection_);
    pn_connection_set_container(conn, connection_->container().id().c_str());
    pn_connection_set_hostname(conn, address_.host_port().c_str());
    counted_ptr<transport> tp = counted_ptr<transport>(transport::cast(pn_transport()), false);
    tp->bind(*connection_);
    // Apply options to the new transport.
    options_.apply(*connection_);
    transport_configured_ = true;
}

void connector::on_connection_local_open(event &e) {
    connect();
}

void connector::on_connection_remote_open(event &e) {
    if (reconnect_timer_) {
        reconnect_timer_->reset();
    }
}

void connector::on_connection_init(event &e) {
}

void connector::on_transport_tail_closed(event &e) {
    on_transport_closed(e);
}

void connector::on_transport_closed(event &e) {
    if (!connection_) return;
    if (connection_->state() & endpoint::LOCAL_ACTIVE) {
        if (reconnect_timer_) {
            e.connection().transport().unbind();
            transport_configured_ = false;
            int delay = reconnect_timer_->next_delay();
            if (delay >= 0) {
                if (delay == 0) {
                    // log "Disconnected, reconnecting..."
                    connect();
                    return;
                }
                else {
                    // log "Disconnected, reconnecting in " <<  delay << " milliseconds"
                    connection_->container().schedule(delay, this);
                    return;
                }
            }
        }
    }
    pn_connection_release(pn_cast(connection_));
    connection_  = 0;
}

void connector::on_timer_task(event &e) {
    connect();
}

}
