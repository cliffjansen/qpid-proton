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

#include "proton/internal/connector.hpp"
#include "proton/connection.hpp"
#include "proton/connection_options.hpp"
#include "proton/url.hpp"
#include "proton_bits.hpp"
#include "proton/reconnect_options.hpp"
#include "reconnect_options_impl.hpp"
#include <string>

namespace proton {
namespace internal {

connector::connector(pn_proactor_t *p, pn_connection_t *c, const connection_options &options, const std::string &addr) :
    proactor_(p), pnc(c), options(options), address(addr), retries(0)
{}

connector::~connector() {}

void connector::connect() {
    // TODO: this->stopping logic for reconnect?
    proton::url url(address);
    pn_connection_set_hostname(pnc, url.host().c_str());
    if (!url.user().empty())
        pn_connection_set_user(pnc, url.user().c_str());
    if (!url.password().empty())
        pn_connection_set_password(pnc, url.password().c_str());

    connection conn = make_wrapper(pnc);
    conn.open(options);
    // Figure out correct string len then create connection address
    int len = pn_proactor_addr(0, 0, url.host().c_str(), url.port().c_str());
    std::vector<char> caddr(len+1);
    pn_proactor_addr(&caddr[0], len+1, url.host().c_str(), url.port().c_str());
    pn_proactor_connect(proactor_, pnc, &caddr[0]);
}

void connector::reconnect_check() {
    reconnect_options::impl &ro(*reconnect->implref());
    if (ro.get_enabled() && ro.get_max_attempts() == 42 && retries == 0) {
        // bogus test values to try single connect
        retries++;
        pn_proactor_release_connection(pnc);
        connect();
    }
}

}}
