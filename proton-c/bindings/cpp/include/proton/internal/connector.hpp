#ifndef PROTON_INTERNAL_CONNECTOR_HPP
#define PROTON_INTERNAL_CONNECTOR_HPP

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

#include <string>
#include "proton/connection.hpp"
#include "proton/connection_options.hpp"
#include "proton/connection.h"
#include "proton/proactor.h"

namespace proton {
namespace internal {

/// For outgoing (client) connections and reconnect.
/// Remember connection_options for life of connection.
/// Hold logic and state for reconnect and failover.

class connector {
  public:
    connector(pn_proactor_t *p, pn_connection_t *c, const connection_options &options, const std::string&);
    ~connector();
    void reconnect_check();
    void connect();
    pn_proactor_t* proactor_;
    pn_connection_t *pnc;
    const connection_options options;
    const std::string address;
    int retries;
    class reconnect_options *reconnect;
};

} // internal
} // proton

#endif // PROTON_INTERNAL_CONNECTOR_HPP
