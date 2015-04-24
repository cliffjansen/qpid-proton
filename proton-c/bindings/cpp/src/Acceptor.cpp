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

#include "proton/cpp/Acceptor.h"
#include "proton/cpp/exceptions.h"
#include "Msg.h"

namespace proton {
namespace reactor {

Acceptor::Acceptor() : pnAcceptor(0) {}

Acceptor::Acceptor(pn_acceptor_t *a) : pnAcceptor(a)
{
    if (!pnAcceptor) throw ProtonException(MSG("NULL Proton acceptor object"));
    pn_incref(pnAcceptor);
}

Acceptor::~Acceptor() {
    if (pnAcceptor)
        pn_decref(pnAcceptor);
}

Acceptor::Acceptor(const Acceptor& l) : pnAcceptor(l.pnAcceptor) {
    if (pnAcceptor)
        pn_incref(pnAcceptor);
}

Acceptor& Acceptor::operator=(const Acceptor& l) {
    pnAcceptor = l.pnAcceptor;
    if (pnAcceptor)
        pn_incref(pnAcceptor);
    return *this;
}

void Acceptor::close() {
    if (pnAcceptor)
        pn_acceptor_close(pnAcceptor);
}

}} // namespace proton::reactor
