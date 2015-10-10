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
#include "proton/link_options.hpp"

namespace proton {

link_options::link_options() {}

link_options::link_options(const link_option &l1) {
    push_back(&l1);
}

link_options::link_options(const link_option &l1, const link_option &l2) {
    push_back(&l1);
    push_back(&l2);
}

link_options::link_options(const link_option &l1, const link_option &l2, const link_option &l3) {
    push_back(&l1);
    push_back(&l2);
    push_back(&l3);
}

link_options::link_options(const link_option &l1, const link_option &l2, const link_option &l3, const link_option &l4) {
    push_back(&l1);
    push_back(&l2);
    push_back(&l3);
    push_back(&l4);
}

void link_options::apply(link &link) const {
    for (link_options::const_iterator option = begin(); option != end(); ++option) {
        if ((*option)->test(link))
            (*option)->apply(link);
    }
}

selector::selector(const std::string &s, const std::string &name) : selector_(s), key_name_(name) {}

void selector::apply(link &l) const {
    encoder &enc = l.receiver().source().filter().encoder();
    bool map_required = enc.data().empty();
    if (map_required)  // not part of a set, i.e sole filter
        enc << start::map();
    enc << amqp_symbol(key_name_) << start::described()
        << amqp_symbol("apache.org:selector-filter:string") << amqp_binary(selector_)
        << finish();
    if (map_required)
        finish();
}

void browse_mode::apply(link &l) const {
    l.source().distribution_mode(terminus::COPY);
}

void move_mode::apply(link &l) const {
    l.source().distribution_mode(terminus::MOVE);
}

local_address::local_address(const std::string &addr) : address_(addr) {}

void local_address::apply(link &lnk) const {
    if (lnk.is_receiver())
        lnk.target().address(address_);
    else
        lnk.source().address(address_);
}

void durable_subscription::apply(link &l) const {
    terminus &source = l.receiver().source();
    source.durability(terminus::DELIVERIES);
    source.expiry_policy(terminus::EXPIRE_NEVER);
}

void at_most_once::apply(link &l) const {
    l.sender_settle_mode(link::SETTLED);
}

void at_least_once::apply(link &l) const {
    l.sender_settle_mode(link::UNSETTLED);
    l.receiver_settle_mode(link::SETTLE_ALWAYS);
}


} // namespace proton
