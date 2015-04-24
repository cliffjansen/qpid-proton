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

#include "Url.h"
#include "proton/cpp/exceptions.h"
#include "Msg.h"

namespace proton {
namespace reactor {

Url::Url(const std::string &url) : pnUrl(pn_url_parse(url.c_str()))
{
    if (!pnUrl)
        throw ProtonException(MSG("invalid URL: " << url));
    pn_incref(pnUrl);
}

Url::~Url() {
    pn_decref(pnUrl);
}

Url::Url(const Url& l) : pnUrl(l.pnUrl) {
    pn_incref(pnUrl);
}

Url& Url::operator=(const Url& l) {
    pnUrl = l.pnUrl;
    pn_incref(pnUrl);
    return *this;
}

std::string Url::getPort() {
    const char *p = pn_url_get_port(pnUrl);
    if (!p)
        return std::string("5672");
    else
        return std::string(p);
}

std::string Url::getHost() {
    const char *p = pn_url_get_host(pnUrl);
    if (!p)
        return std::string("0.0.0.0");
    else
        return std::string(p);
}

std::string Url::getPath() {
    const char *p = pn_url_get_path(pnUrl);
    if (!p)
        return std::string("");
    else
        return std::string(p);
}


}} // namespace proton::reactor
