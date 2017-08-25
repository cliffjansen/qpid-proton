#ifndef PROTON_CPP_RECONNECT_OPTIONSIMPL_H
#define PROTON_CPP_RECONNECT_OPTIONSIMPL_H

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


namespace proton {

template <class T> struct option {
    T value;
    bool set;

    option() : value(), set(false) {}
    option& operator=(const T& x) { value = x;  set = true; return *this; }
    void update(const option<T>& x) { if (x.set) *this = x.value; }
};

class reconnect_options::impl {
  public:
    option<bool> enabled;
    option<duration> initial_delay;
    option<duration> delay;
    option<float> delay_multiplier;
    option<duration> max_delay;
    option<int> max_attempts;

    void update(const impl& x) {
        enabled.update(x.enabled);
        initial_delay.update(x.initial_delay);
        delay.update(x.delay);
        delay_multiplier.update(x.delay_multiplier);
        max_delay.update(x.max_delay);
        max_attempts.update(x.max_attempts);
    }

    bool get_enabled() { return enabled.set ? enabled.value : true; }
    duration get_initial_delay() { return initial_delay.set ? initial_delay.value : duration(0); }
    duration get_delay() { return delay.set ? delay.value : duration(10); }
    float get_delay_multiplier() { return delay_multiplier.set ? delay_multiplier.value : 2.0; }
    duration get_max_delay() { return max_delay.set ? max_delay.value : duration::FOREVER; }
    int get_max_attempts() { return max_attempts.set ? max_attempts.value : -1; }

    friend class internal::connector;

};

}

#endif  /*!PROTON_CPP_RECONNECT_OPTIONSIMPL_H*/
