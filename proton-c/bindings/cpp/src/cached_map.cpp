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

#include "proton/cached_map.hpp"
#include "proton/symbol.hpp"
#include "proton/annotation_key.hpp"
#include "proton/scalar.hpp"
#include <map>

namespace proton {

namespace internal {
template <class K, class V> class cached_map_impl {
  public:
    proton::value value_;
    std::map<K,V> map_;

    proton::value& flush_to_value() {
        if (!map_.empty() && value_.empty()) {
            codec::encoder e(value_);
            e << map_;
        }
        map_.clear();  // no more cache
        return value_;
    }

    void get_cache() {
        if (!value_.empty()) {
            map_.clear();
            codec::decoder d(value_);
            d.rewind();
            d >> map_;
            d.clear();
        }
    }

    // TODO: sanity check method to verify value content from user is of type map<K,V>
};
}


template <class K, class V> cached_map<K,V>::cached_map() : impl_(new internal::cached_map_impl<K,V>()) {}

template <class K, class V> cached_map<K,V>::cached_map(const cached_map<K,V>& x)
    : impl_(new internal::cached_map_impl<K,V>()) { *impl_ = *x.impl_; }

template <class K, class V> cached_map<K,V>& cached_map<K,V>::operator=(const cached_map& x) {
    *impl_ = *x.impl_;
    return *this;
}

template <class K, class V> cached_map<K,V>::~cached_map() {}

template <class K, class V> void cached_map<K,V>::set(const K &k, const V &v) {
    impl_->get_cache();
    impl_->map_[k] = v;
}

template <class K, class V> V cached_map<K,V>::get(const K &k) const {
    impl_->get_cache();
    typename std::map<K,V>::iterator i = impl_->map_.find(k);
    if (i != impl_->map_.end())
        return i->second;
    return V();
}

template <class K, class V> bool cached_map<K,V>::exists(const K &k) const {
    impl_->get_cache();
    return impl_->map_.find(k) != impl_->map_.end();
}

template <class K, class V> size_t cached_map<K,V>::size() const {
    impl_->get_cache();
    return impl_->map_.size();
}

template <class K, class V> void cached_map<K,V>::clear() {
    impl_->map_.clear();
    impl_->value_.clear();
}

template <class K, class V> bool cached_map<K,V>::empty() {
    return impl_->map_.empty() && impl_->value_.empty();
}

template <class K, class V> const proton::value& cached_map<K,V>::value() const {
    return impl_->flush_to_value();
}

template <class K, class V> proton::value& cached_map<K,V>::value() {
    return impl_->flush_to_value();
}

template <class K, class V> size_t cached_map<K,V>::erase(const K &k) {
    impl_->get_cache();
    return impl_->map_.erase(k);
}

template <class K, class V> typename cached_map<K,V>::key_range cached_map<K,V>::keys() const {
    impl_->get_cache();
    const_key_iterator end(impl_.get(), static_cast<K*>(0));
    if (impl_->map_.empty())
        return key_range(end, end);
    const_key_iterator begin(impl_.get(), const_cast<K*>(&impl_->map_.begin()->first));
    return key_range(begin, end);
}

template <class K, class V> typename cached_map<K,V>::const_key_iterator cached_map<K,V>::const_key_iterator::operator++() {
    if (this->impl_ && this->ptr_) {
        typename std::map<K,V>::iterator i = this->impl_->map_.find(*this->ptr_);
        if (i != this->impl_->map_.end())
            i++;
        if (i == this->impl_->map_.end())
            this->ptr_ =  static_cast<K*>(0);
        else {
            this->ptr_ =  const_cast<K*>(&i->first);
        }
    }
    return *this;
}

template class cached_map<symbol, value>;
template class cached_map<std::string, scalar>;
template class cached_map<annotation_key, value>;

void swap(cached_map<symbol, value>& x, cached_map<symbol, value>& y) {
    using std::swap;
    swap(x.impl_, y.impl_);
}
void swap(cached_map<std::string, scalar>& x, cached_map<std::string, scalar>& y) {
    using std::swap;
    swap(x.impl_, y.impl_);
}
void swap(cached_map<annotation_key, value>& x, cached_map<annotation_key, value>& y) {
    using std::swap;
    swap(x.impl_, y.impl_);
}


} // namespace proton

