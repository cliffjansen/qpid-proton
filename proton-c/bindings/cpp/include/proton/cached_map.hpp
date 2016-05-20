#ifndef PROTON_CPP_CACHED_MAP_H
#define PROTON_CPP_CACHED_MAP_H

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

#include <proton/internal/export.hpp>
#include <proton/value.hpp>
#include <proton/codec/map.hpp>
#include <proton/endpoint.hpp>
#include <proton/internal/pn_unique_ptr.hpp>

namespace proton {


///@cond INTERNAL
namespace internal {
template <class K, class V> class cached_map_impl;

template <class K, class D, class V> class const_key_iter_base {
  public:
    typedef K value_type;

    const K operator*() const { return *ptr_; }
    const K* operator->() const { return ptr_; }
    D operator++(int) { D x(*this); ++(*this); return x; }
    bool operator==(const const_key_iter_base<K, D, V>& x) const { return ptr_ == x.ptr_; }
    bool operator!=(const const_key_iter_base<K, D, V>& x) const { return ptr_ != x.ptr_; }
    ///@}
  protected:
    explicit const_key_iter_base(cached_map_impl<K,V> *i = 0, K* p = 0) : impl_(i), ptr_(p) {}
    cached_map_impl<K,V> *impl_;
    const K *ptr_;
};

template<class I> class cached_map_iter_range {
  public:
    typedef I const_Key_iterator;

    explicit cached_map_iter_range(I begin = I(), I end = I()) : begin_(begin), end_(end) {}
    I begin() const { return begin_; }
    I end() const { return end_; }
    bool empty() const { return begin_ == end_; }
  private:
    I begin_, end_;
};

} // namespace internal
///@endcond


/// A convenience class to view and manage AMQP map data contained in
/// a proton::value.  An internal cache of the map data is created as
/// needed.  If desired, a std::map can be extracted from or inserted
/// into the cached_map value directly.
template <class key_type, class value_type>
class PN_CPP_CLASS_EXPORT cached_map {
  public:
    class const_key_iterator: public internal::const_key_iter_base<key_type, const_key_iterator, value_type> {
      public:
        explicit const_key_iterator(internal::cached_map_impl<key_type, value_type> *impl = 0, key_type *p = 0)
            : internal::const_key_iter_base<key_type, const_key_iterator, value_type>(impl, p) {}
        PN_CPP_EXTERN const_key_iterator operator++();
    };
    typedef internal::cached_map_iter_range<const_key_iterator> key_range;

    /// Create an empty cached_map.
    PN_CPP_EXTERN cached_map();

    /// Copy a cached_map.
    PN_CPP_EXTERN cached_map(const cached_map&);

    /// Copy a cached_map.
    PN_CPP_EXTERN cached_map& operator=(const cached_map&);

    // TODO: c++11 move constructor and assignment

    PN_CPP_EXTERN ~cached_map();

    PN_CPP_EXTERN value_type get(const key_type&) const;
    PN_CPP_EXTERN void set(const key_type&, const value_type&);
    PN_CPP_EXTERN bool exists(const key_type&) const;
    PN_CPP_EXTERN size_t size() const;
    PN_CPP_EXTERN void clear();
    PN_CPP_EXTERN bool empty();
    PN_CPP_EXTERN size_t erase(const key_type&);
    PN_CPP_EXTERN key_range keys() const;
    PN_CPP_EXTERN const proton::value& value() const;
    PN_CPP_EXTERN proton::value& value();

    /// @cond INTERNAL
  private:
    cached_map(pn_data_t *);
    internal::pn_unique_ptr<internal::cached_map_impl<key_type, value_type> >impl_;
    friend class message;
    PN_CPP_EXTERN friend void swap(cached_map&, cached_map&);
    /// @endcond
};



}

#endif // PROTON_CPP_CACHED_MAP_H
