#ifndef PROTON_CPP_LINK_OPTIONS_H
#define PROTON_CPP_LINK_OPTIONS_H

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
#include "proton/export.hpp"
#include "proton/link.hpp"
#include <vector>

namespace proton {

class link;

/** Base class for specifying a configurable link option. */
class link_option {
  public:
    /** Apply the option to the link. */
    PN_CPP_EXTERN virtual void apply(link &link) const = 0;

    /** True if the option is applicable to the link. */
    PN_CPP_EXTERN virtual bool test(link &link) const { return true; }

    PN_CPP_EXTERN virtual ~link_option() {}
};

/** An ordered collection of link_option specifiers. */
class link_options : public std::vector<const link_option *> {
  public:
    PN_CPP_EXTERN link_options();
    /** Convenience constuctor, adds link_option */
    PN_CPP_EXTERN link_options(const link_option &l1);
    /** Convenience constuctor, adds link_options in order */
    PN_CPP_EXTERN link_options(const link_option &l1, const link_option &l2);
    /** Convenience constuctor, adds link_options in order */
    PN_CPP_EXTERN link_options(const link_option &l1, const link_option &l2, const link_option &l3);
    /** Convenience constuctor, adds link_options in order */
    PN_CPP_EXTERN link_options(const link_option &l1, const link_option &l2, const link_option &l3, const link_option &l4);

    /** Apply each link_option to the link in order if the option is
        applicable to the link (link_option::test(link) is true).  A
        later link_option will override an earlier one if they
        conflict. */
    PN_CPP_EXTERN void apply(link &link) const;
};


/** Abstract base class for specifying a configurable receiving link option. */
class receiver_option : public link_option {
  public:
    /** True if the option is applicable to the link. */
    PN_CPP_EXTERN virtual bool test(link &link) { return link.is_receiver(); }
};


/** A link option for a selector on a receiving link. */
class selector : public receiver_option {
  public:
    PN_CPP_EXTERN selector(const std::string &selector, const std::string &name = std::string("selector"));
    PN_CPP_EXTERN virtual void apply(link &link) const;
  private:
    std::string selector_;
    std::string key_name_;
};

/** A link option specifying a browsing receiver by setting COPY distribution mode on the link. */
class browse_mode : public receiver_option {
  public:
    PN_CPP_EXTERN virtual void apply(link &link) const;
};

/** An alternate name for a browsing receiver link option. This sets the AMQP COPY
    distribution mode on a receiver link. */
typedef browse_mode copy_mode;

/** A link option specifying a consuming receiver by setting MOVE distribution mode on the link. */
class move_mode : public receiver_option {
  public:
    PN_CPP_EXTERN virtual void apply(link &link) const;
};



/** A link option specifying the local terminus address for the link. */
class local_address : public link_option {
  public:
    PN_CPP_EXTERN local_address(const std::string &addr);
    PN_CPP_EXTERN virtual void apply(link &link) const;
  private:
    std::string address_;
};

/** A link option specifying a durable subscription. */
class durable_subscription : public receiver_option {
  public:
    PN_CPP_EXTERN virtual void apply(link &link) const;
};

class at_most_once : public link_option {
  public:
    PN_CPP_EXTERN virtual void apply(link &link) const;
};

class at_least_once : public link_option {
  public:
    PN_CPP_EXTERN virtual void apply(link &link) const;
};


} // namespace

#endif  /*!PROTON_CPP_LINK_OPTIONS_H*/
