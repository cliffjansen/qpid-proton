#ifndef PROTON_CPP_CONNECTION_OPTIONS_H
#define PROTON_CPP_CONNECTION_OPTIONS_H

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
#include "proton/types.hpp"
#include "proton/reconnect_timer.hpp"
#include "proton/config.hpp"

#include <vector>

namespace proton {

class handler;
class connection;

/** Base class for specifying a configurable connection option. */
class connection_option {
  public:
    /** Create a copy of the connection option */
    PN_CPP_EXTERN virtual connection_option* clone() const = 0;

    PN_CPP_EXTERN virtual ~connection_option() {}
  protected:
    // All connectionoptions are the same size.  Use impl if more storage required.
    void *impl_;
  private:
    friend class connection_options;
    /** Apply the option to the connection. */
    PN_CPP_EXTERN virtual void apply(connection &connection) const = 0;
    /** True if the option is applicable to the connection. */
    PN_CPP_EXTERN virtual bool test(connection &connection) const { return true; }
};

/** An ordered collection of connection_option specifiers. A
        later connection_option will override an earlier one if they
        conflict. connection_options can be nested. */
class connection_options : public connection_option {
  public:
    typedef std::vector<connection_option *>::const_iterator const_iterator;
    PN_CPP_EXTERN connection_options(bool cloned = false);
    /** If cloned, also deletes each contained connection_option */
    PN_CPP_EXTERN ~connection_options();
    /** Convenience constuctor, adds connection_option */
    PN_CPP_EXTERN connection_options(const connection_option &);
    /** Convenience constuctor, adds 2 connection_options in order */
    PN_CPP_EXTERN connection_options(const connection_option &, const connection_option &);
    /** Convenience constuctor, adds 3 connection_options in order */
    PN_CPP_EXTERN connection_options(const connection_option &, const connection_option &,
                                         const connection_option &);
    /** Convenience constuctor, adds 4 connection_options in order */
    PN_CPP_EXTERN connection_options(const connection_option &, const connection_option &,
                                         const connection_option &, const connection_option &);
    /** Convenience constuctor, adds 5 connection_options in order */
    PN_CPP_EXTERN connection_options(const connection_option &, const connection_option &,
                                         const connection_option &, const connection_option &,
                                         const connection_option &);
    /** Convenience constuctor, adds 6 connection_options in order */
    PN_CPP_EXTERN connection_options(const connection_option &, const connection_option &,
                                         const connection_option &, const connection_option &,
                                         const connection_option &, const connection_option &);
    /** Allocate a new connection_options that contains a clone of each contained connection_object.  */
    PN_CPP_EXTERN virtual connection_option* clone() const;
    PN_CPP_EXTERN bool cloned() const { return cloned_; }
    /** If cloned, append opt.clone() and manage the new connection object on destruction.  Otherwise append the refence to the existing connection_option. */
    PN_CPP_EXTERN void append(const connection_option &);
    PN_CPP_EXTERN size_t size () const { return options_.size(); }
    PN_CPP_EXTERN const_iterator begin () const { return options_.begin(); }
    PN_CPP_EXTERN const_iterator end () const { return options_.end(); }
    /** Apply each connection_option to the connection in order if the option is
        applicable to the connection (connection_option::test(connection) is true).  A
        later connection_option will override an earlier one if they
        conflict. */
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
    /** True if any options are applicable to the connection. */
    PN_CPP_EXTERN virtual bool test(connection &connection) const;
    /** Return the last handler in the collection. */
    PN_CPP_EXTERN handler* connection_handler() const;

  private:
    std::vector<connection_option *> options_;
    bool cloned_;
};


/** Abstract base class for specifying a transport option. A
    connection can have multiple transports during its lifetime. */
class transport_option : public connection_option {
  private:
    /** True if the connection has an unopened transport. */
    PN_CPP_EXTERN virtual bool test(connection &connection) const;
};


/** Maximum frame size connection option. */
class max_frame_size : public transport_option {
  public:
    PN_CPP_EXTERN max_frame_size(uint32_t max) : max_frame_size_(max) {}
    PN_CPP_EXTERN virtual connection_option* clone() const;
  private:
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
    uint32_t max_frame_size_;
};

/** Maximum number of open sessions on a connection. */
class max_channels : public transport_option {
  public:
    PN_CPP_EXTERN max_channels(uint16_t max) : max_channels_(max) {}
    PN_CPP_EXTERN virtual connection_option* clone() const;
  private:
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
    uint16_t max_channels_;
};

/** Specify the maximum inactivity time on a connection without disconnecting (in milliseconds). */
class idle_timeout : public transport_option {
  public:
    PN_CPP_EXTERN idle_timeout(uint32_t t) : idle_timeout_(t) {}
    PN_CPP_EXTERN virtual connection_option* clone() const;
  private:
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
    uint32_t idle_timeout_;
};
/** An alternate name for specifying the idle timeout on a connection. */
typedef idle_timeout heartbeat;

/** Specify the container name associated with the connection. */
class container_id : public connection_option {
  public:
    PN_CPP_EXTERN container_id(const std::string &id) : container_id_(id) {}
    PN_CPP_EXTERN virtual connection_option* clone() const;
  private:
    PN_CPP_EXTERN virtual bool test(connection &connection) const;
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
    const std::string container_id_;
};

/** Specify a reconnection timer for a connection. */
class reconnect : public connection_option {
  public:
    PN_CPP_EXTERN reconnect(const reconnect_timer &);
    PN_CPP_EXTERN virtual connection_option* clone() const;
  private:
    reconnect_timer reconnect_timer_;
    PN_CPP_EXTERN virtual bool test(connection &connection) const;
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
};

class connection_handler : public connection_option {
  public:
    PN_CPP_EXTERN connection_handler(handler *);
    PN_CPP_EXTERN virtual connection_option* clone() const;
    handler *get() const;
  private:
    handler *handler_;
    PN_CPP_EXTERN virtual bool test(connection &connection) const;
    PN_CPP_EXTERN virtual void apply(connection &connection) const;
};

} // namespace

#endif  /*!PROTON_CPP_CONNECTION_OPTIONS_H*/
