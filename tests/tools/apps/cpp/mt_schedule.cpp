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

#include "options.hpp"

#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/default_container.hpp>
#include <proton/delivery.hpp>
#include <proton/link.hpp>
#include <proton/message.hpp>
#include <proton/message_id.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/thread_safe.hpp>
#include <proton/value.hpp>
#include <proton/receiver_options.hpp>
#include <proton/tracker.hpp>
#include <proton/listener.hpp>
#include <proton/target.hpp>
#include <proton/target_options.hpp>

#include <iostream>
#include <map>
#include <deque>
#include <stdexcept>

#include "fake_cpp11.hpp"

#include <pthread.h>
#include <unistd.h>

/*
 * Escrow sequence is:
 *
 * T: allocate credit to generator(s)
 * G: send message
 * T: receive message, schedule() offer to Moneybags
 * M: schedule() payment to trustee
 * T: exchange: send message to Moneybags, schedule() trust money payment to G
 * G: process inbound payment
 * M: receive and accept message
 * T: on settle from M, schedule() cleanup of this escrow on same container
 * T: new callback for cleanup, tidy up all escrow resources
 *
 * N Generators, 1 Trustee, 1 Moneybags
 * Each has its own container and event loop
 * Each escrow has 4 schedule() calls: 3 are inter-container, 1 is within the same container.
 */

class tst_thread {
  public:
    tst_thread(void *(*f) (void *), void *arg) : start_routine_(f), arg_(arg) {}
    void start() {
        if(pthread_create(&tid, NULL, start_routine_, arg_))
            throw std::runtime_error("thread create problem");
    }
    void join () {
        void *unused;
        if (pthread_join(tid, &unused))
            throw std::runtime_error("thread join problem");
    }
  private:
    void *(*start_routine_) (void *);
    void *arg_;
    pthread_t tid;
};


class tst_mutex {
  public:
    tst_mutex() { 
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        if (pthread_mutex_init(&pmt, &attr)) {
            throw proton::error("pthread mutex init failure");
        }
    }
    ~tst_mutex() { pthread_mutex_destroy(&pmt); }
    void lock() { pthread_mutex_lock(&pmt); }
    void unlock() { pthread_mutex_unlock(&pmt); }
  private:
    pthread_mutex_t pmt;
    tst_mutex( const tst_mutex& other ); // non copyable
    tst_mutex& operator=( const tst_mutex& ); // non copyable
};

class tst_lock_guard {
  public:
    tst_lock_guard(tst_mutex &m) : mutex_(m) { mutex_.lock(); }
    ~tst_lock_guard() { mutex_.unlock(); }
  private:
    tst_mutex &mutex_;
};


class config;
class escrow;
using namespace proton;


class trustee {
  public:
    trustee(config &c);
    ~trustee();
    void run();
    void sync();  // global sync, mostly for setup and shutdown to keep helgrind happy
    void park_payment(int id);
    bool succeeded();
    void cleanup(escrow &);
private:
    class impl;
    impl *impl_;
    friend class config;
};

class config {
  public:
    config(int n): target_(n) { tst_lock_guard g(mutex_); }
    trustee& get_trustee() { tst_lock_guard g(mutex_); return *trustee_; }
    void add_generator(int credit) { tst_lock_guard g(mutex_); generator_credits_.push_back(credit); }
    std::string host_port() { return trustee_host_port_; }
    int target() { return target_; }
    int get_credit(int idx) { return generator_credits_[idx]; }
    void sync() { tst_lock_guard g(mutex_); }
    tst_mutex global_send_mutex_;  // helgrind and sender.cpp "tag_counter"
  private:
    tst_mutex mutex_; // for helgrind, picky, picky
    int target_; // number of desired escrows
    std::vector<int> generator_credits_;
    std::string trustee_host_port_;
    trustee *trustee_;
    friend class trustee::impl;
};


class generator : public messaging_handler {
  public:
    void run() { 
        { tst_lock_guard g(mutex_); }
        trustee_.sync();
        container_->run();
        trustee_.sync();
    }

    void on_container_start(proton::container &c) OVERRIDE {
        std::string url = host_port_ + '/' + c.id();
        c.open_sender(url);
    }

    void on_sendable(proton::sender &s) OVERRIDE {
        while (s.credit()) {
            message msg;
            std::string payload("very valuable content");
            msg.body(payload);
            {
                tst_lock_guard g(*send_mutex_);
                s.send(msg);
            }
            sent_++;
        }
    }

    void on_tracker_accept(tracker &t) OVERRIDE { confirmed_++; }

    // Called from other threads
    generator(config &c, int n) : 
        trustee_(c.get_trustee()),
        send_mutex_(&c.global_send_mutex_),
        host_port_(c.host_port()),
        do_confirm_payment(*this),
        sent_(0),
        confirmed_(0),
        payed_up_(0),
        id_(n)
    {
        tst_lock_guard g(mutex_);
        container_ = new container(*this, std::string("generator") + std::string(n, 'X'));
    }

    ~generator() { delete container_; }

    int id() { return id_; }

    bool succeeded() { 
        // std::cout << sent_ << ' ' << payed_up_ <<  ' '<< confirmed_ << '\n';
        return (sent_ == payed_up_ ) && (sent_ == confirmed_);
    }

    void take_payment() {
        // call without lock
        container_->schedule(duration::IMMEDIATE, do_confirm_payment);
    }

  private:
    void confirm_payment() {
        payed_up_++;
    }

    struct confirm_payment_fn : public void_function0 {
        generator& parent_;
        confirm_payment_fn(generator& p) : parent_(p) {}
        void operator()() { parent_.confirm_payment(); }
    };

    trustee &trustee_;
    tst_mutex *send_mutex_;
    std::string host_port_;
    container *container_;
    confirm_payment_fn do_confirm_payment;
    tst_mutex mutex_;
    int sent_;
    int confirmed_;
    int payed_up_;
    int id_;
};

class moneybags : public messaging_handler {
  public:
    void run() { 
        { tst_lock_guard g(mutex_); }
        trustee_.sync();
        container_->run();
        trustee_.sync();
    }

    void on_container_start(proton::container &c) OVERRIDE {
        std::string url = host_port_ + '/' + "moneybags";
        proton::receiver_options ro;
        ro.auto_accept(false).auto_settle(false);
        c.open_receiver(url, ro);
    }

    void on_message(proton::delivery &d, proton::message &msg) OVERRIDE {
        received_++;
        d.accept();
    }

    // Called from other threads
    moneybags(config &c) : 
        trustee_(c.get_trustee()),
        host_port_(c.host_port()),
        do_process_offer(*this),
        received_(0),
        payments_(0)
    {
        tst_lock_guard g(mutex_);
        container_ = new container(*this, std::string("moneybags"));
    }

    ~moneybags() { delete container_; }

    bool succeeded() { 
        //std::cout << "Moneybags  " << received_ << ' ' << payments_ << '\n';
        return pending_offers_.empty() && received_ == payments_;
    }

    void message_offered(int escrow_id /* , amount, other args */) {
        // possibly called by multiple trustee_ threads concurrently
        { 
             tst_lock_guard g(mutex_);
             pending_offers_.push_back(escrow_id);
        }
        // call without lock
        container_->schedule(duration::IMMEDIATE, do_process_offer);
        // logic resumes in process_offer() as container callback
    }

  private:
    void process_offer() {
        // We take them all, send payment
        int id = -1;
        { 
             tst_lock_guard g(mutex_);
             if (pending_offers_.empty()) {
                 std::cerr << "moneybags error" << std::endl;
                 exit(1);
             }
             id = pending_offers_.front();
             pending_offers_.pop_front();
        }

        trustee_.park_payment(id /*, amount, ... */);
        payments_++;
    }

    struct process_offer_fn : public void_function0 {
        moneybags& parent_;
        process_offer_fn(moneybags& p) : parent_(p) {}
        void operator()() { parent_.process_offer(); }
    };

    trustee &trustee_;
    std::string host_port_;
    container *container_;
    process_offer_fn do_process_offer;
    tst_mutex mutex_;
    int received_;
    int payments_;
    std::deque<int> pending_offers_;
};

namespace {
void * run_generator(void *arg) { generator *g = (generator *) arg; g->run(); }
void * run_moneybags(void *arg) { moneybags *m = (moneybags *) arg; m->run(); }
}


struct escrow : public void_function0 {
    int id_;
    trustee &trustee_;
    delivery delivery_;
    tracker tracker_;
    generator &generator_;  // the payee
    message message_;       // copy of inbound message
    escrow(int id, trustee &t, delivery &d, message &m, generator &g) : id_(id), trustee_(t), delivery_(d), 
                                                                        message_(m), generator_(g) {}
    void operator()() { trustee_.cleanup(*this); }
};

class trustee::impl : public messaging_handler {
  public:
    impl(config &c, trustee &t);
    ~impl() { 
        delete container_;
        delete moneybags_;
        moneybags_sender_ = sender();
        for (int i = 0; i < generators_.size(); i++)
            delete (generators_[i]);
    }
    void sync() { tst_lock_guard g(mutex_); }  // for a happy helgrind
    void run() { container_ = new container(*this); sync(); container_->run(); teardown(); } // called from main thread
    bool succeeded();

    void on_container_start(proton::container &c) OVERRIDE {
        // TODO: proper hunt for free port 
        config_.trustee_host_port_ = std::string("amqp://127.0.0.1:5999");
        c.listen(config_.host_port());
        // std::cout << "listening on " << config_.host_port() << std::endl;
        setup(c);
    }

    void on_receiver_open(proton::receiver &r) OVERRIDE {
        // generator, one of many
        std::string address(r.target().address());
        proton::receiver_options ro;
        ro.auto_accept(false).auto_settle(false).credit_window(0);
        ro.target(proton::target_options().address(address));
        r.open(ro);

        int num = generator_number(r.target().address());
        receivers_[generators_[num]] = r;
        int expected = config_.generator_credits_.size();
        if (receivers_.size() == expected) {
            // All generators connected, start generating
            for (int i = 0; i < expected; i++) {
                replenish(receivers_[generators_[i]], config_.generator_credits_[i]);
            }
        }
    }

    void on_message(proton::delivery &d, proton::message &msg) OVERRIDE {
        int num = generator_number(d.receiver().target().address());
        generator *g = generators_[num];
        int id = escrow_count_++;
        escrows_[id] = new escrow(id, trustee_, d, msg, *g);
        moneybags_->message_offered(id);
        // wait for payment
    }


    void on_sender_open(proton::sender &sender) OVERRIDE {
        moneybags_sender_ = sender;
        // moneybags is operational, so start generators
        sync();
        for (int i=0; i < config_.generator_credits_.size(); i++) {
            generators_.push_back(new generator(config_, i));
            threads_.push_back(new tst_thread(run_generator, generators_.back()));
            threads_.back()->start();
        }
    }

    void on_tracker_settle(tracker &d) OVERRIDE {
        for (std::deque<escrow *>::iterator ep = retirees_.begin(); ep != retirees_.end(); ep++) {
            if (d == (*ep)->tracker_) {
                // One more schedule, this time from a callback on the same container
                void_function0 *fp = *ep;
                container_->schedule(duration::IMMEDIATE, *fp);
                // Resumes at cleanup;
                retirees_.erase(ep);
                return;
            }
        }
        std::cerr << "tracker settlemnt error" << std::endl;
        exit(1);
    }

    void cleanup(escrow &e) {
        escrows_.erase(e.id_);
        delete &e;
        if (++completions_ == config_.target_) {
            // We are done
            moneybags_sender_.connection().close();
            for (int i = 0; i < generators_.size(); i++)
                receivers_[generators_[i]].connection().close();
            container_->stop_listening(config_.host_port());
        }
        replenish(receivers_[&e.generator_], config_.get_credit(e.generator_.id()));
    }

    void park_payment(int id) {
        { 
             tst_lock_guard g(mutex_);
             done_deals_.push_back(id);
        }
        // call without lock
        container_->schedule(duration::IMMEDIATE, do_exchange);
    }

private:
    void exchange() {
        // Money to the generator, message to the payor
        int id;
        { 
            tst_lock_guard g(mutex_);
            if (done_deals_.empty()) {
                std::cerr << "trustee escrow completion error" << std::endl;
                exit(1);
            }
            id = done_deals_.front();
            done_deals_.pop_front();
        }
        escrow *ep = escrows_[id];
        ep->delivery_.accept();
        ep->generator_.take_payment();
        {
            tst_lock_guard g(*send_mutex_);
            ep->tracker_ = moneybags_sender_.send(ep->message_);
        }
        retirees_.push_back(ep);
    }

    void setup(container &c);
    void teardown();
    int generator_number(const std::string &name) {
        std::string::size_type pos = name.find('X', 0);
        return (pos == std::string::npos) ? 0 : name.length() - pos;
    }

    void replenish(receiver &r, int max_credit) {
        // keep generators bursty, only replenish if fully drained
        if (r.credit() == 0) { 
            int remaining = config_.target_ - issued_credit_;
            if (remaining) {
                int credit  = max_credit;
                if (credit > remaining / 2) credit = remaining / 2;
                if (credit == 0) credit = 1;
                r.add_credit(credit);
                issued_credit_ += credit;
            }
        }
    }

    struct exchange_fn : public void_function0 {
        impl& parent_;
        exchange_fn(impl& p) : parent_(p) {}
        void operator()() { parent_.exchange(); }
    };

    config &config_;
    trustee &trustee_;
    tst_mutex *send_mutex_;
    container *container_;
    int issued_credit_;
    int escrow_count_;
    int completions_;
    exchange_fn do_exchange;
    tst_mutex mutex_;
    std::vector<generator *> generators_;
    std::map<generator *, receiver> receivers_;
    std::vector<tst_thread *> threads_;
    moneybags *moneybags_;
    sender moneybags_sender_;
    std::map<int, escrow *> escrows_;
    std::deque<int> done_deals_;
    std::deque<escrow *> retirees_;
};


trustee::impl::impl(config &c, trustee &t) : config_(c), trustee_(t), send_mutex_(&c.global_send_mutex_), container_(0), issued_credit_(0), 
                                             escrow_count_(0), completions_(0), do_exchange(*this), moneybags_(0) {}

void trustee::impl::setup(container &c) {
    config_.trustee_ = &trustee_;
    moneybags_ = new moneybags(config_);
    threads_.push_back(new tst_thread(run_moneybags, moneybags_));
    sync();
    threads_[0]->start();
    // delay start of generators until on_sender_open
}

void trustee::impl::teardown() {
    for (int i=0; i < threads_.size(); i++) {
        threads_[i]->join();
        delete threads_[i];
    }
    sync();
}

bool trustee::impl::succeeded() {
    if (completions_ != config_.target()) return false;
    if (escrows_.size() || done_deals_.size() || retirees_.size()) return false;
    for (int i = 0; i < generators_.size(); i++)
        if (!generators_[i]->succeeded())
            return false;
    if (!moneybags_->succeeded()) return false;
    return true;
}

trustee::trustee(config &c): impl_(new impl(c, *this)) {}
trustee::~trustee() { delete impl_; }
void trustee::run() { impl_->run(); }
void trustee::sync() { impl_->sync(); }
void trustee::park_payment(int id) { impl_->park_payment(id); }
bool trustee::succeeded() { impl_->succeeded(); }
void trustee::cleanup(escrow &e) { impl_->cleanup(e); }

int main(int argc, char **argv) {
    int escrow_count = 1000;
    if (argc > 1) {
        escrow_count = 1000000;
        std::cout << argv[0] << " soak test " << escrow_count << std::endl;
    }

    try {
        config conf(escrow_count);
        conf.add_generator(1);
        conf.add_generator(1);
        conf.add_generator(2);
        conf.add_generator(3);
        if (escrow_count > 1000) {
            conf.add_generator(1);
            conf.add_generator(1);
            conf.add_generator(1);
            conf.add_generator(1);
            conf.add_generator(2);
            conf.add_generator(8);
        }            

        trustee t(conf);
        t.run();
        if (t.succeeded()) return 0;

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 1;
}
