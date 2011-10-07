/*
 * An HWDB Controller
 */
#ifndef HWDB_CONTROL_HH__
#define HWDB_CONTROL_HH__

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include "component.hh"
#include "config.h"

#include "json_object.hh"

/* HWDB includes */
extern "C" {
#include <hwdb/srpc.h>
#include <hwdb/rtab.h>
#include <hwdb/config.h>
#include <hwdb/timestamp.h>
}

#include "threads/cooperative.hh"
#include "threads/native.hh"
#include "threads/impl.hh"
#include <map>


namespace vigil {

    using namespace std;
    using namespace vigil::container;

    struct Lease;

    struct HWDBEvent;

    struct HWDBDevice;

    class HWDBControl: public Component {

        public:

            HWDBControl(const Context* c, const json_object*): Component(c) {
                /* */
            }

            void configure(const Configuration*);

            void install(void);

            Disposition handle_bootstrap(const Event& e);

            Disposition hwdb_handler(const Event& e);

            static void getInstance(const container::Context* c, 
                    HWDBControl*& component);

            unsigned int query (char *q, char *r, int l);

            int insert(char *q);

            /* Dummy call to test python interface */
            void incall (char *s);
            map<ethernetaddr, Lease> get_dhcp_persist();
        private:

            RpcConnection rpc;
            void connect (void);

            /* Periodic task */
            void timer(void);

            /* Upon restart, reload persistent state in memory */
            void restart(void);

            /* */
            RpcService rps;
            Co_thread mythread;

            void offer(void);
            void run(void);

            int next(char *, char *, int);
    };

    struct HWDBDevice {

        HWDBDevice(const char *mac, const char *action);

        char mac[128];
        /* or, use enum type { PERMIT, DENY, BLACKLIST }; */
        char action[128];
    };

    struct HWDBEvent: public Event {

        HWDBEvent(const list<HWDBDevice> d);

        HWDBEvent (): Event(static_get_name()) {}

        virtual ~HWDBEvent () {}

        static const Event_name static_get_name() {
            return "HWDBEvent";
        }

        list<HWDBDevice> devices;
    };

} /* namespace vigil */

#endif // HWDB_CONTROL_HH__

