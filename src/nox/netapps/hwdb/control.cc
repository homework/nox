#include "control.hh"

#include <boost/bind.hpp>

#include <errno.h>
#include <string>
#include <map>
#include "bootstrap-complete.hh"

#include "event.hh"

#include "lease.hh"

extern "C" {
#include <hwdb/srpc.h>
}


#define DEVICE_QUERY_DELAY 1

namespace vigil {

    static Vlog_module lg("hwdb_control");

    static tstamp_t last = 0LL;

    HWDBDevice::HWDBDevice(const char *m, const char *a) {

        strncpy(mac, m, sizeof(mac));
        strncpy(action, a, sizeof(action));
    }

    HWDBEvent::HWDBEvent(const list<HWDBDevice> d):
        Event(static_get_name()) {

            for (list<HWDBDevice>::const_iterator i = d.begin();
                    i != d.end(); i++) {

                devices.push_back(*(new HWDBDevice(i->mac, i->action)));
            }
        }

    void HWDBControl::configure (const Configuration*) {

        register_event(HWDBEvent::static_get_name());

        //register_handler<Bootstrap_complete_event>
        //    (boost::bind(&HWDBControl::handle_bootstrap, this, _1));

        register_handler<HWDBEvent>
            (boost::bind(&HWDBControl::hwdb_handler, this, _1));

        return ;
    }

    void HWDBControl::install () {
	
	lg.info("Installing hwdb.\n");

        if (! rpc_init(0)) {

            lg.err("hwdb error: rpc_init failed");
            exit(-1);
        }

        /* Query persistent hwdb server.*/
        /* restart(); */

        connect();

        /* Offer an RPC service and receive callbacks upon
         * change in the Devices table.
         *
         * Spawns a new cooperative thread.
         */
        //offer();

        return ;
    }

	Disposition HWDBControl::handle_bootstrap (const Event& e) {

		/*
         * By default, we receive callbacks from HWDB, so there is
         * no need to periodically query hwdb. However, as an exa-
         * mple, consider the following:
         */
 
		/* timeval tv = {DEVICE_QUERY_DELAY, 0};
		post(boost::bind(&HWDBControl::timer, this), tv); */

    return CONTINUE;
}

Disposition HWDBControl::hwdb_handler(const Event& e) {

    lg.info("Event received.\n");

    return CONTINUE;
}

void HWDBControl::getInstance(const Context* c, 
        HWDBControl*& component) {

    component = dynamic_cast<HWDBControl*>
        (c->get_by_interface(container::Interface_description
                             (typeid(HWDBControl).name())));

    return ;
}

void HWDBControl::connect (void) {

    const char *host;

    unsigned short port;
    const char *service;

    host = HWDB_SERVER_ADDR;
    port = HWDB_SERVER_PORT;

    service = "HWDB";

    rpc = NULL; /* connection */

    if (! (rpc = rpc_connect(const_cast<char *>(host), port, 
                    const_cast<char *>(service), 1l))) {

        lg.err("hwdb error: rpc_connect failed at %s:%05u", 
                host, port);
        exit(-1);
    }

    return ;
}

int HWDBControl::insert(char *question) {

    char response[SOCK_RECV_BUF_LEN];
    unsigned int length;

    int e;
    char msg[RTAB_MSG_MAX_LENGTH];

    length = query(question, response, sizeof(response));
	if (length == 0) {
		return 1;
	}
    e = rtab_status(response, msg);
    lg.info("%s\n", msg);
    fprintf(stderr, "insert: %s %s \n", question, response);
    return e;
}

unsigned int HWDBControl::query (char *q, char *r, int l) {
    
    Q_Decl(question, SOCK_RECV_BUF_LEN);

    char response[SOCK_RECV_BUF_LEN];
    unsigned int length;
    
    if (strlen(q) + 1 > SOCK_RECV_BUF_LEN) {
        lg.err("hwdb error: invalid query length\n");
        return 0;
    }

    memset(question, 0, SOCK_RECV_BUF_LEN);
    memcpy(question, q, strlen(q) + 1);

    lg.info("[%d] %s", strlen(question), question);

    if (! rpc_call(rpc, Q_Arg(question), strlen(question) + 1,
        response, SOCK_RECV_BUF_LEN, &length)) {

        lg.err("hwdb error: rpc_call() failed\n");
        return 0;
    }
    response[length] = '\0';
    memcpy(r, response, length);
    return length;
    
    return 0;
}

void HWDBControl::timer (void) {

    char question[SOCK_RECV_BUF_LEN];
    char response[SOCK_RECV_BUF_LEN];

    unsigned int length;

    Rtab *results;
    char msg[RTAB_MSG_MAX_LENGTH];

    /* Convert results into a list. */
    int i = 0;
    list<HWDBDevice> mylist = list<HWDBDevice>();
    char m[256];
    char a[256];

//        lg.info("Timer fired.\n");

    if (last) {

        char *s = timestamp_to_string(last);
        sprintf(question, "SQL:select * from Devices [since %s]\n", s);
        free(s);
    } else {

        sprintf(question, "SQL:select * from Devices\n");
    }

    length = query(question, response, sizeof(response));

    results = rtab_unpack(response, length);
    if (results && ! rtab_status(response, msg)) {

        rtab_print(results);

        for (i = 0; i < results->nrows; i++) {

            char **column = rtab_getrow(results, i);

            memset(m, 0, sizeof(m));
            memset(a, 0, sizeof(a));
            /* First column is the timestamp. */
            last = string_to_timestamp(column[0]);

            strncpy(m, column[1], sizeof(m));
            strncpy(a, column[2], sizeof(a));
            /* lg.info("[%s, %s]\n", m, a); */
            mylist.push_back(*(new HWDBDevice(m, a)));
        }
    }
    rtab_free(results);
    if(mylist.size() > 0)
        post(new HWDBEvent(mylist));

    timeval tv = {DEVICE_QUERY_DELAY, 0};
    post(boost::bind(&HWDBControl::timer, this), tv);
}

void HWDBControl::restart(void) {

    const char *host;

    unsigned short port;
    const char *service;

    char question[SOCK_RECV_BUF_LEN];
    char response[SOCK_RECV_BUF_LEN];

    unsigned int length;

    Rtab *results;
    char msg[RTAB_MSG_MAX_LENGTH];

    int i;

    int done;

    /* Connect to persistent storage server */
    host = HWDB_SERVER_ADDR;
    port = HWDB_SERVER_PORT;

    service = "PDB";

    rpc = NULL;

    if (! (rpc = rpc_connect(const_cast<char *>(host), port, 
                    const_cast<char *>(service), 1l))) {

        lg.err("hwdb error: rpc_connect failed at %s:%05u", 
                host, port);
        exit(-1);
    }

    /* Query until all results have been returned. */
    done = 0;

    while (! done) {

        if (last) {

            char *s = timestamp_to_string(last);
            sprintf(question, "SQL:select * from LeasesLast [since %s]\n", s);
            free(s);
        } else {

            sprintf(question, "SQL:select * from LeasesLast\n");
        }

        length = query(question, response, sizeof(response));

        results = rtab_unpack(response, length);
        if (results && ! rtab_status(response, msg)) {

            rtab_print(results);

            for (i = 0; i < results->nrows; i++) {
                /* map */
                char **column = rtab_getrow(results, i);
                /* First column is the timestamp. */
                last = string_to_timestamp(column[0]);
                Lease *lease = new Lease(last,
                        column[4], /* st */
                        column[1], /* mc */
                        column[2], /* ip */
                        column[3]  /* hn */
                        );
                lg.info("Lease is %s\n", lease->string().c_str());
                delete lease;
            }
            if (results->nrows == 0) done = 1; /* exit */
        }
        rtab_free(results);
    }
    /* At this point, all records have been processed */
    last = 0LL;

    /* Disconnect from persistent storage */
    rpc_disconnect(rpc);
}

map<ethernetaddr, Lease> HWDBControl::get_dhcp_persist() {
	
	map<ethernetaddr, Lease> ret;
	
	const char *question = "SQL: select * from Leases";
	
	char response[SOCK_RECV_BUF_LEN];
	unsigned int length;
	
	Rtab *results;
	char msg[RTAB_MSG_MAX_LENGTH];
	
	tstamp_t ts;
	
	int i;
	
	length = query(const_cast<char *>(question), response, sizeof(response));
	
	if (length == 0) {
		lg.info("Failed to fetch table Leases.\n");
		return ret;
	}
	
	results = rtab_unpack(response, length);
	if (results && ! rtab_status(response, msg)) {
		
		rtab_print(results);
		for (i = 0; i < results->nrows; i++) {
			char **column = rtab_getrow(results, i);
			/* First column is the timestamp. */
               		ts = string_to_timestamp(column[0]);
			lg.info("Lease is %s -> %s\n", column[1], column[2]);
			ret[ethernetaddr(string(column[1]))] = Lease(
			ts,
			column[4], // st
			column[1], // mc
			column[2], // ip
			column[3]  // hn
			);
		}
	}
	return ret;
}
	
/*
map<ethernetaddr, Lease> HWDBControl::get_dhcp_persist() {
	
	const char *host;
	unsigned short port;
	const char *service;
	
	RpcConnection persist_rpc;
	
	map<ethernetaddr, Lease> ret;

	Q_Decl(question, SOCK_RECV_BUF_LEN);
	
	char response[SOCK_RECV_BUF_LEN];
	
	unsigned int length;
	
	Rtab *results;
	char msg[RTAB_MSG_MAX_LENGTH];

	int i, done = 0;

	host = HWDB_SERVER_ADDR;
	// Connect to persistent storage server
        port = HWDB_SERVER_PORT;
        service = "PDB";

        if (! (persist_rpc = rpc_connect(const_cast<char *>(host), port, 
                        const_cast<char *>(service), 1l))) {
            lg.err("hwdb error: rpc_connect failed at %s:%05u", 
                    host, port);
            exit(-1);
        }

        // Query until all results have been returned.
        while (! done) {
            done = 1;
            if (last) {
                char *s = timestamp_to_string(last);
                sprintf(question, "SQL:select * from LeasesLast [since %s]\n", s);
                free(s);
            } else {
                sprintf(question, "SQL:select * from LeasesLast\n");
            }
            lg.info("[%d] %s", strlen(question), question);

            if (! rpc_call(rpc, Q_Arg(question), strlen(question) + 1, 
                        response, SOCK_RECV_BUF_LEN, &length)) {
                lg.err("hwdb error: rpc_call() failed\n");
                return ret;
            }

            //length = query(question, response, sizeof(response));
            results = rtab_unpack(response, length);
            if (results && ! rtab_status(response, msg)) {
                rtab_print(results);
                for (i = 0; i < results->nrows; i++) {
                    // map
                    char **column = rtab_getrow(results, i);
                    // First column is the timestamp.
                    last = string_to_timestamp(column[0]);
                    //ret[ethernetaddr(string(column[2]))] = ipaddr(string(column[3]));
                    lg.info("Lease is %s -> %s\n", column[2], column[3]);
                    ret[ethernetaddr(string(column[2]))] = Lease(last,
                            column[4], // st
                            column[1], // mc
                            column[2], // ip
                            column[3]  // hn
                            );

                }
                done = (results->nrows == 0); // exit

            }
            lg.err("returned rec %d, done %d\n", results->nrows, done);
            rtab_free(results);
        }
        // At this point, all records have been processed
        last = 0LL;

        //timeval now;
        //gettimeofday(&now, NULL);
        //ret[ethernetaddr("00:1f:3b:26:9d:4b")] = Lease(ipaddr("10.2.0.1"), ethernetaddr("00:1f:3b:26:9d:4b"), 
        //        "", 100000L, DHCP_STATE_ADD);
        //ret[ethernetaddr("00:23:cd:c7:93:b5")] = Lease(ipaddr("10.2.0.5"), ethernetaddr("00:23:cd:c7:93:b5"), 
        //        "", now.tv_sec, DHCP_STATE_ADD);

        // Disconnect from persistent storage
        rpc_disconnect(persist_rpc);

        return ret;

    }
	*/

void HWDBControl::offer(void) {

    const char *myservice = "mynox";

    char myhost[128];
    unsigned short myport;

    Q_Decl(q, SOCK_RECV_BUF_LEN); 
    char r[SOCK_RECV_BUF_LEN];

    unsigned int length;

    rps = NULL;

    rps = rpc_offer(const_cast<char *>(myservice));

    if (! rps) {

        fprintf(stderr, "Failure offering %s service\n", myservice);
        exit(-1);
    }
    rpc_details(myhost, &myport);

    sprintf(q, "SQL:subscribe DevicesLast %s %hu %s", 
            myhost, myport, myservice);

    lg.info("Q: %s\n", q);

    if (! rpc_call(rpc, Q_Arg(q), strlen(q) + 1, r, sizeof(r), &length)) {

        lg.err("hwdb error: rpc_call failed (%s)\n", q);
        exit(-1);
    }

    r[length] = '\0';
    //        lg.info("Response to subscribe command: %s", r);

    /* Start a cooperative thread. */	
    mythread.start(boost::bind(&HWDBControl::run, this));

    return ;
}

/* The call to 'next()' blocks inside a co-thread. */
void HWDBControl::run () {

    char m[256];
    char a[256];

    int error;

    list<HWDBDevice> mylist = list<HWDBDevice>();

    for (;;) {

        memset(m, 0, sizeof(m));
        memset(a, 0, sizeof(a));

        mylist.clear();

        /* Get next event associated with a device. */
        error = next(m, a, 256);
        if (error) {
            lg.err("Failed to receive HWDB event.\n");
            continue;
        }
        lg.info("Dispatch next event.");
        mylist.push_back(*(new HWDBDevice(m, a)));
        lg.err("New event working");
        post(new HWDBEvent(mylist)); /* HWDBEvent creates a deep copy */
    }
    return ;
}

/*
 * NOX magic happens here. */
int HWDBControl::next (char *mc, char *st, int size) {

    char e[SOCK_RECV_BUF_LEN], r[SOCK_RECV_BUF_LEN];

    unsigned l; /* received buffer size */

    char msg[RTAB_MSG_MAX_LENGTH];

    RpcEndpoint sender;
    Rtab *results;


    /*
     * Call 'rpc_query' from a native thread, which avoids blocking
     * other cooperative threads in the thread group.
     *
     * This technique has been used in the 'co_async_*' methods, in
     * threads/impl, for system calls that may block (e.g. a read).
     *
     * Co_native section causes the current co-thread (mythread) to
     * migrate to a native thread, and migrate back to its original
     * thread group upon completion (in the destructor).
     *
     * Cf. cooperative.hh, class Co_native_section. */
    Co_native_section as_native;
    lg.info("HWDB blocking call.\n");

    l = rpc_query(rps, &sender, e, SOCK_RECV_BUF_LEN);

    lg.info("HWDB after locking call.\n");
    if (l <= 0) {
        lg.err("hwdb error: rpc_query failed.\n");
        return 1;
    }

    /* Reply to sender. */
    sprintf(r, "OK");
    rpc_response(rps, &sender, r, strlen(r) + 1);

    /* Parse event. */
    e[l] = '\0';
    results = rtab_unpack(e, l);
    if (results && ! rtab_status(e, msg)) {
        rtab_print(results);
        /* */
        lg.info("Event received.\n");
        char **column = rtab_getrow(results, 0);

        strncpy(mc, column[1], size);
        strncpy(st, column[2], size); /* Connection status */
        lg.info("[%s, %s]\n", mc, st);
    }
    rtab_free(results);

    return 0;
}


void HWDBControl::incall (char *s) {

    /* Used for testing the swig'd proxy from python. */
    lg.info("Welcome %s.\n", s);

    return ;
}

REGISTER_COMPONENT(container::Simple_component_factory<HWDBControl>, 
        HWDBControl);

} /* namespace vigil */

