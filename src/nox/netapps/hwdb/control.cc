#include "control.hh"

#include <boost/bind.hpp>

#include <errno.h>
#include <string>

#include "bootstrap-complete.hh"

#include "event.hh"

#include "lease.hh"

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

	register_handler<Bootstrap_complete_event>
		(boost::bind(&HWDBControl::handle_bootstrap, this, _1));

	register_handler<HWDBEvent>
		(boost::bind(&HWDBControl::hwdb_handler, this, _1));

	return ;
}

void HWDBControl::install () {
	
	if (! rpc_init(0)) {

		lg.err("hwdb error: rpc_init failed");
		exit(-1);
	}
	
	/* Query persistent hwdb server.
	 * restart(); */

	connect();
	
	/* Offer an RPC service and receive callbacks upon
	 * change in the Devices table.
	 *
	 * Spawns a new cooperative thread.
	 */
	offer();

	return ;
}

Disposition HWDBControl::handle_bootstrap (const Event& e) {
	
	/*
	 * By default, we receive callbacks from HWDB, so there is
	 * no need to periodically query hwdb. However, as an exa-
	 * mple, consider the following:
	 * 
	 * timeval tv = {1, 0};
	 * post(boost::bind(&HWDBControl::timer, this), tv); */

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
	
	e = rtab_status(response, msg);
	lg.info("%s\n", msg);
	return e;
}

unsigned int HWDBControl::query (char *q, char *r, int l) {
	
	char response[SOCK_RECV_BUF_LEN];
	unsigned int length;
	
	lg.info("[%d] %s", strlen(q), q);

	if (! rpc_call(rpc, q, strlen(q) + 1, 
		response, SOCK_RECV_BUF_LEN, &length)) {
		
		lg.err("hwdb error: rpc_call() failed\n");
		return 0;
	}
	response[length] = '\0';
	memcpy(r, response, length);
	return length;
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

	lg.info("Timer fired.\n");
	
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
	
	post(new HWDBEvent(mylist));

	timeval tv = {1, 0};
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

	host = HWDB_SERVER_ADDR;
	/* Connect to persistent storage server */
	port = HWDB_PERSISTSERVER_PORT;

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
					column[1], /* st */
					column[2], /* mc */
					column[3], /* ip */
					column[4]  /* hn */
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

void HWDBControl::offer(void) {
	
	const char *myservice = "mynox";
	
	char myhost[128];
	unsigned short myport;
	
	char q[SOCK_RECV_BUF_LEN], r[SOCK_RECV_BUF_LEN];

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
		
	if (! rpc_call(rpc, q, strlen(q) + 1, r, sizeof(r), &length)) {
			
		lg.err("hwdb error: rpc_call failed (%s)\n", q);
		exit(-1);
	}
	
	r[length] = '\0';
	lg.info("Response to subscribe command: %s", r);

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

	RpcConnection sender;
	Rtab *results;

	lg.info("HWDB blocking call.\n");
	
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
	l = rpc_query(rps, &sender, e, SOCK_RECV_BUF_LEN);
	
	if (l <= 0) {
		lg.err("hwdb error: rpc_query failed.\n");
		return 1;
	}
	
	/* Reply to sender. */
	sprintf(r, "OK");
	rpc_response(rps, sender, r, strlen(r) + 1);
	
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

