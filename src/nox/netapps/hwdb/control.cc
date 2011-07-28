#include "control.hh"

#include <boost/bind.hpp>

#include <errno.h>
#include <string>

#include "bootstrap-complete.hh"

#include "event.hh"

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

	return ;
}

Disposition HWDBControl::handle_bootstrap (const Event& e) {

	connect();
	
	timeval tv = {1, 0};
	post(boost::bind(&HWDBControl::timer, this), tv);


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

		if (! rpc_init(0)) {

			lg.err("hwdb error: rpc_init failed");
			exit(-1);
		}

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

REGISTER_COMPONENT(container::Simple_component_factory<HWDBControl>, 
	HWDBControl);

} /* namespace vigil */

