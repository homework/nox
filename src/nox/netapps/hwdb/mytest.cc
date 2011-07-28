#include "mytest.hh"

#include "assert.hh"

#include <boost/bind.hpp>

#include <errno.h>
#include <string>

#include "bootstrap-complete.hh"

namespace vigil {

static Vlog_module lg("hwdb_test");

void HWDBTest::configure (const Configuration*) {

	register_handler<Bootstrap_complete_event>
		(boost::bind(&HWDBTest::handle_bootstrap, this, _1));
	
	register_handler<HWDBEvent>
		(boost::bind(&HWDBTest::hwdb_handler, this, _1));

	return ;
}

void HWDBTest::install () {

	resolve(controller);
	
	return ;
}

void HWDBTest::test () {

	char q[256];
	int e;

	lg.info("Timer fired.\n");
	
	sprintf(q, 
"SQL:insert into Devices values (\"00:00:00:00:00:01\", \"permit\")\n");
	
	e = controller->insert(q);
	if (e != 0) {
		lg.err("Insert failed.\n");
	}

	timeval tv = {1, 0};
	post(boost::bind(&HWDBTest::test, this), tv);
	
	return ;
}

void HWDBTest::test_ () {

	char q[256];
	char r[256];
	unsigned int l;

	lg.info("Timer fired.\n");
	
	sprintf(q, 
"SQL:insert into Devices values (\"00:00:00:00:00:01\", \"permit\")\n");
	
	l = controller->query(q, r, sizeof(r));
	lg.info("%s", r);
	
	timeval tv = {1, 0};
	post(boost::bind(&HWDBTest::test, this), tv);
	
	return ;
}

Disposition HWDBTest::handle_bootstrap(const Event& e) {
	
	timeval tv = {1, 0};
	post(boost::bind(&HWDBTest::test, this), tv);

	return CONTINUE;
}

Disposition HWDBTest::hwdb_handler(const Event& e) {
	
	lg.info("Event received.\n");
	const HWDBEvent& event = assert_cast<const HWDBEvent&>(e);
	
	for (list<HWDBDevice>::const_iterator i = event.devices.begin();
		i != event.devices.end(); i++) {
		
		HWDBDevice d = *i;
		lg.info("%s\t%s\n", d.mac, d.action);
	}

	return CONTINUE;
}

void HWDBTest::getInstance(const Context* c, HWDBTest*& component) {
	component = dynamic_cast<HWDBTest*>
		(c->get_by_interface(container::Interface_description
			(typeid(HWDBTest).name())));
}

REGISTER_COMPONENT(container::Simple_component_factory<HWDBTest>, 
	HWDBTest);

} /* namespace vigil */

