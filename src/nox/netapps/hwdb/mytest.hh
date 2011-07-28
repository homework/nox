#ifndef HWDB_TEST_HH__
#define HWDB_TEST_HH__

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include "component.hh"
#include "config.h"

#include "json_object.hh"

#include "control.hh" /* HWDB controller */

namespace vigil {

using namespace std;
using namespace vigil::container;

class HWDBTest: public Component {

public:

	HWDBTest(const Context* c, const json_object*): Component(c) {
		/* */
	}

	void configure(const Configuration*);

	void install();

	Disposition handle_bootstrap(const Event& e);

	Disposition hwdb_handler(const Event& e);

	void test (); /* test controller */
	void test_();

	static void getInstance(const container::Context* c, 
		HWDBTest*& component);

private:
	
	HWDBControl *controller;

};

}

#endif // HWDB_TEST_HH__

