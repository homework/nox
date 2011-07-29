#include "hwdb_proxy.hh"

#include "pyrt/pycontext.hh"

#include "swigpyrun.h"

#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;

namespace {
	Vlog_module lg("hwdb_proxy");
}

namespace vigil {
	
	namespace applications {

		hwdb_proxy::hwdb_proxy(PyObject* ctxt) {
			
			if (
			! SWIG_Python_GetSwigThis(ctxt) ||
			! SWIG_Python_GetSwigThis(ctxt)->ptr
			) {
        	throw runtime_error("Unable to access Python context.");
			}
			/* Gets a pointer to the runtime context `ctxt` */
			c = ((PyContext*) SWIG_Python_GetSwigThis(ctxt)->ptr)->c;
		}

		void hwdb_proxy::configure(PyObject* configuration) {
			
			c->resolve(ctrl);
			lg.dbg("Configure.\n");
		}

		void hwdb_proxy::install(PyObject*) {
			
			lg.dbg("Install\n");
		}
		
		void hwdb_proxy::incall(char* s) {
			
			ctrl->incall(s);
		}
		
		int hwdb_proxy::insert(char* s) {
			
			return ctrl->insert(s);
		}

	}
}

