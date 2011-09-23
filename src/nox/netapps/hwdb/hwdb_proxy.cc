#include "hwdb_proxy.hh"

#include "pyrt/pycontext.hh"

#include "swigpyrun.h"

#include "vlog.hh"
#include <list>


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
		
		void hwdb_proxy::postEvent(PyObject * pylist)
		{
			int size = PyList_Size(pylist);
			if(size == 0)
			{
				return;
			}

		    list<HWDBDevice> mylist = list<HWDBDevice>();
			for(int index = 0; index < size; index++)
			{
				PyObject* object = PyList_GetItem(pylist, index);
				PyObject* macObj = PyDict_GetItemString(object, "mac");
				PyObject* actObj = PyDict_GetItemString(object, "action");

				char * macStr = PyString_AsString(macObj);
				char * actStr = PyString_AsString(actObj);

		        lg.info("%s %s", actStr, macStr);

		        mylist.push_back(*(new HWDBDevice(macStr, actStr)));
			}

	        ctrl->post(new HWDBEvent(mylist)); /* HWDBEvent creates a deep copy */
		}

		int hwdb_proxy::insert(char* s) {
			
			return ctrl->insert(s);
		}

	    PyObject* hwdb_proxy::call(char * query) {
	        char response[SOCK_RECV_BUF_LEN];
	        unsigned int length;

	        length = ctrl->query(query, response, SOCK_RECV_BUF_LEN);

	        response[length] = '\0';
	        lg.info("[%d] %s", length, response);

	        return PyString_FromString(response);
	    }
	}
}
