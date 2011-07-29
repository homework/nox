#ifndef __HWDB_CONTROL_PROXY_HH__
#define __HWDB_CONTROL_PROXY_HH__

#include <Python.h>

#include "control.hh"

#include "pyrt/pyglue.hh"

namespace vigil {
	
	namespace applications {
		
		class hwdb_proxy {

			public:
				
				hwdb_proxy(PyObject *ctxt);

				void configure(PyObject*);
				
				void install(PyObject*);

				/* More public interface methods... */
				void incall(char *);
			
				int insert(char *);

			protected:
				
				HWDBControl* ctrl;
				container::Component* c;
		};
	}
}

#endif /* __HWDB_CONTROL_PROXY_HH__ */

