#include "dhcp_proxy.hh"

#include "../../coreapps/pyrt/pycontext.hh"
#include "swigpyrun.h"
#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;

namespace {
  Vlog_module lg("dhcp-proxy");
}

namespace vigil {
  namespace applications {
    
    /*
     * Get a pointer to the runtime context so we can resolve 
     * simply_c_py_app at configure time.
     */
    
    dhcp_proxy::dhcp_proxy(PyObject* ctxt)
    {
      if (!SWIG_Python_GetSwigThis(ctxt) || !SWIG_Python_GetSwigThis(ctxt)->ptr) {
        throw runtime_error("Unable to access Python context.");
      }
      
      c = ((PyContext*)SWIG_Python_GetSwigThis(ctxt)->ptr)->c;
    }
    
    /*
     * Get a handle to the dhcp_app container on the C++ side.
     */
    
    void
    dhcp_proxy::configure(PyObject* configuration) 
    {
      c->resolve(p_dhcp);    
      lg.dbg("Configure called in c++ wrapper");
    }
    
    void 
    dhcp_proxy::install(PyObject*) 
    {
      lg.dbg("Install called in c++ wrapper");
    }
    
    std::string
    dhcp_proxy::hello_world() {
      return this->p_dhcp->hello_world(); //string("Hello World!!!");
    }

    //std::vector<dhcp_mapping> 
    // int
    // dhcp_proxy::get_mapping() {
    //   return  this->p_dhcp->get_dhcp_mapping();
    // }

    // void 
    // dhcp_proxy::register_object(PyObject *p_obj) {
    //   this->p_hw = p_obj;
    // }

  
  } // namespace applications
} // namespace vigil
