#include "dhcp.hh"

#include "../../coreapps/pyrt/pycontext.hh"
#include "swigpyrun.h"
#include "vlog.hh"
#include "dhcp_proxy.hh"

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
      this->p_dhcp->register_proxy((dhcp_proxy *)this);
      lg.dbg("Configure called in c++ wrapper");
    }
    
    void 
    dhcp_proxy::install(PyObject*) 
    {
      lg.dbg("Install called in c++ wrapper");
    }
    
    std::string
    dhcp_proxy::hello_world() {
      return string("Hello World!!!");
    }

    void 
    dhcp_proxy::register_object(PyObject *p_obj) {
      printf("object name: %s\n", PyString_AsString(PyObject_Str(p_obj)));
      this->p_hw = p_obj;
    }
  
    bool
    dhcp_proxy::is_ether_addr_routable(ethernetaddr ether) {
      bool ret = false;
      PyObject *py_ret = PyObject_CallMethod(this->p_hw, "permit_ether_addr", "(s)", 
					     ether.string().c_str());
      if(py_ret != NULL) {
	ret = PyInt_AsLong(py_ret);
	// printf("permit_ether_addr %s returned: %d %s\n", ether.string().c_str(),PyInt_AsLong(py_ret),
	//        ret?"Allowed":"Not Allowed");
	Py_DECREF(py_ret);
      } else {        
	PyErr_Print();	
      }
      return ret;
    }
    
    std::vector<std::string> 
    dhcp_proxy::get_mapping() {
      return (std::vector<std::string>)this->p_dhcp->get_dhcp_mapping();
    };
  
    void
    dhcp_proxy::revoke_ether_addr(ethernetaddr ether) {
      this->p_dhcp->revoke_mac_access(ether);
    }
  
    void
    dhcp_proxy::blacklist_mac_addr(ethernetaddr ether) {
      this->p_dhcp->blacklist_mac(ether);
    }
  
    void
    dhcp_proxy::whitelist_mac_addr(ethernetaddr ether) {
      this->p_dhcp->whitelist_mac(ether);
    }
  
    std::vector<std::string> 
    dhcp_proxy::get_blacklist_status() {
      return (std::vector<std::string>)this->p_dhcp->get_blacklist_status();
    }
    
  } // namespace applications
} // namespace vigil
