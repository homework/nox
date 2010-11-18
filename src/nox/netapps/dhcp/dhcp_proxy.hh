#ifndef DHCP_PROXY_HH__
#define DHCP_PROXY_HH__

#include <Python.h>
#include <vector>

#include "../../coreapps/pyrt/pyglue.hh"
#include "dhcp.hh"

namespace vigil {
  namespace applications {

    class dhcp_proxy{
    public:
      dhcp_proxy(PyObject* ctxt);
  
      void configure(PyObject*);
      void install(PyObject*);
      std::string hello_world();
      //void register_object(PyObject *p_obj);
      //std::vector<dhcp_mapping> get_dhcp_mapping();
      std::vector<std::string> get_mapping() {
	return (std::vector<std::string>)this->p_dhcp->get_dhcp_mapping();
      };

      // --
      // Proxy public interface methods here!!
      // --

    protected:   

      dhcp* p_dhcp;
      //PyObject *p_hw;
      container::Component* c;
    }; // class dhcp_proxy

  } // namespace applications
} // namespace vigil

#endif //  DHCP_PROXY_HH__
