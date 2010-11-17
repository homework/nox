#ifndef DHCP_PROXY_HH__
#define DHCP_PROXY_HH__

#include <Python.h>

#include "dhcp.hh"
#include "../../coreapps/pyrt/pyglue.hh"

namespace vigil {
  namespace applications {

    class dhcp_proxy{
    public:
      dhcp_proxy(PyObject* ctxt);
  
      void configure(PyObject*);
      void install(PyObject*);
      std::string hello_world();
      void register_object(PyObject *p_obj);

      // --
      // Proxy public interface methods here!!
      // --

    protected:   

      dhcp* p_dhcp;
      PyObject *p_hw;
      container::Component* c;
    }; // class dhcp_proxy

  } // namespace applications
} // namespace vigil

#endif //  DHCP_PROXY_HH__
