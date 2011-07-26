#ifndef DHCP_PROXY_HH__
#define DHCP_PROXY_HH__

#include <Python.h>
#include <vector>

#include "../../coreapps/pyrt/pyglue.hh"

class dhcp;

namespace vigil {
  namespace applications {

    class dhcp_proxy{
    public:
      dhcp_proxy(PyObject* ctxt);
  
      void configure(PyObject*);
      void install(PyObject*);
      // --
      // Proxy public interface methods here!!
      // --
      std::string hello_world();
      void register_object(PyObject *p_obj);
      std::vector<std::string> get_mapping();
      bool is_ether_addr_routable(ethernetaddr ether);
      void revoke_ether_addr(ethernetaddr ether);

      void blacklist_mac_addr(ethernetaddr ether);
      void whitelist_mac_addr(ethernetaddr ether);
      std::vector<std::string> get_blacklist_status();
      
    protected:   
      dhcp* p_dhcp;
      PyObject *p_hw;
      container::Component* c;
    }; // class dhcp_proxy

  } // namespace applications
} // namespace vigil

#endif //  DHCP_PROXY_HH__
