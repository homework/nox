//exporting behaviour of the module to the 

%{
#include <cstddef>
%}

%module "nox.coreapps.dhcp"

%include stl.i

%{
#include "dhcp_proxy.hh"
#include "../../coreapps/pyrt/pycontext.hh"
#include <string>
#include <vector>
using namespace vigil;
using namespace vigil::applications;
%}

%include "typemaps.i"
%include "std_string.i"
%include "std_vector.i"
// Instantiate templates used by example
namespace std {
  %template(IntVector) vector<string>;
}

%include "dhcp_proxy.hh"
 //%include "dhcp.hh"

%pythoncode
%{
  from nox.lib.core import Component

  class pydhcp_app(Component):
      """
        An adaptor over the C++ based Python bindings to
        simplify their implementation.
      """  
      def __init__(self, ctxt):
        self.pscpa = dhcp_proxy(ctxt)

      def configure(self, configuration):
        self.pscpa.configure(configuration)
        #self.dhcp_app = self.resolve(str(dhcp_app.dhcp_app))

      def install(self):
        pass

      def getInterface(self):
        return str(pydhcp_app)

      # --
      # Expose additional methods here!
      # --

      def hello_world(self):
        return self.pscpa.hello_world()

      def get_dhcp_mapping(self):
        return self.pscpa.get_mapping()

      def revoke_mac_addr(self, ether):
        return self.pscpa.revoke_ether_addr(ether)

      def whitelist_mac_addr(self, ether):
        return self.pscpa.whitelist_mac_addr(ether)

      def blacklist_mac_addr(self, ether):
        return self.pscpa.blacklist_mac_addr(ether)
 
      def get_blacklist_mac_status(self):
        return self.pscpa.get_blacklist_status()


      def register_object(self, obj):
        self.pscpa.register_object(obj)

  def getFactory():
        class Factory():
            def instance(self, context):
                        
                return pydhcp_app(context)

        return Factory()
%}
