//exporting behaviour of the module to the 

%module "nox.coreapps.dhcp"

%include stl.i

%{
#include "dhcp_proxy.hh"
#include "../../coreapps/pyrt/pycontext.hh"
#include <string>
using namespace vigil;
using namespace vigil::applications;
%}

%include "dhcp_proxy.hh"

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

       def register_object(self, obj):
         self.pscpa.register_object(obj)

  def getFactory():
        class Factory():
            def instance(self, context):
                        
                return pydhcp_app(context)

        return Factory()
%}
