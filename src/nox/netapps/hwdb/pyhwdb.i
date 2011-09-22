%module "nox.napps.pyhwdb"

%{

#include "hwdb_proxy.hh"

#include "pyrt/pycontext.hh"

using namespace vigil;
using namespace vigil::applications;

%}

%include "hwdb_proxy.hh"

%pythoncode
%{
from nox.lib.core import Component

class pyhwdb(Component):
		
	def __init__(self, ctxt):
		self.ctrl = hwdb_proxy(ctxt)

	def configure(self, configuration):
		self.ctrl.configure(configuration)

	def install(self):
		pass

	def getInterface(self):
		return str(pyhwdb)

	def call(self, str):
		return self.ctrl.call(str)
		
	def postEvent(self, list):
		self.ctrl.postEvent(list)

	# Expose additional methods here.
	def incall(self, str):
		self.ctrl.incall(str)
	
	def insert(self, str):
		return self.ctrl.insert(str)
	
def getFactory():
	
	class Factory():
		def instance(self, context):
			return pyhwdb(context)

	return Factory()
%}

