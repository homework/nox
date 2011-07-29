from nox.lib.core import *
from nox.netapps.hwdb.pyhwdb import pyhwdb

import logging

lg = logging.getLogger('hwdb_py_test')

class HWDBPytest(Component):
	
	def __init__(self, ctxt):
		Component.__init__(self, ctxt)

	def configure(self, configuration):
		lg.info("Configure.")
		return

	def install(self):
		lg.info("Install.")
		self._hwdb = self.resolve(pyhwdb)
		self._hwdb.incall("pytest")
		self.post_callback(1, self.insert)
		pass

	def getInterface(self):
		return str(HWDBPytest)

	def insert(self): # dummy insert
		m = "01:23:45:67:89:10"
		a = "permit"
		s = "SQL:insert into Devices values (\"" + m + "\",\"" + a + "\")\n"
		lg.info("%s" % (s))
		self._hwdb.insert(s)
		self.post_callback(1, self.insert)
		return True

def getFactory():

	class Factory:
		def instance(self, ctxt):
			return HWDBPytest(ctxt)

	return Factory()

