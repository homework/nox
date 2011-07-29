from nox.lib.core import *

import logging

from ctypes import *
import StringIO

# HWDB variables
#
hwdb = CDLL('/home/homeuser/hwdb/libhwdb.so')
rpc = None

lg = logging.getLogger('hwdb_py_test')

class HWDBPytest(Component):
	
	def __init__(self, ctxt):
		Component.__init__(self, ctxt)

	def configure(self, configuration):
		lg.info("Configure.")
		return

	def install(self):
		lg.info("Install.")
		
		self.connect("localhost", 987, "HWDB")
		
		self.post_callback(1, self.insert)
		pass

	def getInterface(self):
		return str(HWDBPytest)

	def connect(self, host, port, service): # connect to homework database
		
		global rpc
		
		e = hwdb.rpc_init(0)
		if e == 0:
			lg.error("hwdb error: rpc_init failed")
			return False

		hwdb.rpc_connect.restype = c_void_p
		rpc = c_void_p(hwdb.rpc_connect(host, port, service, 1))
		if rpc.value == None:
			lg.error("hwdb error: rpc_connect failed")
			return False
		lg.info("Connection established.")
		return True

	def insert(self): # dummy insert
		m = "01:23:45:67:89:10"
		a = "permit"
		s = "SQL:insert into Devices values (\"" + m + "\",\"" + a + "\")\n"
		q = create_string_buffer(s)
		l = sizeof(q)
		r = create_string_buffer(65535)
		p = c_int()
		e = hwdb.rpc_call(rpc, q, l, r, sizeof(r), byref(p))
		if e == 0:
			lg.error("hwdb error: rpc_call failed")
			return False
		lg.info("[%d]: %s" % (p.value, repr(r.value)))

		self.post_callback(1, self.insert)
		return True

def getFactory():

	class Factory:
		def instance(self, ctxt):
			return HWDBPytest(ctxt)

	return Factory()

