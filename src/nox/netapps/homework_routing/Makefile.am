include ../../../Make.vars 

EXTRA_DIST =\
	    meta.json\
	    _init_.py\
	    pydhcp.i

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED 

pkglib_LTLIBRARIES =\
		    homework_routing.la

homework_routing_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox \
			       -I $(top_srcdir)/src/nox/netapps/
homework_routing_la_SOURCES = homework_routing.hh homework_routing.cc dhcp_msg.hh \
			      dhcp_proxy.cc dhcp_proxy.hh
homework_routing_la_LDFLAGS = -module -export-dynamic -lhwdb

NOX_RUNTIMEFILES = meta.json

NOX_RUNTIMEFILES += __init__.py

pydhcp_wrap.cc pydhcp.py: pydhcp.i
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/nox/lib/ -outdir $(builddir)/. -o pydhcp_wrap.cc  -module pydhcp $(srcdir)/pydhcp.i

pkglib_LTLIBRARIES += _pydhcp.la
_pydhcp_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(srcdir)/../ -I$(top_builddir)/src/nox/
_pydhcp_la_SOURCES = dhcp_proxy.cc dhcp_proxy.hh homework_routing.hh
nodist__pydhcp_la_SOURCES = pydhcp_wrap.cc

_pydhcp_la_LDFLAGS = -module

NOX_PYLIBFILES = _pydhcp.so


all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
