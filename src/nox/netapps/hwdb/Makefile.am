include ../../../Make.vars 

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)

pkglib_LTLIBRARIES =\
	hwdbcontroller.la \
	hwdb_test.la

hwdbcontroller_la_CPPFLAGS = $(AM_CPPFLAGS) \
-I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/

hwdbcontroller_la_SOURCES = control.hh control.cc

hwdbcontroller_la_LDFLAGS = -module -export-dynamic -lhwdb

hwdb_test_la_CPPFLAGS = $(AM_CPPFLAGS) \
-I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/

hwdb_test_la_SOURCES = mytest.hh mytest.cc

hwdb_test_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.json __init__.py pytest.py

pyhwdb_wrap.cc pyhwdb.py: pyhwdb.i 
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/nox/lib/ \
-outdir $(builddir)/. \
-o pyhwdb_wrap.cc -module pyhwdb $(srcdir)/pyhwdb.i

pkglib_LTLIBRARIES += _pyhwdb.la

_pyhwdb_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox \
-I$(srcdir)/../ -I$(top_builddir)/src/nox/ \
-I$(top_srcdir)/src/nox/coreapps/

_pyhwdb_la_SOURCES = hwdb_proxy.cc hwdb_proxy.hh

nodist__pyhwdb_la_SOURCES = pyhwdb_wrap.cc

_pyhwdb_la_LDFLAGS = -module

NOX_PYLIBFILES = _pyhwdb.so

endif # PY_ENABLED

EXTRA_DIST = meta.json __init__.py pytest.py pyhwdb.i

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local

