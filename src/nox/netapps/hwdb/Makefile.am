include ../../../Make.vars 

EXTRA_DIST = meta.json __init__.py pytest.py

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

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

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local

