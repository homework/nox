include ../../../Make.vars 

EXTRA_DIST =\
	meta.json

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED 

pkglib_LTLIBRARIES =\
	insertion_delay_test.la

insertion_delay_test_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/
insertion_delay_test_la_SOURCES = insertion_delay_test.hh insertion_delay_test.cc
insertion_delay_test_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.json	

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
