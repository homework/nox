include ../../../Make.vars 

EXTRA_DIST =\
	meta.json

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED 

pkglib_LTLIBRARIES =\
	homework_dhcp.la

homework_dhcp_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox \
														-I $(top_srcdir)/src/nox/netapps/ -I /usr/include/hwdb/
homework_dhcp_la_SOURCES = homework_dhcp.hh homework_dhcp.cc dhcp_msg.hh
homework_dhcp_la_LDFLAGS = -module -export-dynamic -lnl -lnl-route -lnl-genl -lhwdb

NOX_RUNTIMEFILES = meta.json	

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
