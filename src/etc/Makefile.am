include ../Make.vars

dist_bin_SCRIPTS = \
	gen-nox-cert.sh

bin_SCRIPTS = \
	gen-nox-cert.sh

data_DATA = \
	noxca.cnf

pkgsysconf_DATA = \
	nox.json

EXTRA_DIST = \
	noxca.cnf \
	nox.json

noxca.key noxca.crt ca.pem:
	@echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	@echo "++  Creating Development SSL certs for coreui  "
	@echo ""
	$(srcdir)/gen-nox-cert.sh $(srcdir)/
	@echo ""
	@echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

all-local: # noxca.key noxca.crt ca.pem
	@dlist="$(pkgsysconf_DATA)";for f in $$dlist; do \
	  if test ! -f $$f; then \
		ln -sf $(srcdir)/$$f $(builddir)/$$f;\
	  fi;\
	done; 

clean-local:
	@find  . -type l -exec rm -rf {} \; 
	@rm -f noxca.key noxca.crt noxca.key ca.pem 
