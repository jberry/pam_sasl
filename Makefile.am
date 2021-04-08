ACLOCAL_AMFLAGS = -I m4 --install

SECUREDIR = @SECUREDIR@
securelibdir = $(SECUREDIR)

securelib_LTLIBRARIES = pam_sasl.la
pam_sasl_la_SOURCES = src/pam_sasl.c
pam_sasl_la_LDFLAGS = -module -avoid-version -no-undefined -export-symbols-regex '^pam_sm_'

man8_MANS = src/pam_sasl.8

EXTRA_DIST = src/pam_sasl.8.xml Make.xml.rules

-include Make.xml.rules

install-data-hook:
	rm -fr $(DESTDIR)$(securelibdir)/pam_sasl.la
