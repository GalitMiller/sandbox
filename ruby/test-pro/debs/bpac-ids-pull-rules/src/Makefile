
PREFIX = $(DESTDIR)/usr
SYSCONFDIR=$(DESTDIR)/etc
INSTALL = /bin/install -c
MKDIR = /bin/install -c -d

install:
	$(MKDIR) $(PREFIX)/bin
	$(MKDIR) $(SYSCONFDIR)/bricata/settings.d
	$(INSTALL) -m 755 usr/bin/*.sh $(PREFIX)/bin
	$(INSTALL) -m 755 usr/bin/*.pl $(PREFIX)/bin
	$(INSTALL) -m 755 etc/bricata/settings.d/*.sh $(SYSCONFDIR)/bricata/settings.d
