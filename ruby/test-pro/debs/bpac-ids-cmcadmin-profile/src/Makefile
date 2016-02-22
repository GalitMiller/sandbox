
PREFIX = $(DESTDIR)
INSTALL = /bin/install -c
MKDIR = /bin/install -c -d

install:
	$(MKDIR) $(PREFIX)/etc/sudoers.d
	$(INSTALL) -m 400 etc/sudoers.d/cmcadmin $(PREFIX)/etc/sudoers.d/
