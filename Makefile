DESTDIR=
PREFIX=/usr/local
DATAROOTDIR=$(PREFIX)/share
DATADIR=$(DATAROOTDIR)
EXEC_PREFIX=$(PREFIX)
BINDIR=$(EXEC_PREFIX)/bin
SBINDIR=$(EXEC_PREFIX)/sbin
MANDIR=$(DATAROOTDIR)/man
INFODIR=$(DATAROOTDIR)/info

CPPFLAGS=
CFLAGS=-Wall -Werror
LDFLAGS=

all: grepcidr

grepcidr: grepcidr.c

install: grepcidr
	install -m 0755 -d $(DESTDIR)$(BINDIR)
	install -m 0755 grepcidr $(DESTDIR)$(BINDIR)/grepcidr

clean:
	$(RM) grepcidr *.o
