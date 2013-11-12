#
# Makefile for grepcidr
#

# Set to where you'd like grepcidr installed
INSTALLDIR=/usr/local/bin

# Set to your favorite C compiler and flags
CC=gcc
CFLAGS=-s -O3 -Wall -pedantic

# End of settable values

grepcidr:
	$(CC) $(CFLAGS) -o grepcidr grepcidr.c getopt.c

all:	grepcidr

install:	grepcidr
	cp grepcidr $(INSTALLDIR)

clean:
	rm -f grepcidr *.o

