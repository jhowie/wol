# MacOS Makefile for wol
#
ARCHITECTURE = $(shell uname -m)
CC=cc
OBJDIR=obj/$(ARCHITECTURE)
LIBDIR=lib/$(ARCHITECTURE)
LIBOBJS=$(addprefix $(OBJDIR)/,wol.o)
INSTALLLIBDIR=/usr/local/lib
INSTALLINCLUDEDIR=/usr/local/include
INSTALLBINDIR=/usr/local/bin
CFLAGS=-DWOLPROGRAMNAME="\"wol\""
LDFLAGS=-L$(LIBDIR) -lwol
BINARIES=$(LIBDIR)/libwol.a $(OBJDIR)/wol

$(OBJDIR)/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR)/$(<:.c=.o)

all: $(BINARIES)

install: all
	install -d -o root -g wheel $(INSTALLBINDIR)
	install -d -o root -g wheel $(INSTALLLIBDIR)
	install -c -o root -g wheel -m 0555 $(OBJDIR)/wol $(INSTALLBINDIR)
	install -c -o root -g wheel -m 0555 $(LIBDIR)/libwol.a $(INSTALLLIBDIR)

clean:
	rm -rf obj lib

$(LIBDIR)/libwol.a: $(LIBDIR) $(OBJDIR) $(OBJDIR)/wol.o
	ar -ur $(LIBDIR)/libwol.a $(OBJDIR)/wol.o
	ranlib $(LIBDIR)/libwol.a

$(OBJDIR)/wol: $(OBJDIR)/main.o $(LIBDIR)/libwol.a
	cc $(CFLAGS) $(LDFLAGS) -o $(OBJDIR)/wol $(OBJDIR)/main.o

$(LIBOBJS): $(OBJDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(LIBDIR):
	mkdir -p $(LIBDIR)