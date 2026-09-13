# MacOS Makefile for wol
#
ARCHITECTURE = $(shell uname -m)
CC=cc
OBJDIR=obj/$(ARCHITECTURE)
LIBDIR=../lyparseJSON/lib/$(ARCHITECTURE) 
INSTALLLIBDIR=/usr/local/lib
INSTALLINCLUDEDIR=/usr/local/include
INSTALLBINDIR=/usr/local/bin
LDFLAGS=-L$(LIBDIR) -lcurl -llyparseJSON
CFLAGS=-DDEFAULTRESTSERVERURL="\"http://127.0.0.1:8697\"" -g


BINARIES=$(OBJDIR) $(OBJDIR)/vmfusionwold

$(OBJDIR)/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR)/$(<:.c=.o)

all: $(BINARIES)

install: all
	install -d -o root -g wheel $(INSTALLBINDIR)
	install -c -o root -g wheel -m 0555 $(OBJDIR)/vmfusionwold $(INSTALLBINDIR)

clean:
	rm -rf obj

install: all

$(OBJDIR)/vmfusionwold: $(OBJDIR)/main.o $(OBJDIR)/vmprod_fusion.o
	cc -o $(OBJDIR)/vmfusionwold $(CFLAGS) $(LDFLAGS) $(OBJDIR)/main.o $(OBJDIR)/vmprod_fusion.o

$(OBJDIR):
	mkdir -p $(OBJDIR)
