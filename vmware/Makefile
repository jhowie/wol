# MacOS Makefile for wol
#
ARCHITECTURE = $(shell uname -m)
CC=cc
OBJDIR=obj/$(ARCHITECTURE)
JSONINCDIR=../lyparseJSON
JSONLIBDIR=../lyparseJSON/lib/$(ARCHITECTURE)
B64INCDIR=../libb64
B64LIBDIR=../libb64/lib/$(ARCHITECTURE)  
INSTALLLIBDIR=/usr/local/lib
INSTALLINCLUDEDIR=/usr/local/include
INSTALLBINDIR=/usr/local/bin
INSTALLETCDIR=/usr/local/etc
LDFLAGS=-L$(JSONLIBDIR) -L$(B64LIBDIR) -lcurl -llyparseJSON -lb64
CFLAGS=-DDEFAULTRESTSERVERURL="\"http://127.0.0.1:8697\"" -DVMENCRYPTEDPASSWORDFILE="\"/usr/local/etc/vmpasswd\"" -I$(JSONINCDIR) -I$(B64INCDIR)


BINARIES=$(OBJDIR) $(OBJDIR)/vmfusionwold

$(OBJDIR)/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR)/$(<:.c=.o)

all: $(BINARIES)

install: all
	install -d -o root -g wheel $(INSTALLBINDIR)
	install -c -o root -g wheel -m 0555 $(OBJDIR)/vmfusionwold $(INSTALLBINDIR)
	install -d -o root -g wheel $(INSTALLETCDIR)
	install -b -c -o root -g wheel -m 0644 etc/vmpasswd $(INSTALLETCDIR)/vmpasswd

clean:
	rm -rf obj

install: all

$(OBJDIR)/vmfusionwold: $(OBJDIR)/main.o $(OBJDIR)/vmprod_fusion.o
	cc -o $(OBJDIR)/vmfusionwold $(CFLAGS) $(LDFLAGS) $(OBJDIR)/main.o $(OBJDIR)/vmprod_fusion.o

$(OBJDIR):
	mkdir -p $(OBJDIR)
