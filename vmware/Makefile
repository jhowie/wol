CFLAGS=-DDEFAULTRESTSERVERURL="\"http://127.0.0.1:8697\"" -g
LDFLAGS=-lcurl

BINARIES=vmfusionwold

.c.o:
	cc -c $(CFLAGS) $<

all: $(BINARIES)

install: all
	install -d -o root -g wheel $(BINDIR)
	install -c -o root -g wheel -m 0555 vmfusionwold $(BINDIR)

clean:
	rm -f $(BINARIES)
	rm -f *.o
	rm -f *.a
	rm -rf *.dSYM

install: all

vmfusionwold: main.o vmprod_fusion.o
	cc -o vmfusionwold $(CFLAGS) $(LDFLAGS) main.o vmprod_fusion.o
