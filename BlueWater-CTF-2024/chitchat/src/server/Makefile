CC=cc
CFLAGS=-ggdb -Wall
LDFLAGS=-Wl,-z,relro,-z,now -fstack-protector-all
OUTDIR=../../out/server

all: $(OUTDIR)/libserver.so $(OUTDIR)/server $(OUTDIR)/Dockerfile

$(OUTDIR)/libserver.so: libserver.c | $(OUTDIR)
	$(CC) $< $(CFLAGS) $(LDFLAGS) -lcrypto -fPIC -shared -o $@

$(OUTDIR)/server: server.c | $(OUTDIR)
	$(CC) $< $(CFLAGS) $(LDFLAGS) -ldl -o $@

$(OUTDIR)/Dockerfile: Dockerfile.src | $(OUTDIR)
	cp Dockerfile.src $(OUTDIR)/Dockerfile

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	-rm -rf $(OUTDIR)/

