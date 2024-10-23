OUTPUT=../../out/client
CC=aarch64-linux-gnu-gcc
CFLAGS=-ggdb -march=armv8.5-a+memtag
LDFLAGS=-Wl,--rpath=libc/ -Wl,--dynamic-linker=libc/ld.so

all: $(OUTPUT)/chal $(OUTPUT)/libc/libc.so.6 $(OUTPUT)/libc/ld.so $(OUTPUT)/Dockerfile $(OUTPUT)/flag.txt

$(OUTPUT)/chal: chal.c | $(OUTPUT)
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

$(OUTPUT)/libc/libc.so.6 $(OUTPUT)/libc/ld.so: | $(OUTPUT)
	mkdir -p $(OUTPUT)/libc
	cp libc/libc.so.6 libc/ld.so $(OUTPUT)/libc/

$(OUTPUT)/Dockerfile: Dockerfile.src | $(OUTPUT)
	cp Dockerfile.src $(OUTPUT)/Dockerfile

$(OUTPUT)/flag.txt: flag.txt | $(OUTPUT)
	cp flag.txt $(OUTPUT)/flag.txt

$(OUTPUT):
	mkdir -p $(OUTPUT)

clean:
	-rm -rf $(OUTPUT)
