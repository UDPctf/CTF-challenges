.PHONY: all clean server

OUTPUT_FOLDER:=../out

all: libc client server copy-compose

clean:
	$(MAKE) -C client/libc clean
	$(MAKE) -C client clean
	$(MAKE) -C server clean
	rm -rf $(OUTPUT_FOLDER)

libc:
	$(MAKE) -C client/libc

client: .FORCE
	$(MAKE) -C client

server: .FORCE
	$(MAKE) -C server

copy-compose:
	cp docker-compose.yml $(OUTPUT_FOLDER)/

# Dummy target to force 'server' to always rebuild
.FORCE:

