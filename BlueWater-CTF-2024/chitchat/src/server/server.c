#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

int main(void) {
	// Turn off buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	setbuf(stdin, NULL);

	void *handle = dlopen("./libserver.so", RTLD_NOW);
	if (!handle) {
		puts("Failed to load server.so");
		exit(1);
	}

	void (*server_main)() = dlsym(handle, "server_main");
	server_main();
}
