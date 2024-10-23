.PHONY: all clean

all: build/libs

build:
	mkdir -p build

build/libs: | build
	export CC="/usr/bin/aarch64-linux-gnu-gcc"
	(cd build && \
	wget 'https://ftp.gnu.org/gnu/glibc/glibc-2.39.tar.gz' && \
	tar xvzf glibc-2.39.tar.gz && \
	(cd glibc-2.39/ && \
	mkdir -p build && \
	cd build/ && \
	../configure --enable-memory-tagging \
                --enable-stack-protector=all \
                --enable-bind-now \
                --disable-sanity-checks \
                --with-pkgversion='mad h4x' \
                --with-bugurl='https://ctf.perfect.blue/' \
                --enable-fortify-source \
                --build=x86_64-pc-linux-gnu \
                --host=aarch64-linux-gnu && \
	make -j`nproc`  && \
	cp libc.so elf/ld.so ../../../)) && \
  mv libc.so libc.so.6
	rm -rf build


clean:
	-rm libc.so.6
	-rm ld.so
	-rm -rf build
