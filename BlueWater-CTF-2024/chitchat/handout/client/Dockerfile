FROM ubuntu:24.04

RUN apt update && apt install -y qemu-user


WORKDIR /app

COPY chal /app/
COPY libc/ /app/libc/
COPY flag.txt /app/


CMD ["sh", "-c", "echo 'Sleeping for 1 second to await server..' && sleep 1 && qemu-aarch64 ./chal"]
