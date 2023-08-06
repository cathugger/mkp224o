FROM alpine:latest AS builder
RUN apk add --no-cache gcc libc-dev libsodium-dev libsodium-static make autoconf git
WORKDIR /app
COPY . .
RUN ./autogen.sh
RUN ./configure --enable-amd64-51-30k CFLAGS="-O3 -march=x86-64 -mtune=generic -fomit-frame-pointer" LDFLAGS="-static"
RUN make
RUN strip mkp224o

FROM scratch
WORKDIR /app
COPY --from=builder /app/mkp224o .

ENTRYPOINT ["./mkp224o"]
