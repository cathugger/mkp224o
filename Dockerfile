FROM debian:bookworm as builder
WORKDIR /app
RUN apt-get update && apt-get install -y gcc libc6-dev libsodium-dev make autoconf
COPY . .
RUN ./autogen.sh && ./configure --enable-amd64-51-30k LDFLAGS=-static
RUN make

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/mkp224o .
CMD [ "./mkp224o" ]