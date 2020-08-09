FROM alpine:3.12.0

#Installing all the dependencies
RUN apk add --no-cache gcc libsodium-dev make autoconf build-base

WORKDIR /mkp224o

COPY . /mkp224o/

RUN ./autogen.sh \
  && ./configure \
  && make \
  && cp /mkp224o/mkp224o /usr/local/bin/

WORKDIR /root
VOLUME /root/data
ENTRYPOINT ["mkp224o", "-d", "/root/data"]
