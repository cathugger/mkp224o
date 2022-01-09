# Add "docker.io/library/" for support to buildah and podman
FROM docker.io/library/alpine:3.14 AS build

#Installing all the dependencies
RUN apk add --no-cache gcc libsodium-dev make autoconf build-base

WORKDIR /mkp224o
COPY . .

RUN ./autogen.sh \
  && ./configure \
  && make

# Multiple staging build for smaller size
FROM docker.io/library/alpine:3.14 AS dist
LABEL maintainer="sstefin@bk.ru"

RUN apk add --no-cache libsodium

COPY --from=build /mkp224o/mkp224o /usr/bin/mkp224o

VOLUME /root/data
WORKDIR /root/data

ENTRYPOINT ["/usr/bin/mkp224o"]
