FROM alpine:3.12.0

#Installing all the dependencies
RUN apk add gcc libsodium-dev make autoconf build-base

WORKDIR /mkp224o

COPY . .

RUN ["./autogen.sh"]

RUN ["./configure"]

RUN ["make"]

RUN cp /mkp224o/mkp224o /usr/bin/

WORKDIR /root

CMD ["sh"]
