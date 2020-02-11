FROM golang:1.13-alpine as builder

RUN apk add --no-cache --update git make
RUN mkdir /build
WORKDIR /build
RUN git clone https://github.com/sebidude/authproxy.git
WORKDIR /build/authproxy
RUN make build-linux

FROM scratch
COPY --from=builder /build/authproxy/build/linux/authproxy /usr/bin/authproxy
ENTRYPOINT ["/usr/bin/authproxy"]