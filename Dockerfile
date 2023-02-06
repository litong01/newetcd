FROM golang:1.20.0-alpine3.17 as BUILDER
ADD . /go/src/github.com/pathecho
WORKDIR /go/src/github.com/pathecho
RUN cd /go/src/github.com/pathecho && \
    go build -o pathecho

FROM alpine:3.17.1
WORKDIR /etc/pathecho
COPY --from=BUILDER /go/src/github.com/pathecho/pathecho /usr/local/bin

CMD ["/usr/local/bin/pathecho"]