FROM golang:1.14.9-alpine3.12 as BUILDER
ADD . /go/src/github.com/pathecho
WORKDIR /go/src/github.com/pathecho
RUN cd /go/src/github.com/pathecho && \
    go build -o pathecho

FROM alpine:3.12.1
WORKDIR /etc/pathecho
COPY --from=BUILDER /go/src/github.com/pathecho/pathecho /usr/local/bin

CMD ["/usr/local/bin/pathecho"]