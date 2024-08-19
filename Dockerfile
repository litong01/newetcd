FROM golang:1.22-alpine3.20 as BUILDER
ADD . /go/src/github.com/newetcd
WORKDIR /go/src/github.com/newetcd
RUN cd /go/src/github.com/newetcd && go build -o tinyetcd
RUN apk add curl && ARCH=$(uname -m) && if [[ "${ARCH}" == "aarch64" ]]; then ARCH=arm64; fi && \
    if [[ "${ARCH}" == "x86_64" ]]; then ARCH="amd64"; fi && \
    echo "Downloading etcd 3.5.15 ..." && \
    curl -Lso etcd.tar.gz https://github.com/etcd-io/etcd/releases/download/v3.5.15/etcd-v3.5.15-linux-${ARCH}.tar.gz
RUN echo "Extracting etcd ..." && tar -xvf etcd.tar.gz

FROM alpine:3.20
WORKDIR /etc/tinyetcd
COPY --from=BUILDER /go/src/github.com/newetcd/tinyetcd /usr/local/bin
RUN apk add curl bash-completion

CMD ["/usr/local/bin/tinyetcd"]