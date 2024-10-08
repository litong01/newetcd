FROM golang:1.22-alpine3.20 as BUILDER
RUN apk add curl && ARCH=$(uname -m) && if [[ "${ARCH}" == "aarch64" ]]; then ARCH=arm64; fi && \
    if [[ "${ARCH}" == "x86_64" ]]; then ARCH="amd64"; fi && \
    echo "Downloading etcd 3.5.15 ..." && \
    mkdir -p /tmp/etcd && cd /tmp && \
    curl -Lso etcd.tar.gz https://github.com/etcd-io/etcd/releases/download/v3.5.15/etcd-v3.5.15-linux-${ARCH}.tar.gz && \
    echo "Extracting etcd ..." && tar -xvf etcd.tar.gz -C etcd --strip-components 1

FROM alpine:3.20
WORKDIR /etc/tinyetcd
COPY --from=BUILDER /tmp/etcd/etcdctl /usr/local/bin
COPY --from=BUILDER /tmp/etcd/etcd /usr/local/bin

RUN apk add curl bash-completion

CMD ["/usr/local/bin/etcd", "--enable-grpc-gateway", "--data-dir", "/var/lib/etcd"]