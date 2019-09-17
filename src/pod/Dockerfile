FROM alpine:3.9

RUN apk update && \
    apk add --no-cache iperf3 iproute2 bash ethtool curl netcat-openbsd python arping

WORKDIR /opt/example

COPY . .

ENTRYPOINT bash
EXPOSE 80
