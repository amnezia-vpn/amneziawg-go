FROM golang:1.23.6 as awg
COPY . /awg
WORKDIR /awg
RUN go mod download && \
    go mod verify && \
    go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /usr/bin

FROM alpine:3.19
ARG AWGTOOLS_RELEASE="1.0.20241018"
RUN apk --no-cache add iproute2 iptables bash && \
    cd /usr/bin/ && \
    wget https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v${AWGTOOLS_RELEASE}/alpine-3.19-amneziawg-tools.zip && \
    unzip -j alpine-3.19-amneziawg-tools.zip && \
    chmod +x /usr/bin/awg /usr/bin/awg-quick
COPY --from=awg /usr/bin/amneziawg-go /usr/bin/amneziawg-go
