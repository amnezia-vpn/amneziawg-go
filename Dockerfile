FROM golang:1.24.4 AS awg
COPY . /awg
WORKDIR /awg
RUN go mod download && \
    go mod verify && \
    go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /usr/bin

FROM alpine:3.19 AS awg-tools
ARG AWGTOOLS_RELEASE="1.0.20250901"
RUN apk --no-cache add git make gcc musl-dev linux-headers bash && \
    git clone --depth 1 --branch "v${AWGTOOLS_RELEASE}" https://github.com/amnezia-vpn/amneziawg-tools.git /awg-tools && \
    make -C /awg-tools/src && \
    make -C /awg-tools/src install WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no WITH_WGQUICK=yes

FROM alpine:3.19
RUN apk --no-cache add iproute2 iptables bash && \
    ln -s /usr/bin/awg /usr/bin/wg && \
    ln -s /usr/bin/awg-quick /usr/bin/wg-quick
COPY --from=awg-tools /usr/bin/awg /usr/bin/awg-quick /usr/bin/
COPY --from=awg /usr/bin/amneziawg-go /usr/bin/amneziawg-go
