FROM golang:1.20 as awg
COPY . /awg
WORKDIR /awg
RUN go mod download && \
    go mod verify && \
    go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /usr/bin

FROM alpine:3.15 as awg-tools
ARG AWGTOOLS_RELEASE="1.0.20231215"
RUN apk --no-cache add linux-headers build-base bash && \
    wget https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/v${AWGTOOLS_RELEASE}.zip && \
    unzip v${AWGTOOLS_RELEASE}.zip && \
    cd amneziawg-tools-${AWGTOOLS_RELEASE}/src && \
    make -e LDFLAGS=-static && \
    make install

FROM alpine:3.15
RUN apk --no-cache add iproute2 bash
COPY --from=awg /usr/bin/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools /usr/bin/awg /usr/bin/awg-quick /usr/bin/
