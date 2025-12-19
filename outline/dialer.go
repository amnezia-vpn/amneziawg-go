package outline

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type DialerOptions struct {
	Ipc      string
	Prefixes []netip.Prefix
	Mtu      int
	Dns      []netip.Addr
}

func NewStreamDialer(opts DialerOptions) (*StreamDialer, error) {
	var localAddresses []netip.Addr
	for _, prefix := range opts.Prefixes {
		localAddresses = append(localAddresses, prefix.Addr())
	}

	tun, tnet, err := netstack.CreateNetTUN(localAddresses, opts.Dns, opts.Mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create network tun: %v", err)
	}

	awgLogger := device.Logger{
		Verbosef: func(format string, args ...any) {
		},
		Errorf: func(format string, args ...any) {
		},
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), &awgLogger)
	if err := dev.IpcSet(opts.Ipc); err != nil {
		return nil, fmt.Errorf("failed to configure device: %v", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("failed to start awg device: %v", err)
	}

	return &StreamDialer{
		tnet: tnet,
	}, nil
}

var _ transport.StreamDialer = (*StreamDialer)(nil)

type StreamDialer struct {
	tnet *netstack.Net
}

func (d *StreamDialer) DialStream(ctx context.Context, raddr string) (transport.StreamConn, error) {
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raddr: %v", err)
	}
	if l := len(host); l > 0 && host[l-1] == '.' {
		host = host[:l-1]
		raddr = net.JoinHostPort(host, port)
	}

	conn, err := d.tnet.DialContext(ctx, "tcp", raddr)
	if err != nil {
		return nil, err
	}

	return conn.(*gonet.TCPConn), nil
}
