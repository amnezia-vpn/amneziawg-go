package outline

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/goccy/go-yaml"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/mobileproxy"
	"golang.getoutline.org/sdk/x/smart"
)

type DeviceConfig struct {
	PrivateKey             string       `yaml:"private_key"`
	Address                []string     `yaml:"address"`
	Dns                    []string     `yaml:"dns"`
	Mtu                    int          `yaml:"mtu,omitempty"`
	Jc                     int          `yaml:"jc,omitempty"`
	Jmin                   int          `yaml:"jmin,omitempty"`
	Jmax                   int          `yaml:"jmax,omitempty"`
	S1                     int          `yaml:"s1,omitempty"`
	S2                     int          `yaml:"s2,omitempty"`
	S3                     int          `yaml:"s3,omitempty"`
	S4                     int          `yaml:"s4,omitempty"`
	H1                     string       `yaml:"h1,omitempty"`
	H2                     string       `yaml:"h2,omitempty"`
	H3                     string       `yaml:"h3,omitempty"`
	H4                     string       `yaml:"h4,omitempty"`
	I1                     string       `yaml:"i1,omitempty"`
	I2                     string       `yaml:"i2,omitempty"`
	I3                     string       `yaml:"i3,omitempty"`
	I4                     string       `yaml:"i4,omitempty"`
	I5                     string       `yaml:"i5,omitempty"`
	HeaderProtectionKey    string       `yaml:"header_protection_key,omitempty"`
	ContentPaddingAddition string       `yaml:"content_padding_addition,omitempty"`
	RekeyAfterTime         string       `yaml:"rekey_after_time,omitempty"`
	RekeyTimeout           string       `yaml:"rekey_timeout,omitempty"`
	RejectAfterTime        string       `yaml:"reject_after_time,omitempty"`
	KeepaliveTimeout       string       `yaml:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string       `yaml:"max_handshake_attempts,omitempty"`
	RandomTrailers         string       `yaml:"random_trailers,omitempty"`
	DisableCookies         string       `yaml:"disable_cookies,omitempty"`
	Peers                  []PeerConfig `yaml:"peers,omitempty"`
}

type PeerConfig struct {
	PublicKey                   string   `yaml:"public_key"`
	PresharedKey                string   `yaml:"preshared_key,omitempty"`
	Endpoint                    string   `yaml:"endpoint"`
	AllowedIPs                  []string `yaml:"allowed_ips"`
	PersistentKeepaliveInterval uint16   `yaml:"persistent_keepalive_interval,omitempty"`
}

func mapYamlToConfig(y smart.YAMLNode) (*DeviceConfig, error) {
	bytes, err := yaml.Marshal(y)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal yaml: %v", err)
	}

	var cfg DeviceConfig
	if err = yaml.Unmarshal(bytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %v", err)
	}

	return &cfg, nil
}

func validateUint16Range(value string) error {
	var parsed device.UintRange
	if err := parsed.FromString(value); err != nil {
		return err
	}
	if parsed.Hi() > 65535 {
		return fmt.Errorf("range exceeds uint16")
	}
	return nil
}

func normalizeAWGBool(value string) (string, error) {
	switch value {
	case "on", "true", "1":
		return "true", nil
	case "off", "false", "0":
		return "false", nil
	default:
		return "", fmt.Errorf("expected on/off, true/false, or 1/0")
	}
}

func genIpcString(cfg *DeviceConfig) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	var b strings.Builder

	b.WriteString("private_key=")
	b.WriteString(hex.EncodeToString(privateKeyBytes))

	if cfg.Jc != 0 {
		b.WriteString("\njc=")
		b.WriteString(strconv.Itoa(cfg.Jc))
	}
	if cfg.Jmin != 0 {
		b.WriteString("\njmin=")
		b.WriteString(strconv.Itoa(cfg.Jmin))
	}
	if cfg.Jmax != 0 {
		b.WriteString("\njmax=")
		b.WriteString(strconv.Itoa(cfg.Jmax))
	}
	if cfg.S1 != 0 {
		b.WriteString("\ns1=")
		b.WriteString(strconv.Itoa(cfg.S1))
	}
	if cfg.S2 != 0 {
		b.WriteString("\ns2=")
		b.WriteString(strconv.Itoa(cfg.S2))
	}
	if cfg.S3 != 0 {
		b.WriteString("\ns3=")
		b.WriteString(strconv.Itoa(cfg.S3))
	}
	if cfg.S4 != 0 {
		b.WriteString("\ns4=")
		b.WriteString(strconv.Itoa(cfg.S4))
	}
	if cfg.H1 != "" {
		b.WriteString("\nh1=")
		b.WriteString(cfg.H1)
	}
	if cfg.H2 != "" {
		b.WriteString("\nh2=")
		b.WriteString(cfg.H2)
	}
	if cfg.H3 != "" {
		b.WriteString("\nh3=")
		b.WriteString(cfg.H3)
	}
	if cfg.H4 != "" {
		b.WriteString("\nh4=")
		b.WriteString(cfg.H4)
	}
	if cfg.I1 != "" {
		b.WriteString("\ni1=")
		b.WriteString(cfg.I1)
	}
	if cfg.I2 != "" {
		b.WriteString("\ni2=")
		b.WriteString(cfg.I2)
	}
	if cfg.I3 != "" {
		b.WriteString("\ni3=")
		b.WriteString(cfg.I3)
	}
	if cfg.I4 != "" {
		b.WriteString("\ni4=")
		b.WriteString(cfg.I4)
	}
	if cfg.I5 != "" {
		b.WriteString("\ni5=")
		b.WriteString(cfg.I5)
	}
	if cfg.HeaderProtectionKey != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.HeaderProtectionKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode header protection key: %w", err)
		}
		if len(key) != 32 {
			return "", fmt.Errorf("header protection key must contain 32 bytes")
		}
		b.WriteString("\nheader_protection_key=")
		b.WriteString(hex.EncodeToString(key))
	}
	for _, field := range []struct{ name, value string }{
		{name: "content_padding_addition", value: cfg.ContentPaddingAddition},
		{name: "rekey_after_time", value: cfg.RekeyAfterTime},
		{name: "rekey_timeout", value: cfg.RekeyTimeout},
		{name: "reject_after_time", value: cfg.RejectAfterTime},
		{name: "keepalive_timeout", value: cfg.KeepaliveTimeout},
		{name: "max_handshake_attempts", value: cfg.MaxHandshakeAttempts},
	} {
		if field.value == "" {
			continue
		}
		if err := validateUint16Range(field.value); err != nil {
			return "", fmt.Errorf("invalid %s: %w", field.name, err)
		}
		b.WriteString("\n" + field.name + "=" + field.value)
	}
	for _, field := range []struct{ name, value string }{
		{name: "random_trailers", value: cfg.RandomTrailers},
		{name: "disable_cookies", value: cfg.DisableCookies},
	} {
		if field.value == "" {
			continue
		}
		value, err := normalizeAWGBool(field.value)
		if err != nil {
			return "", fmt.Errorf("invalid %s: %w", field.name, err)
		}
		b.WriteString("\n" + field.name + "=" + value)
	}

	for _, peer := range cfg.Peers {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode public key: %v", err)
		}

		b.WriteString("\npublic_key=")
		b.WriteString(hex.EncodeToString(publicKeyBytes))

		b.WriteString("\nendpoint=")
		b.WriteString(peer.Endpoint)

		for _, allowedIp := range peer.AllowedIPs {
			b.WriteString("\nallowed_ip=")
			b.WriteString(allowedIp)
		}

		if peer.PresharedKey != "" {
			presharedKeyBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("failed to decode preshared key: %v", err)
			}

			b.WriteString("\npreshared_key=")
			b.WriteString(hex.EncodeToString(presharedKeyBytes))
		}

		if peer.PersistentKeepaliveInterval != 0 {
			b.WriteString("\npersistent_keepalive_interval=")
			b.WriteString(strconv.Itoa(int(peer.PersistentKeepaliveInterval)))
		}
	}

	return b.String(), nil
}

func FallbackParser(ctx context.Context, y smart.YAMLNode) (transport.StreamDialer, string, error) {
	cfg, err := mapYamlToConfig(y)
	if err != nil {
		return nil, "", fmt.Errorf("failed to map yaml to config: %v", err)
	}

	ipc, err := genIpcString(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("faield to generate ipc config: %v", err)
	}

	var prefixes []netip.Prefix
	for _, address := range cfg.Address {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse address: %v", err)
		}
		prefixes = append(prefixes, prefix)
	}

	var dns []netip.Addr
	for _, saddr := range cfg.Dns {
		addr, err := netip.ParseAddr(saddr)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse dns: %v", err)
		}
		dns = append(dns, addr)
	}

	if cfg.Mtu == 0 {
		cfg.Mtu = 1408
	}

	dialer, err := NewStreamDialer(DialerOptions{
		Ipc:      ipc,
		Prefixes: prefixes,
		Mtu:      cfg.Mtu,
		Dns:      dns,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create dialer: %v", err)
	}

	return dialer, ipc, nil
}

func RegisterFallbackParser(opt *mobileproxy.SmartDialerOptions, name string) {
	opt.RegisterFallbackParser(name, FallbackParser)
}
