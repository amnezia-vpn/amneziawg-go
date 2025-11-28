package outline_test

import (
	"testing"

	"github.com/Jigsaw-Code/outline-sdk/x/mobileproxy"
	awg "github.com/amnezia-vpn/amneziawg-go/outline"
)

const cfg = `
dns:
  - {system: {}}
tls:
  - ""
fallback:
  - awg:
      address: [10.0.0.0/32]
      dns: [8.8.8.8, 8.8.4.4]
      private_key: +CdqlYvjqZ3OUr4mLWvGJo1h67CWpQwMIxA5OpyiJUM=
      jc: 4
      jmin: 50
      jmax: 100
      s1: 87
      s2: 65
      s3: 43
      s4: 21
      h1: 1000000000-1000000001
      h2: 2000000000-2000000002
      h3: 3000000000-3000000003
      h4: 4000000000-4000000004
      peers:
        - public_key: EGxNYihRLKQ9nvdOE5j5aZ7rtw3ttzJS1xxaJpgYYHI=
          preshared_key: 2OiSh6rP3t/g39jgJNGK70B+nize821yIFNtUqi8/XU=
          endpoint: 123.123.123.123:51820
          allowed_ips: [0.0.0.0/0, ::/0]
          persistent_keepalive_interval: 25
`

var testDomains = mobileproxy.NewListFromLines("example.com")

func Test_outlineIntegration(t *testing.T) {
	opts := mobileproxy.NewSmartDialerOptions(testDomains, cfg)
	opts.SetLogWriter(mobileproxy.NewStderrLogWriter())
	awg.RegisterFallbackParser(opts, "awg")
	dialer, err := opts.NewStreamDialer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mobileproxy.RunProxy("", dialer); err != nil {
		t.Fatal(err)
	}
}
