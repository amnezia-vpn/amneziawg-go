package outline

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const (
	testPrivateKeyBase64      = "+CdqlYvjqZ3OUr4mLWvGJo1h67CWpQwMIxA5OpyiJUM="
	testPublicKeyBase64       = "EGxNYihRLKQ9nvdOE5j5aZ7rtw3ttzJS1xxaJpgYYHI="
	testSecondPublicKeyBase64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	testPresharedKeyBase64    = "2OiSh6rP3t/g39jgJNGK70B+nize821yIFNtUqi8/XU="
	testZeroKeyBase64         = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	testPrivateKeyHex = "f8276a958be3a99dce52be262d6bc6268d61ebb096a50c0c2310393a9ca22543"
)

const awg31FullYAML = `private_key: +CdqlYvjqZ3OUr4mLWvGJo1h67CWpQwMIxA5OpyiJUM=
s1: 12
s2: 12
s3: 12
s4: 12
header_protection_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
content_padding_addition: 10-30
rekey_after_time: 120
rekey_timeout: "5-8"
reject_after_time: 180-240
keepalive_timeout: 10-15
max_handshake_attempts: 18
random_trailers: on
disable_cookies: true
peers:
  - public_key: EGxNYihRLKQ9nvdOE5j5aZ7rtw3ttzJS1xxaJpgYYHI=
    endpoint: 127.0.0.1:2
    allowed_ips: [0.0.0.0/0, "::/0"]
`

var awg31InterfaceFields = []string{
	"header_protection_key",
	"content_padding_addition",
	"rekey_after_time",
	"rekey_timeout",
	"reject_after_time",
	"keepalive_timeout",
	"max_handshake_attempts",
	"random_trailers",
	"disable_cookies",
}

var awg31ExpectedInterfaceLines = []string{
	"header_protection_key=" + strings.Repeat("01", 32),
	"content_padding_addition=10-30",
	"rekey_after_time=120",
	"rekey_timeout=5-8",
	"reject_after_time=180-240",
	"keepalive_timeout=10-15",
	"max_handshake_attempts=18",
	"random_trailers=true",
	"disable_cookies=true",
}

func TestLegacyConfigToIPC(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "minimal",
			input: "private_key: " + testPrivateKeyBase64 + "\n",
			want:  "private_key=" + testPrivateKeyHex,
		},
		{
			name: "full interface and two peers",
			input: `private_key: +CdqlYvjqZ3OUr4mLWvGJo1h67CWpQwMIxA5OpyiJUM=
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
i1: "alpha"
i2: "beta"
i3: "gamma"
i4: "delta"
i5: "epsilon"
peers:
  - public_key: EGxNYihRLKQ9nvdOE5j5aZ7rtw3ttzJS1xxaJpgYYHI=
    endpoint: 192.0.2.1:51820
    allowed_ips: [0.0.0.0/0, "::/0"]
    preshared_key: 2OiSh6rP3t/g39jgJNGK70B+nize821yIFNtUqi8/XU=
    persistent_keepalive_interval: 25
  - public_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    endpoint: 198.51.100.2:53
    allowed_ips: [10.0.0.0/8]
`,
			want: "private_key=" + testPrivateKeyHex + `
jc=4
jmin=50
jmax=100
s1=87
s2=65
s3=43
s4=21
h1=1000000000-1000000001
h2=2000000000-2000000002
h3=3000000000-3000000003
h4=4000000000-4000000004
i1=alpha
i2=beta
i3=gamma
i4=delta
i5=epsilon
public_key=106c4d6228512ca43d9ef74e1398f9699eebb70dedb73252d71c5a2698186072
endpoint=192.0.2.1:51820
allowed_ip=0.0.0.0/0
allowed_ip=::/0
preshared_key=d8e89287aacfdedfe0dfd8e024d18aef407e9e2cdef36d7220536d52a8bcfd75
persistent_keepalive_interval=25
public_key=0101010101010101010101010101010101010101010101010101010101010101
endpoint=198.51.100.2:53
allowed_ip=10.0.0.0/8`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := mustGenerateIPC(t, tt.input)
			if ipc != tt.want {
				t.Fatal("legacy IPC changed")
			}

			lines := strings.Split(ipc, "\n")
			for _, field := range awg31InterfaceFields {
				if containsIPCField(lines, field) {
					t.Fatalf("legacy IPC unexpectedly contains %s", field)
				}
			}
		})
	}
}

func TestAWG31ConfigToIPC(t *testing.T) {
	ipc := mustGenerateIPC(t, awg31FullYAML)
	lines := strings.Split(ipc, "\n")
	peerIndex := indexIPCField(lines, "public_key")
	if peerIndex < 0 {
		t.Fatal("missing peer")
	}

	for _, want := range awg31ExpectedInterfaceLines {
		index := slices.Index(lines, want)
		if index < 0 || index >= peerIndex {
			name := strings.SplitN(want, "=", 2)[0]
			t.Errorf("missing or misplaced %s", name)
		}
	}
}

func TestAWG31Ranges(t *testing.T) {
	fields := []string{
		"content_padding_addition",
		"rekey_after_time",
		"rekey_timeout",
		"reject_after_time",
		"keepalive_timeout",
		"max_handshake_attempts",
	}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unquoted scalar", input: "120", want: "120"},
		{name: "quoted scalar", input: `"120"`, want: "120"},
		{name: "range", input: `"120-180"`, want: "120-180"},
		{name: "zero", input: "0", want: "0"},
		{name: "zero range", input: `"0-0"`, want: "0-0"},
		{name: "range starting at zero", input: `"0-5"`, want: "0-5"},
		{name: "uint16 maximum", input: "65535", want: "65535"},
		{name: "uint16 maximum range", input: `"65535-65535"`, want: "65535-65535"},
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					input := fmt.Sprintf(
						"private_key: %s\n%s: %s\n",
						testPrivateKeyBase64,
						field,
						tt.input,
					)
					lines := strings.Split(mustGenerateIPC(t, input), "\n")
					if !slices.Contains(lines, field+"="+tt.want) {
						t.Fatalf("%s did not preserve %q", field, tt.want)
					}
				})
			}
		})
	}
}

func TestAWG31RangeErrors(t *testing.T) {
	fields := []string{
		"content_padding_addition",
		"rekey_after_time",
		"rekey_timeout",
		"reject_after_time",
		"keepalive_timeout",
		"max_handshake_attempts",
	}
	values := []string{
		"-1",
		"65536",
		"0-65536",
		"2-1",
		"1-2-3",
		"abc",
		"1.5",
		" 1",
		"1 ",
		"1\npublic_key=00",
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			for _, value := range values {
				t.Run(value, func(t *testing.T) {
					input := fmt.Sprintf(
						"private_key: %s\n%s: %q\n",
						testPrivateKeyBase64,
						field,
						value,
					)
					_, err := genIpcString(mustMapConfigYAML(t, input))
					if err == nil || !strings.Contains(err.Error(), field) {
						t.Fatalf("expected field-specific error for %s", field)
					}
				})
			}
		})
	}
}

func TestAWG31Flags(t *testing.T) {
	fields := []string{"random_trailers", "disable_cookies"}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unquoted on", input: "on", want: "true"},
		{name: "quoted on", input: `"on"`, want: "true"},
		{name: "native true", input: "true", want: "true"},
		{name: "one", input: "1", want: "true"},
		{name: "unquoted off", input: "off", want: "false"},
		{name: "quoted off", input: `"off"`, want: "false"},
		{name: "native false", input: "false", want: "false"},
		{name: "zero", input: "0", want: "false"},
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			lines := strings.Split(
				mustGenerateIPC(t, "private_key: "+testPrivateKeyBase64+"\n"),
				"\n",
			)
			if containsIPCField(lines, field) {
				t.Fatalf("omitted %s reached IPC", field)
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					input := fmt.Sprintf(
						"private_key: %s\n%s: %s\n",
						testPrivateKeyBase64,
						field,
						tt.input,
					)
					lines := strings.Split(mustGenerateIPC(t, input), "\n")
					if !slices.Contains(lines, field+"="+tt.want) {
						t.Fatalf("%s did not normalize %s to %s", field, tt.name, tt.want)
					}
				})
			}
		})
	}
}

func TestAWG31FlagErrors(t *testing.T) {
	fields := []string{"random_trailers", "disable_cookies"}
	values := []string{"yes", "no", "2", "enabled", "on\nreplace_peers=true"}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			for _, value := range values {
				t.Run(value, func(t *testing.T) {
					input := fmt.Sprintf(
						"private_key: %s\n%s: %q\n",
						testPrivateKeyBase64,
						field,
						value,
					)
					_, err := genIpcString(mustMapConfigYAML(t, input))
					if err == nil || !strings.Contains(err.Error(), field) {
						t.Fatalf("expected field-specific error for %s", field)
					}
				})
			}
		})
	}
}

func TestAWG31HeaderKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "nonzero key",
			input: testSecondPublicKeyBase64,
			want:  strings.Repeat("01", 32),
		},
		{
			name:  "zero key",
			input: testZeroKeyBase64,
			want:  strings.Repeat("00", 32),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(
				"private_key: %s\nheader_protection_key: %s\n",
				testPrivateKeyBase64,
				tt.input,
			)
			lines := strings.Split(mustGenerateIPC(t, input), "\n")
			if !slices.Contains(lines, "header_protection_key="+tt.want) {
				t.Fatal("header protection key did not reach IPC as exact hex")
			}
		})
	}

	t.Run("omitted", func(t *testing.T) {
		lines := strings.Split(
			mustGenerateIPC(t, "private_key: "+testPrivateKeyBase64+"\n"),
			"\n",
		)
		if containsIPCField(lines, "header_protection_key") {
			t.Fatal("omitted header protection key reached IPC")
		}
	})

	errors := []struct {
		name  string
		input string
	}{
		{name: "invalid base64", input: "not-base64"},
		{name: "31 bytes", input: base64.StdEncoding.EncodeToString(make([]byte, 31))},
		{name: "33 bytes", input: base64.StdEncoding.EncodeToString(make([]byte, 33))},
	}
	for _, tt := range errors {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(
				"private_key: %s\nheader_protection_key: %s\n",
				testPrivateKeyBase64,
				tt.input,
			)
			_, err := genIpcString(mustMapConfigYAML(t, input))
			if err == nil {
				t.Fatal("expected invalid header protection key error")
			}
			if strings.Contains(err.Error(), tt.input) {
				t.Fatal("header protection key error contains raw key")
			}
		})
	}
}

func TestAWG31InterfaceBeforePeers(t *testing.T) {
	input := strings.TrimSuffix(awg31FullYAML, "\n") + `
    preshared_key: 2OiSh6rP3t/g39jgJNGK70B+nize821yIFNtUqi8/XU=
    persistent_keepalive_interval: 25
  - public_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    endpoint: 198.51.100.2:53
    allowed_ips: [10.0.0.0/8]
    preshared_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    persistent_keepalive_interval: 9
`
	lines := strings.Split(mustGenerateIPC(t, input), "\n")
	peerIndex := indexIPCField(lines, "public_key")
	if peerIndex < 0 {
		t.Fatal("missing first peer")
	}

	for _, want := range awg31ExpectedInterfaceLines {
		index := slices.Index(lines, want)
		if index < 0 || index >= peerIndex {
			name := strings.SplitN(want, "=", 2)[0]
			t.Fatalf("missing or misplaced interface field %s", name)
		}
	}
	requireIPCLineSequence(t, lines, awg31ExpectedInterfaceLines)
	requireIPCLineSequence(t, lines, []string{
		"public_key=106c4d6228512ca43d9ef74e1398f9699eebb70dedb73252d71c5a2698186072",
		"endpoint=127.0.0.1:2",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"preshared_key=d8e89287aacfdedfe0dfd8e024d18aef407e9e2cdef36d7220536d52a8bcfd75",
		"persistent_keepalive_interval=25",
	})
	requireIPCLineSequence(t, lines, []string{
		"public_key=0101010101010101010101010101010101010101010101010101010101010101",
		"endpoint=198.51.100.2:53",
		"allowed_ip=10.0.0.0/8",
		"preshared_key=" + strings.Repeat("00", 32),
		"persistent_keepalive_interval=9",
	})
}

func mustMapConfigYAML(t *testing.T, input string) *DeviceConfig {
	t.Helper()

	var node any
	if err := yaml.Unmarshal([]byte(input), &node); err != nil {
		t.Fatal(err)
	}

	cfg, err := mapYamlToConfig(node)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func mustGenerateIPC(t *testing.T, input string) string {
	t.Helper()

	ipc, err := genIpcString(mustMapConfigYAML(t, input))
	if err != nil {
		t.Fatal(err)
	}
	return ipc
}

func containsIPCField(lines []string, name string) bool {
	return indexIPCField(lines, name) >= 0
}

func indexIPCField(lines []string, name string) int {
	prefix := name + "="
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return i
		}
	}
	return -1
}

func requireIPCLineSequence(t *testing.T, lines, want []string) {
	t.Helper()

	for i := 0; i+len(want) <= len(lines); i++ {
		if slices.Equal(lines[i:i+len(want)], want) {
			return
		}
	}
	name := strings.SplitN(want[0], "=", 2)[0]
	t.Fatalf("missing ordered IPC line sequence beginning with %s", name)
}
