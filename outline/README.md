# Outline configuration

Register `FallbackParser` as `awg`, then add it to the Outline SDK fallback list:

```yaml
dns:
  - {system: {}}
tls:
  - ""
fallback:
  - awg:
      address: [10.0.0.1/32]
      dns: [8.8.8.8, 8.8.4.4]
      private_key: +CdqlYvjqZ3OUr4mLWvGJo1h67CWpQwMIxA5OpyiJUM=
      s1: 12
      s2: 12
      s3: 12
      s4: 12
      header_protection_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
      content_padding_addition: "10-30"
      rekey_after_time: "120-150"
      rekey_timeout: "5-8"
      reject_after_time: "180-240"
      keepalive_timeout: "10-15"
      max_handshake_attempts: 18
      random_trailers: on
      disable_cookies: off
      peers:
        - public_key: EGxNYihRLKQ9nvdOE5j5aZ7rtw3ttzJS1xxaJpgYYHI=
          endpoint: 192.0.2.1:51820
          allowed_ips: [0.0.0.0/0, "::/0"]
          persistent_keepalive_interval: 25
```

The keys above are public test keys. Replace them before use.

All nine AWG 3.1 fields are optional:

| YAML field | Value | Endpoint requirement |
| --- | --- | --- |
| `header_protection_key` | Base64 encoding of exactly 32 bytes | Must match |
| `content_padding_addition` | Byte range | Client-local |
| `rekey_after_time` | Seconds range | Client-local |
| `rekey_timeout` | Seconds range | Client-local |
| `reject_after_time` | Seconds range | Client-local |
| `keepalive_timeout` | Seconds range | Client-local |
| `max_handshake_attempts` | Attempt-count range | Client-local |
| `random_trailers` | Flag | Must match |
| `disable_cookies` | Flag | Client-local |

A range accepts `a` or `a-b`, with `0 <= a <= b <= 65535`. A single value may be a YAML integer or string; write ranges as strings. Flags accept `on`, `off`, `true`, `false`, `1`, or `0`.

When header protection is active, `s1`, `s2`, `s3`, and `s4` must each be at least 12. S1–S4 and H1–H4 must match the other endpoint. For transport packets, nonzero `content_padding_addition` takes precedence over `random_trailers`.

Omitted fields keep existing defaults. Header protection and random trailers are disabled by default. Use `0` or `0-0` to clear a range override, `off` to disable a flag, and an all-zero 32-byte key to disable header protection.

Run the package contract checks with:

```sh
go test ./outline
go test -race ./outline
```

The optional smoke test may use the network:

```sh
go test -tags=integration ./outline -run '^TestOutlineSmartDialerSmoke$'
```

It checks Outline SDK construction and local proxy startup. The SDK may use its proxyless strategy, so a pass does not prove AWG configuration parsing or an AWG data path.
