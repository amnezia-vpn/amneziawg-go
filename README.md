# Go Implementation of AmneziaWG

AmneziaWG is a contemporary version of the WireGuard protocol. It's a fork of WireGuard-Go and offers protection against detection by Deep Packet Inspection (DPI) systems. At the same time, it retains the simplified architecture and high performance of the original.

The precursor, WireGuard, is known for its efficiency but had issues with detection due to its distinctive packet signatures.
AmneziaWG addresses this problem by employing advanced obfuscation methods, allowing its traffic to blend seamlessly with regular internet traffic.
As a result, AmneziaWG maintains high performance while adding an extra layer of stealth, making it a superb choice for those seeking a fast and discreet VPN connection.

## Usage

Simply run:

```
$ amneziawg-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/amneziawg/wg0.sock`, which will result in amneziawg-go shutting down.

To run amneziawg-go without forking to the background, pass `-f` or `--foreground`:

```
$ amneziawg-go -f wg0
```
When an interface is running, you may use [`amneziawg-tools `](https://github.com/amnezia-vpn/amneziawg-tools) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; you should run amnezia-wg instead of using default linux kernel module.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.
This runs on MacOS, you should use it from [amneziawg-apple](https://github.com/amnezia-vpn/amneziawg-apple)

### Windows

This runs on Windows, you should use it from [amneziawg-windows](https://github.com/amnezia-vpn/amneziawg-windows), which uses this as a module.


## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://github.com/amnezia-vpn/amneziawg-go
$ cd amneziawg-go
$ make
```

## Configuration

> [!NOTE]
> If there is no value specified (for any param), AWG treats it as 0

### Junk packets

The amount of junk packets specified in `Jc` with a random size between `Jmin` and `Jmax` would be generated and sent prior every handshake

- `Jc: int`, recommended range is 4-12
- `Jmin: int` <= `Jmax:int`

> [!TIP]
> Junk packets do not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If Jmax >= system MTU (not the one specified in AWG), then the system can fracture this packet into fragments, which looks suspicious from the censor side

### Message paddings

- `S1: int` - padding of handshake initial message
- `S2: int` - padding of handshake response message
- `S3: int` - padding of handshake cookie message
- `S4: int` - padding of transport messages

### Message headers

Every message in wireguard has `int32` type at the beginning of the packet. This field could be controlled by specifying the params below:

- `H1: string` - header range of handshake initial message
- `H2: string` - header range of handshake initial message
- `H3: string` - header range of handshake cookie message
- `H4: string` - header range of transport message

Values could be specified as:
- range: `x-y`, x <= y; e.g. `123-456`
- single value `1234`

> [!TIP]
> Custom signature packets does not carry any actual data, so there is no need to specify it on both sides. General recommendation is to use it on the client side only

> [!IMPORTANT]
> If the final size of any packet exceeds system MTU, it would be fractured into fragments, which looks suspicious

### Custom signature packets

These packets are being send prior to every handshake, in the same way as Junk packets do. The sending order is `I1`, `I2`, `I3`, `I4`, `I5`. If there is no value specified, the packet is skipped.

- `I1: string`
- `I2: string`
- `I3: string`
- `I4: string`
- `I5: string`

Value as a tag-sequence, as described in Tag format paragraph

### Network

**`Network: "udp" | "tcp"`**
- A network which device would use to connect to peers
- In case of `tcp`, the connection is always initiated by the peer which has `Endpoint` specified
- In case of `tcp`, the device would not listen if `ListenPort` is omitted

> [!NOTE]
> Although it is not required, `Network = tcp` would highly-likely require `FormatIn` and `FormatOut` parameters since stream connection does not have fixed-sized messages

### Fallback

**`FallbackPort: int`**
- A local fallback service port in range `1-65535`.
- If configured and incoming data does not match the configured AWG/conceal formats, AWG proxies that TCP stream or UDP sender to a loopback service on `FallbackPort` and relays the response back to the original sender.
- Absence means fallback is disabled.

### Message format

**`FormatIn: string of tags`**
- A format of packet which AWG device would expect on the input side instead of the original WG packet
- The packet could be a part of the stream if `<dz>` is specified

**`FormatOut: string of tags`**
- A format of packet which AWG device would generate on the output side instead of the original WG packet. The whole packet would be generated as a single piece and would be sent to the system as-is

- **Example**
```
FormatIn = <b 0x4567><dz be 4><r 12><d><t>
FormatOut = <b 0x1234><dz be 4><d>
```

> [!IMPORTANT]
> For TCP network it is really neccessary to specify `<dz>` tag somewhere because of the stream nature - the original packet could be coalecsed with the next one or splitted into the fragments

> [!IMPORTANT]
> Always put `<d>` tag in the format.

> [!IMPORTANT]
> Peer's `FormatIn` must be the same as device's `FormatOut` for ***machines*** to understand each other formats

## Tags format

### Static bytes tag

**Description**
- Static bytes, sends and receives specified bytes as-is with predictable size
- Immutable, does not change after configuration

**Format**
```
<b 0x[seq]>
```

**Params**
- `[seq]` - *always even-sized* hex-encoded sequence of bytes (2 hex numbers per byte)

**Sample usage**
```
<b 0xd34db3ef>
<b 0x1234><dz be 2><d>
```

### Random bytes tag

**Description**
- Randomly-generated bytes of specified size
- Uses cryptographically secure generator

**Format**
```
<r [size]>
```

**Params**
- `[size]` - amount of random bytes

**Sample usage**
```
<r 21>
<r 21><dz be 2><r 1><d>
```

### Random digits tag

**Description**
- Randomly-generated digits from `[0-9]` set
- Uses cryptographically secure generator

**Format**
```
<rd [size]>
```

**Params**
- `[size]` - amount of digits

**Sample usage**
```
<rd 21>
<b 0x6e756d3a><rd 21><b 0x0d0a><dz hex 0x0d><b 0x0a><rd 1><d>
```

### Random characters tag

**Description**
- Randomly-generated digits from `[a-zA-Z]` set
- Uses cryptographically secure generator

**Format**
```
<rc [size]>
```

**Params**
- `[size]` - amount of chars

**Example**
```
<rc 21>
<b 0x6e616d653a><rc 21><b 0x0d0a><dz ascii 0x0d><b 0x0a><rc 1><d>
```

### Timestamp tag

**Description**
- Current UNIX time, int32
- Provided in big-endian

**Format**
```
<t>
```

**Sample usage**
```
<t>
<b 0x1234><t><dz be 2><d>
```

### Data tag

**Description**
- The original WireGuard packet
- Has `H1-H4` and `S1-S4` params applied

**Format**
```
<d>
```

**Sample usage**
```
<d>
<dz hex 0x0d><b 0x0a><d>
```

### Data size tag

**Description**
- Size of the remaining pard of original WireGuard packet
- `hex` and `ascii` formats are dynamic-sized and no leading zeroes
- sender appends `[end]` to the end in case of `ascii` or `hex`

**Format**
```
<dz [fmt] [size|end]>
```

**Params**
- `[fmt]` - format of the field
    - `be`    - fixed-size big-endian
    - `le`    - fixed-size little-endian
    - `ascii` - decimal ascii representation
    - `hex`   - hexadecimal ASCII representation
- `[size]` - amount of bytes of the field
    - only for `be` and `le`
- `[end]` - the symbol following the data size
    - only for `ascii` and `hex`

**Sample usage**
```
<dz ascii 0x0d>     e.g. `10 -> "10\r"`
<dz hex 0x0a>       e.g. `10 -> "A\n"`
<dz be 4>           e.g. `10 -> 0x00 0x00 0x00 0x0A`
<dz le 2>           e.g. `10 -> 0x0A 0x00`

<dz 0x0d><b 0x0a><d><b 0x0d0a>
```
