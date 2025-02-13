module github.com/amnezia-vpn/amneziawg-go

go 1.23

require (
	github.com/aarzilli/golua v0.0.0-20241229084300-cd31ab23902e
	github.com/tevino/abool/v2 v2.1.0
	golang.org/x/crypto v0.21.0
	golang.org/x/net v0.21.0
	golang.org/x/sys v0.18.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259
)

replace github.com/aarzilli/golua v0.0.0-20241229084300-cd31ab23902e => github.com/marko1777/golua v0.1.0

require (
	github.com/google/btree v1.0.1 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
)
