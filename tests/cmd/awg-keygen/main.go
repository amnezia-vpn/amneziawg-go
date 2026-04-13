package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"

	"golang.org/x/crypto/curve25519"
)

type keypairOutput struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

type pskOutput struct {
	PSK string `json:"psk"`
}

func main() {
	mode := flag.String("mode", "keypair", "keypair or psk")
	flag.Parse()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	switch *mode {
	case "keypair":
		private := make([]byte, 32)
		if _, err := rand.Read(private); err != nil {
			log.Fatalf("read private key: %v", err)
		}
		private[0] &= 248
		private[31] &= 127
		private[31] |= 64

		public, err := curve25519.X25519(private, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("derive public key: %v", err)
		}

		if err := enc.Encode(keypairOutput{
			Private: hex.EncodeToString(private),
			Public:  hex.EncodeToString(public),
		}); err != nil {
			log.Fatalf("encode keypair: %v", err)
		}
	case "psk":
		psk := make([]byte, 32)
		if _, err := rand.Read(psk); err != nil {
			log.Fatalf("read psk: %v", err)
		}
		if err := enc.Encode(pskOutput{PSK: hex.EncodeToString(psk)}); err != nil {
			log.Fatalf("encode psk: %v", err)
		}
	default:
		log.Fatalf("unsupported mode %q", *mode)
	}
}
