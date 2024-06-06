package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func checkTLSVersions(host string) {
	versions := map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	for version, name := range versions {
		conn, err := tls.Dial("tcp", host, &tls.Config{MinVersion: version, MaxVersion: version})
		if err == nil {
			defer conn.Close()
			cert := conn.ConnectionState().PeerCertificates[0]
			hash := sha256.Sum256(cert.Raw)
			fmt.Printf("%s supported - Certificate hash: %s\n", name, hex.EncodeToString(hash[:]))
		}
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <host:port>\n", os.Args[0])
		return
	}
	host := os.Args[1]
	if !strings.Contains(host, ":") {
		fmt.Println("Need the host in the format host:port")
	}
	checkTLSVersions(host)
}
