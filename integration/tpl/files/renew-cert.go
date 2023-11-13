//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: go run renew-cert.go <cert-path> <ca-path> <ca-key-path>")
		os.Exit(2)
	}

	certPath := os.Args[1]
	b, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalln(err)
	}
	block, _ := pem.Decode(b)
	tpl, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalln(err)
	}

	// Parse the CA certificate and private key.
	b, err = os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatalln(err)
	}
	block, _ = pem.Decode(b)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalln(err)
	}
	b, err = os.ReadFile(os.Args[3])
	if err != nil {
		log.Fatalln(err)
	}
	block, _ = pem.Decode(b)
	caKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalln(err)
	}

	if tpl.CheckSignatureFrom(caCert) != nil {
		log.Fatalln("error: cert was not issued by the provided CA")
	}

	now := time.Now()
	tpl.NotBefore = now
	tpl.NotAfter = now.Add(3650 * 24 * time.Hour)

	// Issue the new certificate.
	b, err = x509.CreateCertificate(rand.Reader, tpl, caCert, tpl.PublicKey, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	// Write the new certificate to a PEM file.
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	if err := os.WriteFile(certPath, b, 0644); err != nil {
		log.Fatalln(err)
	}
}
