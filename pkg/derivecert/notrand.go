package derivecert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/pomerium/pomerium/internal/deterministicecdsa"
)

type readerType byte

const (
	readerTypeCAPrivateKey readerType = iota
	readerTypeCACertificate
	readerTypeServerPrivateKey
	readerTypeServerCertificate
	readerTypeSerialNumber
)

func newReader(readerType readerType, psk []byte, domains ...string) io.Reader {
	var buf bytes.Buffer
	buf.WriteByte(byte(readerType))
	buf.Write(psk)
	buf.WriteByte(0)
	for _, domain := range domains {
		buf.WriteString(domain)
		buf.WriteByte(0)
	}

	return hkdf.New(sha256.New, buf.Bytes(), nil, nil)
}

func deriveKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	return deterministicecdsa.GenerateKey(elliptic.P256(), r)
}
