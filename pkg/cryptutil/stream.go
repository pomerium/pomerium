package cryptutil

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	streamBlockSize = 4096
)

// EncryptStream encrypts the src stream and returns the encrypted stream reader
func EncryptStream(src io.Reader, c cipher.AEAD) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		err := encryptStream(pw, src, c)
		if err != nil {
			_ = pw.CloseWithError(fmt.Errorf("encrypting stream: %w", err))
		} else {
			_ = pw.Close()
		}
	}()

	return pr, nil
}

func encryptStream(dst io.Writer, src io.Reader, c cipher.AEAD) error {
	buf := make([]byte, streamBlockSize+c.Overhead())
	sizeBuf := make([]byte, 4)
	nonce := make([]byte, c.NonceSize())

	for {
		n, err := src.Read(buf[0:streamBlockSize])
		if n > 0 {
			binary.BigEndian.PutUint32(sizeBuf, uint32(n))
			_, err = dst.Write(sizeBuf)
			if err != nil {
				return fmt.Errorf("writing block size: %w", err)
			}

			_, err := rand.Read(nonce)
			if err != nil {
				return fmt.Errorf("generating nonce: %w", err)
			}

			_, err = dst.Write(nonce)
			if err != nil {
				return fmt.Errorf("writing nonce: %w", err)
			}

			_, err = dst.Write(c.Seal(nil, nonce, buf[0:n], sizeBuf))
			if err != nil {
				return fmt.Errorf("encrypting block: %w", err)
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading block: %w", err)
		}
	}
}

// DecryptStream decrypts the src stream and returns the decrypted stream reader
func DecryptStream(src io.Reader, c cipher.AEAD) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		err := decryptStream(pw, src, c)
		if err != nil {
			_ = pw.CloseWithError(fmt.Errorf("decrypting stream: %w", err))
		} else {
			_ = pw.Close()
		}
	}()

	return pr, nil
}

func decryptStream(dst io.Writer, src io.Reader, c cipher.AEAD) error {
	buf := make([]byte, streamBlockSize+c.Overhead())
	sizeBuf := make([]byte, 4)
	nonce := make([]byte, c.NonceSize())

	for {
		_, err := io.ReadFull(src, sizeBuf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading block size: %w", err)
		}

		_, err = io.ReadFull(src, nonce)
		if err != nil {
			return fmt.Errorf("reading nonce: %w", err)
		}

		n := binary.BigEndian.Uint32(sizeBuf)
		_, err = io.ReadFull(src, buf[0:int(n)+c.Overhead()])
		if err != nil {
			return fmt.Errorf("reading block: %w", err)
		}

		plaintext, err := c.Open(nil, nonce, buf[0:int(n)+c.Overhead()], sizeBuf)
		if err != nil {
			return fmt.Errorf("decrypting block: %w", err)
		}

		_, err = dst.Write(plaintext)
		if err != nil {
			return fmt.Errorf("writing block: %w", err)
		}
	}
}
