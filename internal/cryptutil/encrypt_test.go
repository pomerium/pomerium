package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	plaintext := []byte("my plain text value")

	key := GenerateKey()
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if reflect.DeepEqual(plaintext, ciphertext) {
		t.Fatalf("plaintext is not encrypted plaintext:%v ciphertext:%x", plaintext, ciphertext)
	}

	got, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("unexpected err decrypting: %v", err)
	}

	// if less than 32 bytes, fail
	_, err = c.Decrypt([]byte("oh"))
	if err == nil {
		t.Fatalf("should fail if <32 bytes output: %v", err)
	}

	if !reflect.DeepEqual(got, plaintext) {
		t.Logf(" got: %v", got)
		t.Logf("want: %v", plaintext)
		t.Fatal("got unexpected decrypted value")
	}
}

func TestMarshalAndUnmarshalStruct(t *testing.T) {
	key := GenerateKey()

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	type TC struct {
		Field string `json:"field"`
	}

	tc := &TC{
		Field: "my plain text value",
	}

	value1, err := c.Marshal(tc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	value2, err := c.Marshal(tc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if value1 == value2 {
		t.Fatalf("expected marshaled values to not be equal %v != %v", value1, value2)
	}

	got1 := &TC{}
	err = c.Unmarshal(value1, got1)
	if err != nil {
		t.Fatalf("unexpected err unmarshalling struct: %v", err)
	}

	if !reflect.DeepEqual(got1, tc) {
		t.Logf("want: %#v", tc)
		t.Logf(" got: %#v", got1)
		t.Fatalf("expected structs to be equal")
	}

	got2 := &TC{}
	err = c.Unmarshal(value2, got2)
	if err != nil {
		t.Fatalf("unexpected err unmarshalling struct: %v", err)
	}

	if !reflect.DeepEqual(got1, got2) {
		t.Logf("got2: %#v", got2)
		t.Logf("got1: %#v", got1)
		t.Fatalf("expected structs to be equal")
	}
}

func TestCipherDataRace(t *testing.T) {
	cipher, err := NewCipher(GenerateKey())
	if err != nil {
		t.Fatalf("unexpected generating cipher err: %v", err)
	}

	type TC struct {
		Field string `json:"field"`
	}

	wg := &sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(c *XChaCha20Cipher, wg *sync.WaitGroup) {
			defer wg.Done()
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				t.Fatalf("unexecpted error reading random bytes: %v", err)
			}

			sha := fmt.Sprintf("%x", sha1.New().Sum(b))
			tc := &TC{
				Field: sha,
			}

			value1, err := c.Marshal(tc)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			value2, err := c.Marshal(tc)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			if value1 == value2 {
				t.Fatalf("expected marshaled values to not be equal %v != %v", value1, value2)
			}

			got1 := &TC{}
			err = c.Unmarshal(value1, got1)
			if err != nil {
				t.Fatalf("unexpected err unmarshalling struct: %v", err)
			}

			if !reflect.DeepEqual(got1, tc) {
				t.Logf("want: %#v", tc)
				t.Logf(" got: %#v", got1)
				t.Fatalf("expected structs to be equal")
			}

			got2 := &TC{}
			err = c.Unmarshal(value2, got2)
			if err != nil {
				t.Fatalf("unexpected err unmarshalling struct: %v", err)
			}

			if !reflect.DeepEqual(got1, got2) {
				t.Logf("got2: %#v", got2)
				t.Logf("got1: %#v", got1)
				t.Fatalf("expected structs to be equal")
			}

		}(cipher, wg)
	}
	wg.Wait()
}

func TestGenerateRandomString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    int
		want int
	}{
		{"simple", 32, 32},
		{"zero", 0, 0},
		{"negative", -1, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := GenerateRandomString(tt.c)
			b, err := base64.StdEncoding.DecodeString(o)
			if err != nil {
				t.Error(err)
			}
			got := len(b)
			if got != tt.want {
				t.Errorf("GenerateRandomString() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestXChaCha20Cipher_Marshal(t *testing.T) {

	tests := []struct {
		name    string
		s       interface{}
		wantErr bool
	}{
		{"unsupported type",
			struct {
				Animal string `json:"animal"`
				Func   func() `json:"sound"`
			}{
				Animal: "cat",
				Func:   func() {},
			},
			true},
		{"simple",
			struct {
				Animal string `json:"animal"`
				Sound  string `json:"sound"`
			}{
				Animal: "cat",
				Sound:  "meow",
			},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c, err := NewCipher(GenerateKey())
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			_, err = c.Marshal(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("XChaCha20Cipher.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewCipher(t *testing.T) {

	tests := []struct {
		name    string
		secret  []byte
		wantErr bool
	}{
		{"simple 32 byte key", GenerateKey(), false},
		{"key too short", []byte("what is entropy"), true},
		{"key too long", []byte(GenerateRandomString(33)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCipher(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
