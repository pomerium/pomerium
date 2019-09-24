package cryptutil

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	plaintext := []byte("my plain text value")

	key := NewKey()
	c, err := NewAEADCipher(key)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ciphertext := Encrypt(c, plaintext, nil)

	if reflect.DeepEqual(plaintext, ciphertext) {
		t.Fatalf("plaintext is not encrypted plaintext:%v ciphertext:%x", plaintext, ciphertext)
	}

	got, err := Decrypt(c, ciphertext, nil)
	if err != nil {
		t.Fatalf("unexpected err decrypting: %v", err)
	}

	// if less than 32 bytes, fail
	_, err = Decrypt(c, []byte("oh"), nil)
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
	key := NewKey()

	a, err := NewAEADCipher(key)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	c := SecureJSONEncoder{aead: a}

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

func TestSecureJSONEncoder_Marshal(t *testing.T) {
	t.Parallel()
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

			c, err := NewAEADCipher(NewKey())
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			e := SecureJSONEncoder{aead: c}

			_, err = e.Marshal(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("SecureJSONEncoder.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewAEADCipher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		secret  []byte
		wantErr bool
	}{
		{"simple 32 byte key", NewKey(), false},
		{"key too short", []byte("what is entropy"), true},
		{"key too long", []byte(NewRandomStringN(33)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAEADCipher(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAEADCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewAEADCipherFromBase64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		s       string
		wantErr bool
	}{
		{"simple 32 byte key", base64.StdEncoding.EncodeToString(NewKey()), false},
		{"key too short", base64.StdEncoding.EncodeToString([]byte("what is entropy")), true},
		{"key too long", NewRandomStringN(33), true},
		{"bad base 64", string(NewKey()), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAEADCipherFromBase64(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAEADCipherFromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
