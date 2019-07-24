package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"errors"
	"testing"
)

func TestMockCipher_Unmarshal(t *testing.T) {
	e := errors.New("err")
	mc := MockCipher{
		EncryptResponse: []byte("EncryptResponse"),
		EncryptError:    e,
		DecryptResponse: []byte("DecryptResponse"),
		DecryptError:    e,
		MarshalResponse: "MarshalResponse",
		MarshalError:    e,
		UnmarshalError:  e,
	}
	b, err := mc.Encrypt([]byte("test"))
	if string(b) != "EncryptResponse" {
		t.Error("unexpected encrypt response")
	}
	if err != e {
		t.Error("unexpected encrypt error")
	}
	b, err = mc.Decrypt([]byte("test"))
	if string(b) != "DecryptResponse" {
		t.Error("unexpected Decrypt response")
	}
	if err != e {
		t.Error("unexpected Decrypt error")
	}
	s, err := mc.Marshal("test")
	if err != e {
		t.Error("unexpected Marshal error")
	}
	if s != "MarshalResponse" {
		t.Error("unexpected MarshalResponse error")
	}
	err = mc.Unmarshal("s", "s")
	if err != e {
		t.Error("unexpected Unmarshal error")
	}
}
