package encoding // import "github.com/pomerium/pomerium/internal/encoding"

import (
	"errors"
	"testing"
)

func TestMockEncoder(t *testing.T) {
	e := errors.New("err")
	mc := MockEncoder{
		MarshalResponse: []byte("MarshalResponse"),
		MarshalError:    e,
		UnmarshalError:  e,
	}
	s, err := mc.Marshal("test")
	if err != e {
		t.Error("unexpected Marshal error")
	}
	if string(s) != "MarshalResponse" {
		t.Error("unexpected MarshalResponse error")
	}
	err = mc.Unmarshal([]byte("s"), "s")
	if err != e {
		t.Error("unexpected Unmarshal error")
	}
}
