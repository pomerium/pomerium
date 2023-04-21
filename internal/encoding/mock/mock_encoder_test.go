package mock

import (
	"errors"
	"testing"
)

func TestMockEncoder(t *testing.T) {
	e := errors.New("err")
	mc := Encoder{
		MarshalResponse: []byte("MarshalResponse"),
		MarshalError:    e,
		UnmarshalError:  e,
	}
	s, err := mc.Marshal("test")
	if !errors.Is(err, e) {
		t.Error("unexpected Marshal error")
	}
	if string(s) != "MarshalResponse" {
		t.Error("unexpected MarshalResponse error")
	}
	err = mc.Unmarshal([]byte("s"), "s")
	if !errors.Is(err, e) {
		t.Error("unexpected Unmarshal error")
	}
}
