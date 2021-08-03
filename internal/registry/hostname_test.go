package registry

import (
	"testing"
)

func TestHostname(t *testing.T) {
	t.Log(getHostOrIP())
}
