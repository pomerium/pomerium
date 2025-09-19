package ssh

import (
	"errors"
	"math/rand/v2"
	"sync"

	"github.com/bits-and-blooms/bitset"
)

const (
	maxPorts = 32768
	offset   = 32768
)

type virtualPortSet struct {
	mu    sync.Mutex
	ports *bitset.BitSet
}

func NewVirtualPortSet() *virtualPortSet {
	return &virtualPortSet{
		ports: bitset.MustNew(maxPorts),
	}
}

var ErrNoFreePorts = errors.New("no free ports available")

func (vpa *virtualPortSet) Count() uint {
	return vpa.ports.Count()
}

func (vpa *virtualPortSet) Get() (uint, error) {
	initial := rand.N[uint16](maxPorts)
	var port uint
	var ok bool
	if initial%2 == 0 {
		if port, ok = vpa.ports.NextClear(uint(initial)); !ok {
			port, ok = vpa.ports.PreviousClear(uint(initial))
		}
	} else {
		if port, ok = vpa.ports.PreviousClear(uint(initial)); !ok {
			port, ok = vpa.ports.NextClear(uint(initial))
		}
	}
	if ok {
		vpa.ports.Set(port)
		return port + offset, nil
	}
	return 0, ErrNoFreePorts
}

func (vpa *virtualPortSet) WithinVirtualPortRange(port uint) bool {
	return port >= offset && port < offset+maxPorts
}

func (vpa *virtualPortSet) Put(port uint) {
	if !vpa.ports.Test(port - offset) {
		panic("bug: port was never allocated")
	}
	vpa.ports.Clear(port - offset)
}
