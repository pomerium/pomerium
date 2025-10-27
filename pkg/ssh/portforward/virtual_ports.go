package portforward

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"

	"github.com/bits-and-blooms/bitset"
)

type VirtualPortSet struct {
	mu        sync.Mutex
	ports     *bitset.BitSet
	maxPorts  uint
	offset    uint
	active    map[uint]context.CancelCauseFunc
	preempted map[uint]context.CancelCauseFunc
}

func NewVirtualPortSet(maxPorts, offset uint) *VirtualPortSet {
	return &VirtualPortSet{
		maxPorts:  maxPorts,
		offset:    offset,
		ports:     bitset.MustNew(maxPorts),
		active:    map[uint]context.CancelCauseFunc{},
		preempted: map[uint]context.CancelCauseFunc{},
	}
}

var (
	ErrNoFreePorts = errors.New("no free ports available")
	ErrPortClosed  = errors.New("port closed")
)

func (vps *VirtualPortSet) Count() uint {
	return vps.ports.Count()
}

func (vps *VirtualPortSet) Get() (uint, context.Context, error) {
	initial := rand.N(vps.maxPorts)
	var port uint
	var ok bool
	if initial%2 == 0 {
		if port, ok = vps.ports.NextClear(initial); !ok {
			port, ok = vps.ports.PreviousClear(initial)
		}
	} else {
		if port, ok = vps.ports.PreviousClear(initial); !ok {
			port, ok = vps.ports.NextClear(initial)
		}
	}
	if ok {
		vps.ports.Set(port)
		ctx, ca := context.WithCancelCause(context.Background())
		vps.active[port] = ca
		return port + vps.offset, ctx, nil
	}
	return 0, nil, ErrNoFreePorts
}

func (vps *VirtualPortSet) WithinRange(port uint) bool {
	return port >= vps.offset && port < vps.offset+vps.maxPorts
}

func (vps *VirtualPortSet) Put(port uint) {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: Put called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if !vps.ports.Test(translatedPort) {
		panic("bug: port was never allocated")
	}
	if _, ok := vps.preempted[translatedPort]; ok {
		panic(fmt.Sprintf("bug: Put called with preempted port %d", port))
	}
	vps.putTranslated(translatedPort)
}

func (vps *VirtualPortSet) putTranslated(port uint) {
	vps.ports.Clear(port)
	vps.active[port](ErrPortClosed)
	delete(vps.active, port)
}

func (vps *VirtualPortSet) Preempt(port uint) context.Context {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: Preempt called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if _, ok := vps.preempted[translatedPort]; ok {
		panic(fmt.Sprintf("bug: Preempt called with port %d which is already preempted", port))
	}
	// first, check if there is an active port with this number
	if _, ok := vps.active[translatedPort]; ok {
		// if so, clear it
		vps.putTranslated(translatedPort)
	}
	ctx, ca := context.WithCancelCause(context.Background())
	vps.preempted[translatedPort] = ca
	vps.ports.Set(translatedPort)
	return ctx
}

func (vps *VirtualPortSet) RemovePreemption(port uint, cause error) {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: RemovePreemption called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if _, ok := vps.preempted[translatedPort]; !ok {
		panic(fmt.Sprintf("bug: RemovePreemption called with port %d which is not preempted", port))
	}
	vps.preempted[translatedPort](cause)
	delete(vps.preempted, translatedPort)
	vps.ports.Clear(translatedPort)
}
