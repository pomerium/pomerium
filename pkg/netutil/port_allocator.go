package netutil

import (
	crnd "crypto/rand"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"

	"github.com/hashicorp/go-set/v3"
)

// A PortAllocator allocates ports.
type PortAllocator interface {
	AllocatePort() (uint16, bool)
}

type ephemeralBindPortAllocator struct {
	mu       sync.Mutex
	reserved *set.Set[uint16]
}

// NewEphemeralBindPortAllocator creates a new PortAllocator that
// allocates ports by binding a listener to :0 and then releasing
// it and using the assigned port as the allocated port.
func NewEphemeralBindPortAllocator() PortAllocator {
	return &ephemeralBindPortAllocator{
		reserved: set.New[uint16](0),
	}
}

func (e *ephemeralBindPortAllocator) AllocatePort() (uint16, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, false
		}
		port := uint16(li.Addr().(*net.TCPAddr).Port)
		defer li.Close()
		if e.reserved.Insert(port) {
			return port, true
		}
	}
}

type portBlock struct {
	first, last uint16
	current     uint16
	release     func()
}

type blockPortAllocator struct {
	reserver     func(uint16) (releaser func(), ok bool)
	blockSize    uint16
	minPort      uint16
	maxPort      uint16
	randomSource rand.Source

	mu        sync.Mutex
	reserved  []portBlock
	available []portBlock
}

// A BlockPortAllocatorOption customizes the block port allocator.
type BlockPortAllocatorOption func(b *blockPortAllocator)

// WithBlockPortAllocatorBlockSize sets the block size that will be used
// for reserving blocks. Defaults to 100.
func WithBlockPortAllocatorBlockSize(blockSize uint16) BlockPortAllocatorOption {
	return func(b *blockPortAllocator) {
		b.blockSize = blockSize
	}
}

// WithBlockPortAllocatorMinPort sets the minimum port that can be used.
// Defaults to 20,000.
func WithBlockPortAllocatorMinPort(minPort uint16) BlockPortAllocatorOption {
	return func(b *blockPortAllocator) {
		b.minPort = minPort
	}
}

// WithBlockPortAllocatorMaxPort sets the maximum port that can be used.
// Defaults to 29,999.
func WithBlockPortAllocatorMaxPort(maxPort uint16) BlockPortAllocatorOption {
	return func(b *blockPortAllocator) {
		b.maxPort = maxPort
	}
}

// WithBlockPortAllocatorRandomSource sets the random source to use. Defaults
// to a ChaCha8 source seeded with the current time.
func WithBlockPortAllocatorRandomSource(randomSource rand.Source) BlockPortAllocatorOption {
	return func(b *blockPortAllocator) {
		b.randomSource = randomSource
	}
}

// WithBlockPortAllocatorReserver customizes the block port allocator so that
// a custom function can be used to indicate a block/port is reserved instead
// of the default net.Listen.
func WithBlockPortAllocatorReserver(reserver func(uint16) (releaser func(), ok bool)) BlockPortAllocatorOption {
	return func(b *blockPortAllocator) {
		b.reserver = reserver
	}
}

// NewBlockPortAllocator creates a new PortAllocator that allocates ports by
// using blocks of ports with each block being reserved by the process by
// using a sentinel port, (the first port in the block). That sentinel port
// is available, the whole block is reserved by the process and ports are
// chosen from it.
func NewBlockPortAllocator(options ...BlockPortAllocatorOption) PortAllocator {
	b := &blockPortAllocator{}
	WithBlockPortAllocatorBlockSize(100)(b)
	WithBlockPortAllocatorMinPort(20_000)(b)
	WithBlockPortAllocatorMaxPort(29_999)(b)
	WithBlockPortAllocatorRandomSource(defaultRandomSource())(b)
	WithBlockPortAllocatorReserver(func(port uint16) (releaser func(), ok bool) {
		li, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, false
		}
		return func() {
			_ = li.Close()
		}, true
	})(b)
	for _, option := range options {
		option(b)
	}

	for i := int(b.minPort); i <= int(b.maxPort); i++ {
		p := uint16(i)
		if len(b.available) == 0 || (b.available[len(b.available)-1].last-b.available[len(b.available)-1].first) >= b.blockSize {
			b.available = append(b.available, portBlock{
				first: p,
				last:  p,
			})
		} else {
			b.available[len(b.available)-1].last++
		}
	}

	rand.New(b.randomSource).Shuffle(len(b.available), func(i, j int) { //nolint:gosec
		b.available[i], b.available[j] = b.available[j], b.available[i]
	})

	return b
}

func (b *blockPortAllocator) AllocatePort() (uint16, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		// if we either have no reserved port blocks, or have used up the last reserved port block, add a new one
		if len(b.reserved) == 0 ||
			b.reserved[len(b.reserved)-1].current == b.reserved[len(b.reserved)-1].last {
			if len(b.available) == 0 {
				// no blocks left
				return 0, false
			}

			// get the port block from the end of the list
			nextPortBlock := b.available[len(b.available)-1]
			b.available = b.available[:len(b.available)-1]

			release, ok := b.reserver(nextPortBlock.first)
			if !ok {
				// this block is already reserved so move on to the next one
				continue
			}
			// add this block to the reserved blocks, holding on to the
			// releaser so the sentinel stays open
			nextPortBlock.current = nextPortBlock.first
			nextPortBlock.release = release
			b.reserved = append(b.reserved, nextPortBlock)
			continue
		}

		next := b.reserved[len(b.reserved)-1].current + 1
		b.reserved[len(b.reserved)-1].current++

		// skip invalid ports
		if next < b.minPort || next > b.maxPort {
			continue
		}

		release, ok := b.reserver(next)
		if ok {
			release()
			return next, true
		}
	}
}

type failoverPortAllocator []PortAllocator

// NewFailoverPortAllocator creates a port allocator that tries the list of
// port allocators until one succeeds.
func NewFailoverPortAllocator(first PortAllocator, rest ...PortAllocator) PortAllocator {
	return failoverPortAllocator(append([]PortAllocator{first}, rest...))
}

func (f failoverPortAllocator) AllocatePort() (uint16, bool) {
	for _, a := range f {
		p, ok := a.AllocatePort()
		if ok {
			return p, true
		}
	}
	return 0, false
}

func defaultRandomSource() rand.Source {
	var seed [32]byte
	_, _ = crnd.Read(seed[:])
	return rand.NewChaCha8(seed)
}
