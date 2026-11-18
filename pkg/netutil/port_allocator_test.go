package netutil_test

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestBlockPortAllocator(t *testing.T) {
	t.Parallel()

	b := netutil.NewBlockPortAllocator(
		netutil.WithBlockPortAllocatorBlockSize(10),
		netutil.WithBlockPortAllocatorMinPort(20_005),
		netutil.WithBlockPortAllocatorMaxPort(20_093),
		netutil.WithBlockPortAllocatorRandomSource(rand.NewPCG(1, 1)),
		netutil.WithBlockPortAllocatorReserver(func(u uint16) (releaser func(), ok bool) {
			// treat this as a reserved block
			if u == 20_050 {
				return nil, false
			}
			// treat these as reserved by some other process
			if u >= 20_065 && u < 20_068 {
				return nil, false
			}
			return func() {}, true
		}),
	)

	expect := []uint16{
		20_091, 20_092, 20_093,
		20_005, 20_006, 20_007, 20_008, 20_009,
		20_041, 20_042, 20_043, 20_044, 20_045, 20_046, 20_047, 20_048, 20_049,
		20_061, 20_062, 20_063, 20_064, 20_068, 20_069,
		20_011, 20_012, 20_013, 20_014, 20_015, 20_016, 20_017, 20_018, 20_019,
		20_071, 20_072, 20_073, 20_074, 20_075, 20_076, 20_077, 20_078, 20_079,
		20_021, 20_022, 20_023, 20_024, 20_025, 20_026, 20_027, 20_028, 20_029,
		20_081, 20_082, 20_083, 20_084, 20_085, 20_086, 20_087, 20_088, 20_089,
		20_031, 20_032, 20_033, 20_034, 20_035, 20_036, 20_037, 20_038, 20_039,
	}
	for _, e := range expect {
		p, ok := b.AllocatePort()
		assert.True(t, ok)
		assert.Equal(t, int(e), int(p))
	}
	p, ok := b.AllocatePort()
	assert.False(t, ok, "should return false after allocating all possible ports, got: %d", p)
}

func TestEphemeralBindPortAllocator(t *testing.T) {
	t.Parallel()

	b := netutil.NewEphemeralBindPortAllocator()
	p, ok := b.AllocatePort()
	assert.True(t, ok)
	assert.NotZero(t, p)
}
