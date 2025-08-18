package file

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordCIDRIndex(t *testing.T) {
	t.Parallel()

	pfx1 := netip.MustParsePrefix("192.168.0.0/16")
	pfx2 := netip.MustParsePrefix("192.168.0.0/24")
	addr1 := netip.AddrFrom4([4]byte{192, 168, 0, 1})
	n1 := recordCIDRNode{
		recordType: "t1",
		recordID:   "i1",
		prefix:     pfx1,
	}
	n2 := recordCIDRNode{
		recordType: "t2",
		recordID:   "i2",
		prefix:     pfx1,
	}

	idx := newRecordCIDRIndex()
	idx.add(n1)
	idx.add(n2)
	assert.Equal(t, []recordCIDRNode{n1, n2}, idx.lookupAddr("", addr1))
	assert.Equal(t, []recordCIDRNode{n2}, idx.lookupAddr("t2", addr1))
	assert.Equal(t, []recordCIDRNode{n1, n2}, idx.lookupPrefix("", pfx2))
	assert.Equal(t, []recordCIDRNode{n2}, idx.lookupPrefix("t2", pfx2))
	idx.delete(n2)
	assert.Equal(t, []recordCIDRNode{n1}, idx.lookupAddr("", addr1))
	assert.Equal(t, []recordCIDRNode{n1}, idx.lookupPrefix("", pfx2))
}
