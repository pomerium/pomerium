package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertOverlap(t *testing.T) {
	testCases := []struct {
		names []string
		test  string
		match bool
	}{
		{[]string{"aa.bb.cc", "cc.bb.aa"}, "aa.bb.c", false},
		{[]string{"aa.bb.cc"}, "aa.bb.cc", true},
		{[]string{"*.bb.cc"}, "aa.bb.cc", true},
		{[]string{"a1.bb.cc", "a2.bb.cc"}, "*.bb.cc", true},
		{[]string{"*.bb.cc", "a2.bb.cc"}, "*.bb.cc", true},
		{[]string{"*.aa.bb.cc"}, "*.bb.cc", false},
		{[]string{"*.aa.bb.cc"}, "aa.bb.cc", false},
		{[]string{"bb.cc"}, "*.bb.cc", false},
	}
	t.Run("match mix mode", func(t *testing.T) {
		for _, tc := range testCases {
			idx := make(certsIndex)
			for _, name := range tc.names {
				idx.add(name, certUsageServerAuth|certUsageClientAuth)
			}
			assert.Equalf(t, tc.match, idx.match(tc.test, certUsageServerAuth), "%v", tc)
		}
	})
	t.Run("different cert usages never match", func(t *testing.T) {
		for _, tc := range testCases {
			idx := make(certsIndex)
			for _, name := range tc.names {
				idx.add(name, certUsageServerAuth)
			}
			assert.Equalf(t, false, idx.match(tc.test, certUsageClientAuth), "%v", tc)
		}
	})

}
