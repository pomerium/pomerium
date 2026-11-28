package resolver

import (
	"fmt"
	"testing"
)

// BenchmarkLookup guards the hot-path allocation target (§1.8): one atomic load
// plus two map reads. Run with -benchmem; expect 0 allocs/op.
//
// The snapshot is built directly (bypassing the fetch loops) so the benchmark
// measures only the read path.
func BenchmarkLookup(b *testing.B) {
	const bindingsN = 1000
	snap := &snapshot{
		bindings: make(map[string]bindingInfo, bindingsN),
		values:   make(map[string]valueEntry, bindingsN/2),
	}
	ids := make([]string, 0, bindingsN)
	for i := range bindingsN {
		vk := fmt.Sprintf("file:///s%d", i/2) // 500 distinct value keys
		snap.values[vk] = valueEntry{value: secretString(fmt.Sprintf("value-%d", i)), state: StateFresh}
		id := fmt.Sprintf("id%d", i)
		snap.bindings[id] = bindingInfo{valueKey: vk, metricLabel: id, scheme: "file"}
		ids = append(ids, id)
	}

	var r Resolver
	r.snap.Store(snap)

	b.ReportAllocs()
	b.ResetTimer()

	var sink LookupResult
	for i := range b.N {
		sink = r.Lookup(ids[i%len(ids)])
	}
	_ = sink
}
