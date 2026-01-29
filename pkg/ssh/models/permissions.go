package models

import (
	"strconv"
	"sync"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type Permission struct {
	portforward.Permission
	MatchCount int
}

func (p Permission) Key() uint64 {
	d := hashutil.NewDigest()
	d.WriteStringWithLen(p.HostMatcher.InputPattern())
	d.WriteUint32(p.RequestedPort)
	d.WriteUint32(uint32(p.VirtualPort))
	return d.Sum64()
}

type PermissionModel struct {
	ItemModel[Permission, uint64]
	mu sync.Mutex
}

func NewPermissionModel() *PermissionModel {
	return &PermissionModel{
		ItemModel: NewItemModel[Permission](),
	}
}

func (p Permission) ToRow() []string {
	sp := p.Permission.ServerPort()
	var pattern string
	if p.HostMatcher.IsMatchAll() {
		pattern = "(all)"
	} else {
		pattern = p.HostMatcher.InputPattern()
	}
	portStr := strconv.FormatInt(int64(sp.Value), 10)
	if sp.IsDynamic {
		portStr = "D " + portStr
	}
	numMatches := strconv.FormatInt(int64(p.MatchCount), 10)
	return []string{
		pattern, // Hostname
		portStr, // Port
		numMatches,
	}
}

func (m *PermissionModel) HandlePermissionsUpdate(permissions []portforward.Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Permission, len(permissions))
	for i, p := range permissions {
		items[i] = Permission{
			Permission: p,
		}
	}
	m.Reset(items)
}

func (m *PermissionModel) HandleClusterEndpointsUpdate(added map[string]portforward.RoutePortForwardInfo, _ map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	matchCount := map[uint64]int{}
	for _, info := range added {
		matchCount[Permission{Permission: info.Permission}.Key()]++
	}

	for idx := range m.End() {
		value := m.Data(idx)
		if updated := matchCount[value.Key()]; value.MatchCount != updated {
			value.MatchCount = updated
			m.Put(value)
		}
	}
}
