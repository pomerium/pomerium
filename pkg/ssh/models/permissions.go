package models

import (
	"strconv"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type Permission portforward.Permission

func (p Permission) Key() uint64 {
	d := hashutil.NewDigest()
	d.WriteStringWithLen(p.HostMatcher.InputPattern())
	d.WriteUint32(p.RequestedPort)
	d.WriteUint32(uint32(p.VirtualPort))
	return d.Sum64()
}

type PermissionModel struct {
	ItemModel[Permission, uint64]

	permissionMatchCount map[uint64]int
}

func NewPermissionModel() *PermissionModel {
	return &PermissionModel{
		ItemModel:            NewItemModel[Permission](),
		permissionMatchCount: map[uint64]int{},
	}
}

func (m *PermissionModel) BuildRow(p Permission) []string {
	sp := ((*portforward.Permission)(&p)).ServerPort()
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
	numMatches := strconv.FormatInt(int64(m.permissionMatchCount[p.Key()]), 10)
	return []string{
		pattern, // Hostname
		portStr, // Port
		numMatches,
	}
}

func (m *PermissionModel) HandlePermissionsUpdate(permissions []portforward.Permission) {
	items := make([]Permission, len(permissions))
	for i, p := range permissions {
		items[i] = Permission(p)
	}
	m.Reset(items)
}

func (m *PermissionModel) HandleClusterEndpointsUpdate(added map[string]portforward.RoutePortForwardInfo, _ map[string]struct{}) {
	clear(m.permissionMatchCount)
	for _, info := range added {
		m.permissionMatchCount[Permission(info.Permission).Key()]++
	}
	m.InvalidateAll()
}
