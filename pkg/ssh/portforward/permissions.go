package portforward

import (
	"context"
	"iter"
	"slices"
)

// PermissionSet models a set of active reverse port-forward requests from the
// client. Analog to `struct permission_set` in openssh.

type permissionSetEntry struct {
	*Permission
	Cancel context.CancelCauseFunc
}
type PermissionSet struct {
	entries []*permissionSetEntry
}

func (ps *PermissionSet) AllEntries() iter.Seq[*Permission] {
	return func(yield func(*Permission) bool) {
		for _, entry := range ps.entries {
			if !yield(entry.Permission) {
				break
			}
		}
	}
}

func (ps *PermissionSet) ResetCanceled(port uint, newCtx context.Context) {
	if port == 0 {
		panic("bug: ResetCanceled called with port 0")
	}
	for _, entry := range ps.entries {
		if entry.RequestedPort == 0 {
			continue
		}
		if entry.RequestedPort == uint32(port) && entry.Context.Err() != nil {
			entry.Context, entry.Cancel = context.WithCancelCause(newCtx)
		}
	}
}

func (ps *PermissionSet) Add(perm *Permission) {
	var cancel context.CancelCauseFunc
	perm.Context, cancel = context.WithCancelCause(perm.Context)
	ps.entries = append(ps.entries, &permissionSetEntry{
		Permission: perm,
		Cancel:     cancel,
	})
}

func (ps *PermissionSet) Remove(perm *Permission, cause error) {
	for i, entry := range ps.entries {
		if entry.Permission == perm {
			entry.Cancel(cause)
			ps.entries = slices.Delete(ps.entries, i, i+1)
			break
		}
	}
}

func (ps *PermissionSet) Find(pattern string, serverPort uint32) (*Permission, bool) {
	for _, entry := range ps.entries {
		if entry.Context.Err() != nil {
			continue
		}
		if entry.HostPattern.inputPattern == pattern && entry.ServerPort().Value == serverPort {
			return entry.Permission, true
		}
	}
	return nil, false
}

func (ps *PermissionSet) Match(requestedHostname string, requestedPort uint32) (*Permission, bool) {
	for _, entry := range ps.entries {
		if entry.Context.Err() != nil {
			continue
		}
		if entry.HostPattern.Match(requestedHostname) {
			if entry.RequestedPort == 0 || entry.RequestedPort == requestedPort {
				return entry.Permission, true
			}
		}
	}
	return nil, false
}

type ServerPort struct {
	Value     uint32
	IsDynamic bool
}

// Permission models a single reverse port-forward request from the client.
// It should be uniquely identifiable within a permission set.
type Permission struct {
	Context       context.Context
	HostPattern   Matcher
	RequestedPort uint32
	VirtualPort   uint
}

func (p *Permission) ServerPort() ServerPort {
	if p.RequestedPort != 0 {
		return ServerPort{
			Value:     p.RequestedPort,
			IsDynamic: false,
		}
	}
	return ServerPort{
		Value:     uint32(p.VirtualPort),
		IsDynamic: true,
	}
}
