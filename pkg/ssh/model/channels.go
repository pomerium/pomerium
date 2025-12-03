package model

import (
	"slices"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
)

type Channel struct {
	ID          uint32
	Hostname    string
	Path        string
	Status      string
	PeerAddress string
	Stats       *extensions_ssh.ChannelStats
}

type Index int

type ChannelUpdateListener interface {
	OnChannelUpdated(index Index, data Channel)
	OnDiagnosticsReceived(diagnostics []*extensions_ssh.Diagnostic)
}

// ChannelModel keeps track of cluster health/status by listening for
// channel events. Used for the TUI. Not thread-safe.
type ChannelModel struct {
	channels    []Channel
	indexLookup map[uint32]Index
	listeners   []ChannelUpdateListener
}

func NewChannelModel() *ChannelModel {
	return &ChannelModel{
		indexLookup: map[uint32]Index{},
	}
}

func (m *ChannelModel) index(channelID uint32) Index {
	if idx, ok := m.indexLookup[channelID]; ok {
		return idx
	} else {
		nextIdx := Index(len(m.channels))
		m.channels = append(m.channels, Channel{ID: channelID})
		m.indexLookup[channelID] = nextIdx
		return nextIdx
	}
}

func (m *ChannelModel) getChannel(channelID uint32) (Index, *Channel) {
	idx := m.index(channelID)
	return idx, &m.channels[idx]
}

func (m *ChannelModel) onChannelUpdated(idx Index, info *Channel) {
	for _, l := range m.listeners {
		l.OnChannelUpdated(idx, *info)
	}
}

func (m *ChannelModel) AddListener(l ChannelUpdateListener) {
	for i, c := range m.channels {
		l.OnChannelUpdated(Index(i), c)
	}
	m.listeners = append(m.listeners, l)
}

func (m *ChannelModel) RemoveListener(l ChannelUpdateListener) {
	idx := slices.Index(m.listeners, l)
	m.listeners = slices.Delete(m.listeners, idx, idx+1)
}

func (m *ChannelModel) HandleEvent(event *extensions_ssh.ChannelEvent) {
	switch event := event.Event.(type) {
	case *extensions_ssh.ChannelEvent_InternalChannelOpened:
		idx, channel := m.getChannel(event.InternalChannelOpened.ChannelId)
		channel.Status = "OPEN"
		channel.Hostname = event.InternalChannelOpened.Hostname
		channel.Path = event.InternalChannelOpened.Path
		channel.PeerAddress = event.InternalChannelOpened.PeerAddress
		m.onChannelUpdated(idx, channel)
	case *extensions_ssh.ChannelEvent_InternalChannelClosed:
		idx, channel := m.getChannel(event.InternalChannelClosed.ChannelId)
		channel.Status = "CLOSED"
		channel.Stats = event.InternalChannelClosed.Stats
		m.onChannelUpdated(idx, channel)

		if len(event.InternalChannelClosed.Diagnostics) > 0 {
			for _, l := range m.listeners {
				l.OnDiagnosticsReceived(event.InternalChannelClosed.Diagnostics)
			}
		}
	case *extensions_ssh.ChannelEvent_ChannelStats:
		for _, entry := range event.ChannelStats.GetStatsList().GetItems() {
			idx, channel := m.getChannel(entry.ChannelId)
			channel.Stats = entry
			m.onChannelUpdated(idx, channel)
		}
	}
}
