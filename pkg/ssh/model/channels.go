package model

import (
	"strconv"
	"time"

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

func (c Channel) Key() uint32 {
	return c.ID
}

type ChannelUpdateListener interface {
	OnDiagnosticsReceived(diagnostics []*extensions_ssh.Diagnostic)
}

type ChannelUpdateMsg = IndexUpdateMsg[Channel, uint32]

// ChannelModel keeps track of cluster health/status by listening for
// channel events. Used for the TUI. Not thread-safe.
type ChannelModel struct {
	ItemModel[Channel, uint32]
}

func NewChannelModel() *ChannelModel {
	return &ChannelModel{
		ItemModel: NewItemModel[Channel](),
	}
}

func (m *ChannelModel) BuildRow(c Channel) []string {
	cols := []string{
		strconv.FormatUint(uint64(c.ID), 10), // Channel
		c.Status,                             // Status
		c.Hostname,                           // Hostname
		c.Path,                               // Path
		c.PeerAddress,                        // RemoteIP
	}

	if c.Stats != nil {
		cols = append(cols,
			strconv.FormatUint(c.Stats.RxBytesTotal, 10),
			strconv.FormatUint(c.Stats.TxBytesTotal, 10),
		)
		if c.Stats.StartTime != nil && c.Stats.EndTime == nil {
			cols = append(cols, time.Since(c.Stats.StartTime.AsTime()).Round(time.Millisecond).String())
		} else if c.Stats.StartTime != nil && c.Stats.EndTime != nil {
			cols = append(cols, c.Stats.EndTime.AsTime().Sub(c.Stats.StartTime.AsTime()).Round(time.Millisecond).String())
		}
	}
	return cols
}

func (m *ChannelModel) HandleEvent(event *extensions_ssh.ChannelEvent) {
	switch event := event.Event.(type) {
	case *extensions_ssh.ChannelEvent_InternalChannelOpened:
		idx, channel := m.Find(event.InternalChannelOpened.ChannelId)
		if channel.Status == "CLOSED" {
			// reset
			channel.Stats = nil
		}
		channel.ID = event.InternalChannelOpened.ChannelId
		channel.Status = "OPEN"
		channel.Hostname = event.InternalChannelOpened.Hostname
		channel.Path = event.InternalChannelOpened.Path
		channel.PeerAddress = event.InternalChannelOpened.PeerAddress
		m.Insert(idx, channel)
	case *extensions_ssh.ChannelEvent_InternalChannelClosed:
		idx, channel := m.Find(event.InternalChannelClosed.ChannelId)
		channel.ID = event.InternalChannelClosed.ChannelId
		channel.Status = "CLOSED"
		channel.Stats = event.InternalChannelClosed.Stats
		m.Insert(idx, channel)

		if len(event.InternalChannelClosed.Diagnostics) > 0 {
			for l := range m.Listeners() {
				if l, ok := l.(ChannelUpdateListener); ok {
					l.OnDiagnosticsReceived(event.InternalChannelClosed.Diagnostics)
				}
			}
		}
	case *extensions_ssh.ChannelEvent_ChannelStats:
		for _, entry := range event.ChannelStats.GetStatsList().GetItems() {
			idx, channel := m.Find(entry.ChannelId)
			channel.ID = entry.ChannelId
			channel.Stats = entry
			m.Insert(idx, channel)
		}
	}
}
