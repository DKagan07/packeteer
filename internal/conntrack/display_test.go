package conntrack

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"

	"packeteer/internal/packet"
)

func TestModelUpdate_PacketCapture(t *testing.T) {
	ch := make(chan *packet.PacketInfo, 1)
	m := NewModel(ch)

	pi := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			SYN: true,
		},
	}

	updated, cmd := m.Update(packetCapture{packetInfo: pi})
	assert.NotNil(t, cmd)

	um := updated.(*model)
	conn := um.tracker.connections
	assert.Len(t, conn, 1)

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		pi.SrcIP, pi.SrcPort,
		pi.DestIP, pi.DestPort,
		pi.Protocol,
	)
	assert.Equal(t, conn[ConnKey(key)].State, StateSynSent)
	assert.Equal(t, conn[ConnKey(key)].SrcIP, "192.168.0.1")
	assert.Equal(t, conn[ConnKey(key)].SrcPort, "8080")
	assert.Equal(t, conn[ConnKey(key)].DstIP, "10.10.10.10")
	assert.Equal(t, conn[ConnKey(key)].DstPort, "443")
}

func TestModelUpdate_QuitKey(t *testing.T) {
	ch := make(chan *packet.PacketInfo)
	m := NewModel(ch)
	keyQ := tea.KeyPressMsg{
		Text: "q",
	}
	_, cmd := m.Update(keyQ)
	assert.NotNil(t, cmd)
	assert.Equal(t, tea.Quit(), cmd())
}

func TestModelView_ShowsTCPConnections(t *testing.T) {
	ch := make(chan *packet.PacketInfo, 1)
	m := NewModel(ch)

	pi := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			SYN: true,
		},
	}

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		pi.SrcIP, pi.SrcPort,
		pi.DestIP, pi.DestPort,
		pi.Protocol,
	)

	updated, cmd := m.Update(packetCapture{packetInfo: pi})
	assert.NotNil(t, cmd)

	um := updated.(*model)
	conn := um.tracker.connections
	assert.Len(t, conn, 1)

	v := m.View()
	assert.NotNil(t, v)
	content := v.Content
	splitContent := strings.Split(content, "\n")
	assert.Len(t, splitContent, 5)
	assert.Equal(t, "Active Connections", splitContent[0])
	assert.True(t, strings.Contains(splitContent[1], key))
	assert.Equal(t, "", splitContent[2])
	assert.Equal(t, "Press 'q' to quit", splitContent[3])
	assert.Equal(t, "", splitContent[4])
}

func TestModelView_ShowsUDPConnections(t *testing.T) {
	ch := make(chan *packet.PacketInfo, 1)
	m := NewModel(ch)

	pi := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("UDP"),
	}

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		pi.SrcIP, pi.SrcPort,
		pi.DestIP, pi.DestPort,
		pi.Protocol,
	)

	updated, cmd := m.Update(packetCapture{packetInfo: pi})
	assert.NotNil(t, cmd)

	um := updated.(*model)
	conn := um.tracker.connections
	assert.Len(t, conn, 1)

	v := m.View()
	assert.NotNil(t, v)
	content := v.Content
	splitContent := strings.Split(content, "\n")

	assert.Len(t, splitContent, 5)
	assert.Equal(t, "Active Connections", splitContent[0])
	assert.True(t, strings.Contains(splitContent[1], key))
	assert.Equal(t, "", splitContent[2])
	assert.Equal(t, "Press 'q' to quit", splitContent[3])
	assert.Equal(t, "", splitContent[4])
}
