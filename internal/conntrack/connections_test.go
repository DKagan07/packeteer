package conntrack

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"packeteer/internal/packet"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker()
	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 0)
}

func TestUpdateTracker_UDP(t *testing.T) {
	tracker := NewTracker()
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	p1 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("UDP"),
		CaptureLength: 60,
		Timestamp:     t0,
	}

	tracker.UpdateTracker(p1)
	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		p1.SrcIP, p1.SrcPort,
		p1.DestIP, p1.DestPort,
		p1.Protocol,
	)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, packet.PacketProtocol("UDP"), v.Protocol)
	assert.Equal(t, StateUnknown, v.State)
	assert.Equal(t, "192.168.0.1", v.SrcIP)
	assert.Equal(t, "8080", v.SrcPort)
	assert.Equal(t, "10.10.10.10", v.DstIP)
	assert.Equal(t, "443", v.DstPort)
	assert.Equal(t, int64(60), v.BytesReceived)
	assert.Equal(t, int64(60), v.TotalBytes)
	assert.Equal(t, t0, v.TimeStart)
	assert.Equal(t, t0, v.TimeLastSeen)
}

func TestUpdateTracker_UDP_AccumulatesTotalBytes(t *testing.T) {
	tracker := NewTracker()
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Second)

	p1 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("UDP"),
		CaptureLength: 60,
		Timestamp:     t0,
	}
	p2 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("UDP"),
		CaptureLength: 100,
		Timestamp:     t1,
	}

	tracker.UpdateTracker(p1)
	tracker.UpdateTracker(p2)

	assert.Len(t, tracker.connections, 1)

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		p1.SrcIP, p1.SrcPort,
		p1.DestIP, p1.DestPort,
		p1.Protocol,
	)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, int64(160), v.TotalBytes) // 60 (initial) + 60 (BytesReceived)
	assert.Equal(t, t0, v.TimeStart)          // unchanged
	assert.Equal(t, t1, v.TimeLastSeen)
}

func TestUpdateTracker_UDP_DistinctConnectionsNotMerged(t *testing.T) {
	tracker := NewTracker()
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	p1 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("UDP"),
		CaptureLength: 60,
		Timestamp:     t0,
	}
	p2 := &packet.PacketInfo{
		SrcIP:         "192.168.0.2",
		SrcPort:       "9090",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("UDP"),
		CaptureLength: 80,
		Timestamp:     t0,
	}

	tracker.UpdateTracker(p1)
	tracker.UpdateTracker(p2)

	assert.Len(t, tracker.connections, 2)
}

func TestUpdateTracker_TCPHandshake(t *testing.T) {
	tracker := NewTracker()
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Millisecond)
	t2 := t0.Add(2 * time.Millisecond)

	p1 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("TCP"),
		CaptureLength: 60,
		Timestamp:     t0,
		TCPFlags: packet.TCPFlags{
			SYN: true,
			ACK: false,
		},
	}

	tracker.UpdateTracker(p1)
	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		p1.SrcIP, p1.SrcPort,
		p1.DestIP, p1.DestPort,
		p1.Protocol,
	)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateSynSent)
	assert.Equal(t, int64(60), v.BytesReceived)
	assert.Equal(t, t0, v.TimeStart)
	assert.Equal(t, t0, v.TimeLastSeen)

	p2 := &packet.PacketInfo{
		SrcIP:         "10.10.10.10",
		SrcPort:       "443",
		DestIP:        "192.168.0.1",
		DestPort:      "8080",
		Protocol:      packet.PacketProtocol("TCP"),
		CaptureLength: 44,
		Timestamp:     t1,
		TCPFlags: packet.TCPFlags{
			SYN: true,
			ACK: true,
		},
	}

	tracker.UpdateTracker(p2)
	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateSynReceived)
	assert.Equal(t, int64(44), v.BytesSent)
	assert.Equal(t, int64(60), v.BytesReceived) // unchanged
	assert.Equal(t, t0, v.TimeStart)            // unchanged
	assert.Equal(t, t1, v.TimeLastSeen)

	p3 := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("TCP"),
		CaptureLength: 52,
		Timestamp:     t2,
		TCPFlags: packet.TCPFlags{
			SYN: false,
			ACK: true,
		},
	}

	tracker.UpdateTracker(p3)
	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateEstablished)
	assert.Equal(t, int64(52), v.BytesReceived)
	assert.Equal(t, int64(44), v.BytesSent) // unchanged
	assert.Equal(t, t0, v.TimeStart)        // unchanged
	assert.Equal(t, t2, v.TimeLastSeen)
}

func TestTrackerUpdate_Teardown_FIN_ClientInitiated(t *testing.T) {
	tracker := NewTracker()
	key := fmt.Sprintf(
		ConnKeyStringFormat,
		"192.168.0.1", "8080",
		"10.10.10.10", "443",
		packet.PacketProtocol("TCP"),
	)

	tracker.connections[ConnKey(key)] = &Connection{
		Key:      ConnKey(key),
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DstIP:    "10.10.10.10",
		DstPort:  "443",
		Protocol: packet.PacketProtocol("TCP"),
		State:    StateEstablished,
	}

	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	p1 := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			FIN: true,
		},
	}
	tracker.UpdateTracker(p1)
	assert.Len(t, tracker.connections, 1)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateFinInitiated)

	p2 := &packet.PacketInfo{
		SrcIP:    "10.10.10.10",
		SrcPort:  "443",
		DestIP:   "192.168.0.1",
		DestPort: "8080",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			ACK: true,
		},
	}
	tracker.UpdateTracker(p2)
	assert.Len(t, tracker.connections, 1)

	v, ok = tracker.connections[ConnKey(key)]

	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateFinWait)

	p3 := &packet.PacketInfo{
		SrcIP:    "10.10.10.10",
		SrcPort:  "443",
		DestIP:   "192.168.0.1",
		DestPort: "8080",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			FIN: true,
		},
	}
	tracker.UpdateTracker(p3)
	assert.Len(t, tracker.connections, 1)

	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateFinWait)

	p4 := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{
			ACK: true,
		},
	}
	tracker.UpdateTracker(p4)
	assert.Len(t, tracker.connections, 1)

	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateClosed)
}

func TestTrackerUpdate_Teardown_FIN_ServerInitiated(t *testing.T) {
	tracker := NewTracker()
	key := fmt.Sprintf(
		ConnKeyStringFormat,
		"192.168.0.1", "8080",
		"10.10.10.10", "443",
		packet.PacketProtocol("TCP"),
	)

	tracker.connections[ConnKey(key)] = &Connection{
		Key:      ConnKey(key),
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DstIP:    "10.10.10.10",
		DstPort:  "443",
		Protocol: packet.PacketProtocol("TCP"),
		State:    StateEstablished,
	}

	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	// Step 1: Server initiates teardown with FIN
	p1 := &packet.PacketInfo{
		SrcIP:    "10.10.10.10",
		SrcPort:  "443",
		DestIP:   "192.168.0.1",
		DestPort: "8080",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{FIN: true},
	}
	tracker.UpdateTracker(p1)
	assert.Len(t, tracker.connections, 1)
	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateFinInitiated)

	// Step 2: Client ACKs the server's FIN
	p2 := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{ACK: true},
	}
	tracker.UpdateTracker(p2)
	assert.Len(t, tracker.connections, 1)
	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateFinWait)

	// Step 3: Client sends its own FIN
	p3 := &packet.PacketInfo{
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DestIP:   "10.10.10.10",
		DestPort: "443",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{FIN: true},
	}
	tracker.UpdateTracker(p3)
	assert.Len(t, tracker.connections, 1)
	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateClosed)

	// Step 4: Server ACKs the client's FIN — connection already closed, no state change
	p4 := &packet.PacketInfo{
		SrcIP:    "10.10.10.10",
		SrcPort:  "443",
		DestIP:   "192.168.0.1",
		DestPort: "8080",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{ACK: true},
	}
	tracker.UpdateTracker(p4)
	assert.Len(t, tracker.connections, 1)
	v, ok = tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateClosed)
}

func TestTrackerUpdate_Teartown_RST(t *testing.T) {
	tracker := NewTracker()
	key := fmt.Sprintf(
		ConnKeyStringFormat,
		"192.168.0.1", "8080",
		"10.10.10.10", "443",
		packet.PacketProtocol("TCP"),
	)

	tracker.connections[ConnKey(key)] = &Connection{
		Key:      ConnKey(key),
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DstIP:    "10.10.10.10",
		DstPort:  "443",
		Protocol: packet.PacketProtocol("TCP"),
		State:    StateEstablished,
	}

	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 1)

	rstTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	p1 := &packet.PacketInfo{
		SrcIP:     "192.168.0.1",
		SrcPort:   "8080",
		DestIP:    "10.10.10.10",
		DestPort:  "443",
		Protocol:  packet.PacketProtocol("TCP"),
		Timestamp: rstTime,
		TCPFlags: packet.TCPFlags{
			RST: true,
		},
	}
	tracker.UpdateTracker(p1)
	assert.Len(t, tracker.connections, 1)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, v.Protocol, packet.PacketProtocol("TCP"))
	assert.Equal(t, v.State, StateClosed)
	assert.Equal(t, rstTime, v.TimeLastSeen)
}

func TestUpdateTracker_DataTransferACK(t *testing.T) {
	tracker := NewTracker()
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Second)

	key := fmt.Sprintf(
		ConnKeyStringFormat,
		"192.168.0.1", "8080",
		"10.10.10.10", "443",
		packet.PacketProtocol("TCP"),
	)
	tracker.connections[ConnKey(key)] = &Connection{
		Key:           ConnKey(key),
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DstIP:         "10.10.10.10",
		DstPort:       "443",
		Protocol:      packet.PacketProtocol("TCP"),
		State:         StateEstablished,
		BytesReceived: 60,
		TimeStart:     t0,
		TimeLastSeen:  t0,
	}

	p := &packet.PacketInfo{
		SrcIP:         "192.168.0.1",
		SrcPort:       "8080",
		DestIP:        "10.10.10.10",
		DestPort:      "443",
		Protocol:      packet.PacketProtocol("TCP"),
		CaptureLength: 512,
		Timestamp:     t1,
		TCPFlags:      packet.TCPFlags{ACK: true},
	}
	tracker.UpdateTracker(p)

	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, StateEstablished, v.State)
	assert.Equal(t, int64(512), v.BytesReceived)
	assert.Equal(t, t1, v.TimeLastSeen)
	assert.Equal(t, t0, v.TimeStart) // unchanged
}

// TestTrackerUpdate_RST_ServerInitiated documents a bug: the RST handler only
// looks up con[key] (the packet's own direction), so a server-sent RST never
// finds the connection stored under the client→server key.
func TestTrackerUpdate_RST_ServerInitiated(t *testing.T) {
	tracker := NewTracker()
	key := fmt.Sprintf(
		ConnKeyStringFormat,
		"192.168.0.1", "8080",
		"10.10.10.10", "443",
		packet.PacketProtocol("TCP"),
	)
	rstTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tracker.connections[ConnKey(key)] = &Connection{
		Key:      ConnKey(key),
		SrcIP:    "192.168.0.1",
		SrcPort:  "8080",
		DstIP:    "10.10.10.10",
		DstPort:  "443",
		Protocol: packet.PacketProtocol("TCP"),
		State:    StateEstablished,
	}

	p := &packet.PacketInfo{
		SrcIP:     "10.10.10.10",
		SrcPort:   "443",
		DestIP:    "192.168.0.1",
		DestPort:  "8080",
		Protocol:  packet.PacketProtocol("TCP"),
		Timestamp: rstTime,
		TCPFlags:  packet.TCPFlags{RST: true},
	}
	tracker.UpdateTracker(p)

	assert.Len(t, tracker.connections, 1)
	v, ok := tracker.connections[ConnKey(key)]
	assert.True(t, ok)
	assert.Equal(t, StateClosed, v.State)
	assert.Equal(t, rstTime, v.TimeLastSeen)
}

func TestUpdateTracker_SYNACK_NoPriorConnection(t *testing.T) {
	tracker := NewTracker()

	p := &packet.PacketInfo{
		SrcIP:    "10.10.10.10",
		SrcPort:  "443",
		DestIP:   "192.168.0.1",
		DestPort: "8080",
		Protocol: packet.PacketProtocol("TCP"),
		TCPFlags: packet.TCPFlags{SYN: true, ACK: true},
	}
	tracker.UpdateTracker(p)

	assert.Len(t, tracker.connections, 0)
}

func TestTrackerUpdate_EmptyPacketInfo(t *testing.T) {
	tracker := NewTracker()
	p := &packet.PacketInfo{}

	tracker.UpdateTracker(p)

	assert.NotNil(t, tracker.connections)
	assert.Len(t, tracker.connections, 0)
}
