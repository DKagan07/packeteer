package conntrack

import (
	"fmt"
	"sync"
	"time"

	"packeteer/internal/packet"
)

const ConnKeyStringFormat = "%s:%s-->%s:%s/%s"

// Src is the client, dest is server
type ConnKey string // <SrcIP>:<SrcPort>--><DstIP>:<DstPort>/<protocol>

type TCPState int

const (
	StateSynSent TCPState = iota
	StateSynReceived
	StateEstablished
	StateFinInitiated
	StateFinWait
	StateClosed
)

type Connection struct {
	Key           ConnKey
	SrcIP         string
	SrcPort       string
	DstIP         string
	DstPort       string
	Protocol      packet.PacketProtocol // TCP or UDP
	State         TCPState              // only matters for TCP
	BytesReceived int64                 // from src -> dst
	BytesSent     int64                 // from dst -> src
	TimeStart     time.Time             // when the connectino was first seen
	TimeLastSeen  time.Time             // when the most recent packet for this arrived
}

type Tracker struct {
	mu          sync.RWMutex
	connections map[ConnKey]*Connection
}

// NewTracker returns a new Tracker object
func NewTracker() Tracker {
	m := map[ConnKey]*Connection{}
	return Tracker{
		connections: m,
	}
}

func (t *Tracker) UpdateTracker(p *packet.PacketInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	con := t.connections

	key := ConnKey(
		fmt.Sprintf(ConnKeyStringFormat, p.SrcIP, p.SrcPort, p.DestIP, p.DestPort, p.Protocol),
	)
	oppositeKey := ConnKey(
		fmt.Sprintf(ConnKeyStringFormat, p.DestIP, p.DestPort, p.SrcIP, p.SrcPort, p.Protocol),
	)

	// SYN, client -> server
	if p.TCPFlags.SYN && !p.TCPFlags.ACK {
		con[key] = &Connection{
			State:         StateSynSent,
			Key:           key,
			SrcIP:         p.SrcIP,
			SrcPort:       p.SrcPort,
			DstIP:         p.DestIP,
			DstPort:       p.DestPort,
			TimeStart:     p.Timestamp,
			TimeLastSeen:  p.Timestamp,
			BytesReceived: int64(p.CaptureLength),
			Protocol:      p.Protocol,
		}
		return
	}

	var currentState TCPState
	if v, ok := con[key]; ok {
		currentState = v.State
	}
	var oppositeCurrentState TCPState
	if v, ok := con[oppositeKey]; ok {
		oppositeCurrentState = v.State
	}

	if p.TCPFlags.SYN && p.TCPFlags.ACK { // SYN-ACK
		if v, ok := con[oppositeKey]; ok {
			v.State = StateSynReceived
			v.TimeLastSeen = p.Timestamp
			v.BytesSent = int64(p.CaptureLength)
		}
	} else if p.TCPFlags.FIN { // FIN
		switch {
		case currentState == StateEstablished:
			if v, ok := con[key]; ok {
				v.State = StateFinInitiated
			}
		case oppositeCurrentState == StateEstablished:
			if v, ok := con[oppositeKey]; ok {
				v.State = StateFinInitiated
			}
		case currentState == StateFinWait:
			if v, ok := con[key]; ok {
				v.State = StateClosed
			}
		}
	} else if p.TCPFlags.ACK { // ACK -- can be for sending info or responding to FIN
		if currentState == StateFinInitiated || currentState == StateFinWait {
			if v, ok := con[key]; ok {
				v.State = StateFinWait
			}
		} else if v, ok := con[key]; ok {
			v.State = StateEstablished
			v.TimeLastSeen = p.Timestamp
			v.BytesReceived = int64(p.CaptureLength)
		}
	} else if p.TCPFlags.RST { // Hard Stop, RST
		if v, ok := con[key]; ok {
			v.State = StateClosed
			v.TimeLastSeen = p.Timestamp
		}
	}
}
