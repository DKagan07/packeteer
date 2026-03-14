package conntrack

import (
	"fmt"
	"image/color"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"packeteer/internal/packet"
)

const ConnKeyStringFormat = "%s:%s-->%s:%s/%s"

// Src is the client, dest is server
type ConnKey string // <SrcIP>:<SrcPort>--><DstIP>:<DstPort>/<protocol>

// TCPState is an iota-based enum that defines a state of a TCP connection
type TCPState int

const (
	StateUnknown TCPState = iota
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinInitiated
	StateFinWait
	StateClosed
)

// Connection is a struct that contains information related to a TCP or UDP
// connection
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

// String satisfies the fmt.Stringer interface and now returns the string
// implementation of TCPState
func (s TCPState) String() string {
	switch s {
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECEIVED"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinInitiated:
		return "FIN_INITIATED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Tracker is a wrapper around a map keyed relationship with a *Connection. This
// map is protected by a RWMutex, to prevent any race conditions
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

// UpdateTracker takes in a TCP or UDP packet and builds/updates a connection
// in the connection map
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
		if currentState == StateFinWait {
			if v, ok := con[key]; ok {
				v.State = StateClosed
			}
		} else if currentState == StateFinInitiated {
			if v, ok := con[key]; ok {
				v.State = StateFinWait
			}
		} else if oppositeCurrentState == StateFinInitiated || oppositeCurrentState == StateFinWait {
			if v, ok := con[oppositeKey]; ok {
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

// model is the model structure for the bubbletea TUI
type model struct {
	tracker    Tracker
	pocketChan <-chan *packet.PacketInfo
}

// packetCapture is the UI event-type of PacketInfo
type packetCapture struct {
	packetInfo *packet.PacketInfo
}

// NewModel returns a new model used for the bubbletea TUI
func NewModel(pc <-chan *packet.PacketInfo) *model {
	return &model{
		tracker:    NewTracker(),
		pocketChan: pc,
	}
}

// Init is 1/3 of fulfilling the bubbletea interface. It initialized reading
// from the channel
func (m *model) Init() tea.Cmd {
	return waitForPacket(m.pocketChan)
}

// Update is 2/3 of the bubbletea interface, which updates the tracker with a
// packet read in from the channel, or a keypress to quit the TUI
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case packetCapture:
		pi := msg.packetInfo
		m.tracker.UpdateTracker(pi)
		return m, waitForPacket(m.pocketChan)
	}
	return m, nil
}

// View is 3/3 of the bubbletea interface where the view is generated to the
// terminal
func (m *model) View() tea.View {
	var header strings.Builder
	header.WriteString("Active Connections\n")

	for k, v := range m.tracker.connections {
		con := fmt.Sprintf("%s :: %s", k, v.State)
		header.WriteString(setStyledString(con, v.State))
		header.WriteString("\n")
	}

	header.WriteString("\nPress 'q' to quit\n")
	return tea.NewView(header.String())
}

// waitForPacket wraps reading the channel into a packetCapture struct, which
// decouples this from the domain structures from the UI structures
func waitForPacket(pc <-chan *packet.PacketInfo) tea.Cmd {
	return func() tea.Msg {
		return packetCapture{
			packetInfo: <-pc,
		}
	}
}

// setStyledString styles the connection string based on the state
func setStyledString(s string, state TCPState) string {
	var c color.Color
	switch state {
	case StateSynSent:
		c = lipgloss.BrightCyan
	case StateSynReceived:
		c = lipgloss.Cyan
	case StateEstablished:
		c = lipgloss.Green
	case StateFinInitiated:
		c = lipgloss.Yellow
	case StateFinWait:
		c = lipgloss.Magenta
	case StateClosed:
		c = lipgloss.Red
	default:
		c = lipgloss.Black
	}

	style := lipgloss.NewStyle().Foreground(c)
	return style.Render(s)
}
