package conntrack

import (
	"context"
	"fmt"
	"image/color"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"packeteer/internal/packet"
)

// model is the model structure for the bubbletea TUI
type model struct {
	tracker          Tracker
	packetChan       <-chan *packet.PacketInfo
	longestLivedConn *connInfo
	highestDataConn  *connInfo
	cancel           context.CancelFunc
}

type connInfo struct {
	ConnectionName  string
	ConnectionValue int
}

// packetCapture is the UI event-type of PacketInfo
type packetCapture struct {
	packetInfo *packet.PacketInfo
}

// NewModel returns a new model used for the bubbletea TUI
func NewModel(pc <-chan *packet.PacketInfo) *model {
	return &model{
		tracker:          NewTracker(),
		packetChan:       pc,
		longestLivedConn: nil,
		highestDataConn:  nil,
		cancel:           func() {},
	}
}

// Init is 1/3 of fulfilling the bubbletea interface. It initialized reading
// from the channel
func (m *model) Init() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())

	m.cancel = cancel
	m.CleanupRoutine(ctx, &m.tracker)
	return waitForPacket(m.packetChan)
}

// Update is 2/3 of the bubbletea interface, which updates the tracker with a
// packet read in from the channel, or a keypress to quit the TUI
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.cancel()
			return m, tea.Quit
		}
	case packetCapture:
		pi := msg.packetInfo
		m.tracker.UpdateTracker(pi)
		return m, waitForPacket(m.packetChan)
	}
	return m, nil
}

// View is 3/3 of the bubbletea interface where the view is generated to the
// terminal
func (m *model) View() tea.View {
	var header strings.Builder
	header.WriteString("Active Connections\n")

	m.tracker.mu.RLock()
	defer m.tracker.mu.RUnlock()
	sortedKeys := slices.Sorted(maps.Keys(m.tracker.connections))

	var tw strings.Builder
	w := tabwriter.NewWriter(&tw, 3, 4, 1, ' ', 0)
	states := make([]TCPState, 0, len(sortedKeys))
	for _, k := range sortedKeys {
		v := m.tracker.connections[k]
		if v.Protocol == packet.UDP {
			fmt.Fprintf(w, "%s\t | bytes: %d\n", k, v.TotalBytes)
			states = append(states, StateUnknown)
		} else {
			fmt.Fprintf(w, "%s\t:: %s\t | bytes: %d\n", k, v.State, v.TotalBytes)
			states = append(states, v.State)
		}
	}
	w.Flush()

	lines := strings.Split(tw.String(), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}

		var state TCPState
		if i < len(states) {
			state = states[i]
		}
		header.WriteString(setStyledString(line, state))
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
		c = lipgloss.White
	}

	style := lipgloss.NewStyle().Foreground(c)
	return style.Render(s)
}

// PrintStats prints longest-lived connections top talkers by bytes transferred.
func (m *model) PrintStats() {
	fmt.Println()

	fmt.Println(strings.Repeat("*", 40))
	fmt.Println("Longest Lived Connection")
	li := m.longestLivedConn
	if li == nil {
		fmt.Println("No longest living connections")
	} else {
		fmt.Printf("%s : %d (s)\n", li.ConnectionName, li.ConnectionValue)
	}
	fmt.Println(strings.Repeat("*", 40))

	fmt.Println()

	fmt.Println(strings.Repeat("*", 40))
	fmt.Println("Most Data-throughput Connection")
	di := m.highestDataConn
	if di == nil {
		fmt.Println("No connections with any throughput")
	} else {
		fmt.Printf("%s : %d (bytes)\n", di.ConnectionName, di.ConnectionValue)
	}
	fmt.Println(strings.Repeat("*", 40))
	fmt.Println()
}
