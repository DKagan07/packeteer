package cmd

import (
	"fmt"
	"log"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"

	"packeteer/internal/conntrack"
	"packeteer/internal/dns"
	"packeteer/internal/output"
	"packeteer/internal/packet"
	"packeteer/internal/rule"
)

var (
	device  string
	bpf     string
	cfgFile string

	homeDir, _ = os.UserHomeDir()
)

// sniffCmd represents the sniff command
var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "sniff listens to a network interface",
	Run: func(cmd *cobra.Command, args []string) {
		Sniff(cmd)
	},
}

func init() {
	rootCmd.AddCommand(sniffCmd)

	sniffCmd.Flags().BoolP("find-interfaces", "i", false, "show available interfaces")
	sniffCmd.Flags().StringVarP(&device, "device", "d", "", "set device to listen to (ex. wlan0)")
	sniffCmd.Flags().StringVarP(&bpf, "bpf", "b", "", "set bpf filters")

	sniffCmd.Flags().BoolP("connections", "c", false, "a life-refreshing TUI connections table")
}

// Sniff looks at the packet and, currently, prints out the packet info. It will
// also store any DNS packets within the sqlite3 database
func Sniff(cmd *cobra.Command) {
	showConnections, err := cmd.Flags().GetBool("connections")
	if err != nil {
		log.Fatal(err)
	}

	// Get interface to sniff
	search, err := cmd.Flags().GetBool("find-interfaces")
	if err != nil {
		log.Fatal(err)
	}

	if search || device == "" {
		device, err = packet.SelectInterface(pcap.FindAllDevs)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Open connection to network interface
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			log.Fatal(err)
		}
	}

	// Producer loop
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := make(chan *packet.PacketInfo)
	rulesChan := make(chan *packet.PacketInfo)
	tracker := conntrack.NewTracker()
	rd := rule.NewRuleDetection(rulesChan, db)

	go func() {
		for p := range packetSrc.Packets() {
			pi, dnsInfo := packet.ExtractPacketInfo(p)
			if pi == nil {
				continue
			}

			if dnsInfo != nil {
				if err := dns.InsertDNSInfo(dnsInfo, db); err != nil {
					log.Fatalf("inserting into dns table: %v", err)
				}
			}

			rulesChan <- pi
			packetChan <- pi

		}
	}()

	go rd.Read()

	// If the connections flag is present, we'll display it
	if showConnections {
		// Running the bubbletea application
		m := conntrack.NewModel(packetChan, &tracker)
		p := tea.NewProgram(m)
		if _, err := p.Run(); err != nil {
			fmt.Printf("Alas, there's been an error: %v", err)
			return
		}

		m.PrintStats()
		return
	}

	handlePrintPacketInfo(packetChan, &tracker)
}

// handlePrintPacketInfo is a helper function that will read from the PacketInfo
// channel and both update the tracker and print out the PacketInfo.
func handlePrintPacketInfo(
	captureChan <-chan *packet.PacketInfo, tracker *conntrack.Tracker,
) {
	n := 0
	for pi := range captureChan {
		tracker.UpdateTracker(pi)
		output.PrintPacketInfo(pi, n)
		n++
	}
}
