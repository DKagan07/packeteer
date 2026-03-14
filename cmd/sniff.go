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

	// Packet processing
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	if showConnections {
		packetChan := make(chan (*packet.PacketInfo))
		go func() {
			for p := range packetSrc.Packets() {
				pi, _ := packet.ExtractPacketInfo(p)
				if pi == nil {
					continue
					// log.Fatal("PacketInfo is nil")
				}

				if pi.Protocol == packet.TCP || pi.Protocol == packet.UDP {
					packetChan <- pi
				}

			}
		}()

		// Running the bubbletea application
		p := tea.NewProgram(conntrack.NewModel(packetChan))
		if _, err := p.Run(); err != nil {
			fmt.Printf("Alas, there's been an error: %v", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	// Normal packet capture
	n := 0
	for p := range packetSrc.Packets() {
		pi, dnsInfo := packet.ExtractPacketInfo(p)
		if pi == nil {
			log.Fatal("PacketInfo is nil")
		}

		if dnsInfo != nil {
			if err := dns.InsertDNSInfo(dnsInfo, db); err != nil {
				log.Fatalf("inserting into dns table: %v", err)
			}
		}

		output.PrintPacketInfo(pi, n)
		n++
	}
}
