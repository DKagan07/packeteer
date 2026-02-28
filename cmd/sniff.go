package cmd

import (
	"log"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"

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

	sniffCmd.Flags().BoolP("find-interfaces", "i", false, "")
	sniffCmd.Flags().StringVarP(&device, "device", "d", "", "set device to listen to (ex. wlan0)")
	sniffCmd.Flags().StringVarP(&bpf, "bpf", "b", "", "set bpf filters")
}

// Sniff looks at the packet and, currently, prints out the packet info. It will
// also store any DNS packets within the sqlite3 database
func Sniff(cmd *cobra.Command) {
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
	n := 0
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
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
