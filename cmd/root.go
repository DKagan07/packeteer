package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"
)

var (
	device string
	bpf    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "packeteer",
	Short: "packet sniffer",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		packet(cmd)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.packeteer.yaml)")

	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().BoolP("find-interfaces", "i", false, "")
	rootCmd.Flags().
		StringVarP(&device, "device", "d", "", "set device to listen to (ex. wlan0, eth0)")
	rootCmd.Flags().StringVarP(&bpf, "bpf", "b", "", "set bpf filters")
}

func packet(cmd *cobra.Command) {
	search, err := cmd.Flags().GetBool("find-interfaces")
	if err != nil {
		// TODO: change this
		panic(err)
	}

	if search || device == "" {
		selectInterface(&device)
	}

	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		if bpf != "" {
			if err := handle.SetBPFFilter(bpf); err != nil {
				panic(err)
			}
		}

		n := 0
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSrc.Packets() {
			fmt.Println("PACKET: ", n)
			printPacketInfo(packet)
			n++
		}
	}
}

func printPacketInfo(p gopacket.Packet) {
	var (
		ts       string
		l        int
		read     int
		srcIP    string
		srcPort  string
		destIP   string
		destPort string
		t        string
	)

	md := p.Metadata()
	ts = md.Timestamp.Format(time.RFC3339)
	l = md.Length
	read = md.CaptureLength

	ls := p.Layers()
	for _, l := range ls {
		switch l.LayerType() {
		case layers.LayerTypeEthernet:
			t = "ETH"
			// 	eth := l.(*layers.Ethernet)

		case layers.LayerTypeIPv4:
			ip4 := l.(*layers.IPv4)
			srcIP = ip4.SrcIP.String()
			destIP = ip4.DstIP.String()
			t = "IPv4"

		case layers.LayerTypeIPv6:
			ip6 := l.(*layers.IPv6)
			srcIP = ip6.SrcIP.String()
			destIP = ip6.DstIP.String()
			t = "IPv6"

		case layers.LayerTypeTCP:
			tcp := l.(*layers.TCP)
			srcPort = tcp.SrcPort.String()
			destPort = tcp.DstPort.String()
			t = "TCP"

		case layers.LayerTypeUDP:
			udp := l.(*layers.UDP)
			srcPort = udp.SrcPort.String()
			destPort = udp.DstPort.String()
			t = "UDP"

		case layers.LayerTypeICMPv4:
			t = "ICMPv4"
			// 	icmp4 := l.(*layers.ICMPv4)

		case layers.LayerTypeICMPv6:
			t = "ICMPv6"
			// icmp6 := l.(*layers.ICMPv6)

		case layers.LayerTypeTLS:
			t = "TLS"
			// tls := l.(*layers.TLS)

		case layers.LayerTypeARP:
			t = "ARP"
			// arp := l.(*layers.ARP)
		}
	}
	fmt.Printf(
		"%s | length %v read: %v | %s src: %s:%s, dst: %s:%s",
		ts,
		l,
		read,
		t,
		srcIP,
		srcPort,
		destIP,
		destPort,
	)
	fmt.Println()
}

func selectInterface(device *string) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	var names []string
	for _, f := range ifaces {
		if len(f.Addresses) > 0 {
			names = append(names, f.Name)
		}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a Interface").
				OptionsFunc(func() []huh.Option[string] {
					return huh.NewOptions(names...)
				}, device).
				Value(device).
				Height(10),
		),
	)
	if err := form.Run(); err != nil {
		panic(err)
	}
}
