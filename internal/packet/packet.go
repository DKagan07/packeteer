package packet

import (
	"log"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// PacketInfo is a neat little struct that has the important gopacket.Packet
// info needed for current functionalities
type PacketInfo struct {
	Timestamp     string
	Length        int
	CaptureLength int
	SrcIP         string
	SrcPort       string
	DestIP        string
	DestPort      string
	Protocol      string
}

// ExtractPacketInfo extracts all the information into an instance of a
// PacketInfo. This function can return nil if all the fields in the PacketInfo
// are falsy
func ExtractPacketInfo(p gopacket.Packet) *PacketInfo {
	pi := &PacketInfo{}

	md := p.Metadata()
	pi.Timestamp = md.Timestamp.Format(time.RFC3339)
	pi.Length = md.Length
	pi.CaptureLength = md.CaptureLength

	ls := p.Layers()
	for _, l := range ls {
		switch l.LayerType() {
		case layers.LayerTypeEthernet:
			pi.Protocol = "ETH"
			// 	eth := l.(*layers.Ethernet)

		case layers.LayerTypeIPv4:
			ip4 := l.(*layers.IPv4)
			pi.SrcIP = ip4.SrcIP.String()
			pi.DestIP = ip4.DstIP.String()
			pi.Protocol = "IPv4"

		case layers.LayerTypeIPv6:
			ip6 := l.(*layers.IPv6)
			pi.SrcIP = ip6.SrcIP.String()
			pi.DestIP = ip6.DstIP.String()
			pi.Protocol = "IPv6"

		case layers.LayerTypeTCP:
			tcp := l.(*layers.TCP)
			pi.SrcPort = tcp.SrcPort.String()
			pi.DestPort = tcp.DstPort.String()
			pi.Protocol = "TCP"

		case layers.LayerTypeUDP:
			udp := l.(*layers.UDP)
			pi.SrcPort = udp.SrcPort.String()
			pi.DestPort = udp.DstPort.String()
			pi.Protocol = "UDP"

		case layers.LayerTypeICMPv4:
			pi.Protocol = "ICMPv4"
			// 	icmp4 := l.(*layers.ICMPv4)

		case layers.LayerTypeICMPv6:
			pi.Protocol = "ICMPv6"
			// icmp6 := l.(*layers.ICMPv6)

		case layers.LayerTypeTLS:
			pi.Protocol = "TLS"
			// tls := l.(*layers.TLS)

		case layers.LayerTypeARP:
			pi.Protocol = "ARP"
			// arp := l.(*layers.ARP)
		}
	}

	if isPacketInfoNil(pi) {
		return nil
	}

	return pi
}

// SelectInterface wraps a Charmbracelet Huh selection for the user to pick a
// network to sniff. `findDevs` is a stub for `pcap.FindAllDevs`
func SelectInterface(findDevs func() ([]pcap.Interface, error)) (string, error) {
	ifaces, err := findDevs()
	if err != nil {
		return "", err
	}

	names := filterNetworkInterfaces(ifaces)

	var selected string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a Interface").
				OptionsFunc(func() []huh.Option[string] {
					return huh.NewOptions(names...)
				}, &selected).
				Value(&selected).
				Height(10),
		),
	)
	if err := form.Run(); err != nil {
		log.Fatal(err)
	}
	return selected, nil
}

// filterNetworkInterfaces filters a slice of pcap.Interface to return a slice
// of string where the Interface has network addresses
func filterNetworkInterfaces(ifaces []pcap.Interface) []string {
	var names []string
	for _, f := range ifaces {
		if len(f.Addresses) > 0 {
			names = append(names, f.Name)
		}
	}

	return names
}

// isPacketInfoNil will return nil if all the fields within PacketInfo are falsy
func isPacketInfoNil(p *PacketInfo) bool {
	return p.Timestamp == "" &&
		p.CaptureLength == 0 &&
		p.Length == 0 &&
		p.SrcIP == "" &&
		p.SrcPort == "" &&
		p.DestIP == "" &&
		p.DestPort == "" &&
		p.Protocol == ""
}
