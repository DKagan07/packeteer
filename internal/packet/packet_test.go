package packet

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

// ******************************
// ExtractPacketInfo
// ******************************

func TestExtractPacketInfo_Metadata(t *testing.T) {
	assert := assert.New(t)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeLLC,
		},
	)

	now := time.Now()
	l := len(buf.Bytes())

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	testPacket.Metadata().CaptureLength = l
	testPacket.Metadata().Length = l
	testPacket.Metadata().Timestamp = now

	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("ETH", pi.Protocol)
	assert.Equal(l, pi.Length)
	assert.Equal(l, pi.CaptureLength)
	assert.Equal(now.Format(time.RFC3339), pi.Timestamp)
}

func TestExtractPacketInfo_Ethernet(t *testing.T) {
	assert := assert.New(t)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeLLC,
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("ETH", pi.Protocol)
}

func TestExtractPacketInfo_IPv4(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version: 4,
			IHL:     5,
			SrcIP:   net.IP{192, 168, 0, 1},
			DstIP:   net.IP{192, 168, 0, 2},
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("IPv4", pi.Protocol)
	assert.Equal("192.168.0.1", pi.SrcIP)
	assert.Equal("192.168.0.2", pi.DestIP)
}

func TestExtractPacket_IPv6(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			SrcIP: net.ParseIP("::ffff:c0a8:1"),
			DstIP: net.ParseIP("::ffff:c0a8:2"),
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("IPv6", pi.Protocol)
	assert.Equal("192.168.0.1", pi.SrcIP)
	assert.Equal("192.168.0.2", pi.DestIP)
}

func TestExtractPacketInfo_TCP_IPv6(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{
			FixLengths: true,
		},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			SrcIP:      net.ParseIP("::ffff:c0a8:1"),
			DstIP:      net.ParseIP("::ffff:c0a8:2"),
			NextHeader: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(54321),
			DstPort: layers.TCPPort(11117),
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("TCP", pi.Protocol)
	assert.Equal("192.168.0.1", pi.SrcIP)
	assert.Equal("192.168.0.2", pi.DestIP)
	assert.Equal("54321", pi.SrcPort)
	assert.Equal("11117", pi.DestPort)
}

func TestExtractPacketInfo_TCP_IPv4(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    net.IP{192, 168, 0, 1},
			DstIP:    net.IP{192, 168, 0, 2},
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(54321),
			DstPort: layers.TCPPort(11117),
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("TCP", pi.Protocol)
	assert.Equal("192.168.0.1", pi.SrcIP)
	assert.Equal("192.168.0.2", pi.DestIP)
	assert.Equal("54321", pi.SrcPort)
	assert.Equal("11117", pi.DestPort)
}

func TestExtractPacketInfo_UDP(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    net.IP{192, 168, 0, 1},
			DstIP:    net.IP{192, 168, 0, 2},
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(54321),
			DstPort: layers.UDPPort(11117),
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("UDP", pi.Protocol)
	assert.Equal("192.168.0.1", pi.SrcIP)
	assert.Equal("192.168.0.2", pi.DestIP)
	assert.Equal("54321", pi.SrcPort)
	assert.Equal("11117", pi.DestPort)
}

func TestExtractPacketInfo_ICMPv4(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    net.IP{192, 168, 0, 1},
			DstIP:    net.IP{192, 168, 0, 2},
			Protocol: layers.IPProtocolICMPv4,
		},
		&layers.ICMPv4{
			Id: 1,
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("ICMPv4", pi.Protocol)
}

func TestExtractPacketInfo_ICMPv6(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    net.IP{192, 168, 0, 1},
			DstIP:    net.IP{192, 168, 0, 2},
			Protocol: layers.IPProtocolICMPv6,
		},
		&layers.ICMPv6{},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("ICMPv6", pi.Protocol)
}

func TestExtractPacketInfo_ARP(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType: layers.LinkTypeEthernet,
		},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("ARP", pi.Protocol)
}

func TestExtractPacketInfo_TLS(t *testing.T) {
	assert := assert.New(t)

	// TLS ChangeCipherSpec record: type 0x14, version TLS 1.2, length 1, payload 0x01
	tlsRecord := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	testPacket := gopacket.NewPacket(tlsRecord, layers.LayerTypeTLS, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.NotEmpty(pi)
	assert.Equal("TLS", pi.Protocol)
}

func TestExtractPacketInfo_Empty(t *testing.T) {
	assert := assert.New(t)

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{},
	)

	testPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pi := ExtractPacketInfo(testPacket)
	assert.Empty(pi.DestPort)
	assert.Empty(pi.SrcPort)
	assert.Empty(pi.DestIP)
	assert.Empty(pi.SrcIP)
	assert.Empty(pi.Protocol)
}

// ******************************
// filterNetworkInterfaces
// ******************************

func TestFilterNetworkInterfaces(t *testing.T) {
	assert := assert.New(t)
	ifaces := []pcap.Interface{
		{
			Name: "wlan0",
			Addresses: []pcap.InterfaceAddress{
				{
					IP: net.IP{192, 168, 0, 1},
				},
			},
		},
		{
			Name: "nothing",
		},
	}

	res := filterNetworkInterfaces(ifaces)
	assert.Len(res, 1)
	assert.Equal("wlan0", res[0])
	assert.NotContains(res, "nothing")
}

// ******************************
// isPacketInfoNil
// ******************************

func TestIsPacketInfoNil_False_Timestamp(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		Timestamp: "2026-01-01T00:00:00Z",
	}))
}

func TestIsPacketInfoNil_False_Length(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		Length: 1,
	}))
}

func TestIsPacketInfoNil_False_CaptureLength(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		CaptureLength: 1,
	}))
}

func TestIsPacketInfoNil_False_SrcIP(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		SrcIP: "192.168.0.1",
	}))
}

func TestIsPacketInfoNil_False_SrcPort(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		SrcPort: "54321",
	}))
}

func TestIsPacketInfoNil_False_DestIP(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		DestIP: "192.168.0.2",
	}))
}

func TestIsPacketInfoNil_False_DestPort(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		DestPort: "11117",
	}))
}

func TestIsPacketInfoNil_False_Protocol(t *testing.T) {
	assert.False(t, isPacketInfoNil(&PacketInfo{
		Protocol: "TCP",
	}))
}

func TestIsPacketInfoNil_True(t *testing.T) {
	assert.True(t, isPacketInfoNil(&PacketInfo{}))
}
