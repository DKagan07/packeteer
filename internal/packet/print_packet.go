package packet

import (
	"fmt"
)

// PrintPacketInfo takes a *PacketInfo and nicely prints it to stdout
func PrintPacketInfo(pi *PacketInfo) {
	fmt.Printf(
		"%s | length %v read: %v | %s src: %s:%s, dst: %s:%s",
		pi.Timestamp,
		pi.Length,
		pi.CaptureLength,
		pi.Protocol,
		pi.SrcIP,
		pi.SrcPort,
		pi.DestIP,
		pi.DestPort,
	)
	fmt.Println()
}
