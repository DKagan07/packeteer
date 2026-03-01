package output

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"packeteer/internal/packet"
	"packeteer/internal/storage"
)

// PrintPacketInfo takes a *PacketInfo and nicely prints it to stdout
func PrintPacketInfo(pi *packet.PacketInfo, packetNum int) {
	fmt.Printf("PACKET: %d | ", packetNum)
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

// PrintMostQueriedDomains pretty-prints the Most Queried Domains
func PrintMostQueriedDomains(mqd []storage.DNSMostQueriedDomain) {
	fmt.Println(strings.Repeat("*", 40))
	fmt.Println("\tMost Queried Domains")
	fmt.Println(strings.Repeat("*", 40))

	w := tabwriter.NewWriter(os.Stdout, 3, 4, 1, ' ', 0)
	for _, d := range mqd {
		fmt.Fprintf(
			w,
			"Count: %v\t|\tDomain: %v\t|\t(DNS txn Ids: %v)\n",
			d.Count,
			d.QueryName,
			d.Events,
		)
	}
	w.Flush()

	fmt.Println(strings.Repeat("*", 40))
}

func PrintQueriesOverTime(ots []storage.DNSOverTime) {
	fmt.Println(strings.Repeat("*", 40))
	fmt.Println("\tQueries Over Time (in mins)")
	fmt.Println(strings.Repeat("*", 40))

	w := tabwriter.NewWriter(os.Stdout, 3, 4, 1, ' ', 0)
	for _, t := range ots {
		fmt.Fprintf(w, "Time: %v\t|\tNum of Queries: %v\n", t.Timestamp, t.Count)
	}
	w.Flush()

	fmt.Println(strings.Repeat("*", 40))
}

func PrintUniqueDomains(dqs []storage.DNSDistinctQuery) {
	fmt.Println(strings.Repeat("*", 40))
	fmt.Println("\tDistinct Queries per Source IP")
	fmt.Println(strings.Repeat("*", 40))

	w := tabwriter.NewWriter(os.Stdout, 3, 4, 1, ' ', 0)
	for _, d := range dqs {
		fmt.Fprintf(
			w,
			"Source IP: %v\t|\tQuery: %v\t|\tRequest Type: %v\n",
			d.SourceIP,
			d.QueryName,
			d.RequestType,
		)
	}
	w.Flush()

	fmt.Println(strings.Repeat("*", 40))
}
