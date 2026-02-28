package dns

import (
	"database/sql"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"packeteer/internal/storage"
)

// DNSInfo contains structured info from a DNS packet
type DNSInfo struct {
	Time        string
	SrcIP       string
	QueryName   string
	QueryType   string
	CNAMEPath   string
	ResponseIPs []string
	RequestType RequestType
	TxnId       uint16
}

type RequestType string

var (
	Query    RequestType = "query"
	Response RequestType = "response"
)

// DecodeDNSPacket decodes the DNS layer of the packet. It builds a *DNSInfo
// and fills it out based on Questions and Answers.
func DecodeDNSPacket(l gopacket.Layer, srcIP, timestamp string) *DNSInfo {
	dnsLayer := l.(*layers.DNS)

	dnsInfo := &DNSInfo{
		Time:  timestamp,
		SrcIP: srcIP,
		TxnId: dnsLayer.ID,
	}

	HandleDNSQuestions(dnsLayer, dnsInfo)
	if dnsLayer.ANCount > 0 {
		HandleDNSAnswer(dnsLayer, dnsInfo)
	}

	if dnsLayer.QR {
		dnsInfo.RequestType = Response
	} else {
		dnsInfo.RequestType = Query
	}

	return dnsInfo
}

// HandleDNSQuestions handles extracting the information out of the Questions
// field in the DNS layer.
func HandleDNSQuestions(dl *layers.DNS, info *DNSInfo) {
	questions := dl.Questions
	for _, q := range questions {
		info.QueryName = string(q.Name)
		info.QueryType = q.Type.String()
	}
}

// HandleDNSAnswer handles extracting the information out of the Answers field
// and into the DNSInfo. It builds a list of the CNAME paths as part of the
// answers.
func HandleDNSAnswer(dl *layers.DNS, info *DNSInfo) {
	answers := dl.Answers
	var cnamePath strings.Builder
	for _, a := range answers {
		if len(a.CNAME) > 0 {
			cnamePath.WriteString(string(a.CNAME) + ",")
		}

		if a.IP.String() != "<nil>" {
			info.ResponseIPs = append(info.ResponseIPs, a.IP.String())
		}
	}
	info.CNAMEPath = cnamePath.String()
}

// InsertDNSInfo inserts the DNSInfo into the database
func InsertDNSInfo(dnsInfo *DNSInfo, sqldb *sql.DB) error {
	responseIPs := strings.Join(dnsInfo.ResponseIPs, ",")

	return storage.InsertDNSEntry(
		sqldb,
		dnsInfo.Time,
		dnsInfo.SrcIP,
		dnsInfo.QueryName,
		dnsInfo.QueryType,
		dnsInfo.CNAMEPath,
		responseIPs,
		string(dnsInfo.RequestType),
		dnsInfo.TxnId,
	)
}
