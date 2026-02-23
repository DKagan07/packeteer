package dns

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"packeteer/internal/storage"
)

// ******************************
// HandleDNSQuestions
// ******************************

func TestHandleDNSQuestions_SingleQuestion(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name: []byte("example.com"),
				Type: layers.DNSTypeA,
			},
		},
	}

	info := &DNSInfo{}
	HandleDNSQuestions(dl, info)

	assert.Equal("example.com", info.QueryName)
	assert.Equal("A", info.QueryType)
}

func TestHandleDNSQuestions_MultipleQuestions_LastWins(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{Name: []byte("first.com"), Type: layers.DNSTypeA},
			{Name: []byte("last.com"), Type: layers.DNSTypeAAAA},
		},
	}

	info := &DNSInfo{}
	HandleDNSQuestions(dl, info)

	assert.Equal("last.com", info.QueryName)
	assert.Equal("AAAA", info.QueryType)
}

func TestHandleDNSQuestions_Empty(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{}
	info := &DNSInfo{}
	HandleDNSQuestions(dl, info)

	assert.Empty(info.QueryName)
	assert.Empty(info.QueryType)
}

// ******************************
// HandleDNSAnswer
// ******************************

func TestHandleDNSAnswer_WithIPs(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Answers: []layers.DNSResourceRecord{
			{IP: net.ParseIP("1.2.3.4")},
			{IP: net.ParseIP("5.6.7.8")},
		},
	}

	info := &DNSInfo{}
	HandleDNSAnswer(dl, info)

	assert.Contains(info.ResponseIPs, "1.2.3.4")
	assert.Contains(info.ResponseIPs, "5.6.7.8")
	assert.Empty(info.CNAMEPath)
}

func TestHandleDNSAnswer_WithCNAME(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Answers: []layers.DNSResourceRecord{
			{CNAME: []byte("cdn.example.com")},
			{IP: net.ParseIP("1.2.3.4")},
		},
	}

	info := &DNSInfo{}
	HandleDNSAnswer(dl, info)

	assert.Contains(info.CNAMEPath, "cdn.example.com")
	assert.Contains(info.ResponseIPs, "1.2.3.4")
}

func TestHandleDNSAnswer_MultipleCNAMEs(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Answers: []layers.DNSResourceRecord{
			{CNAME: []byte("a.example.com")},
			{CNAME: []byte("b.example.com")},
		},
	}

	info := &DNSInfo{}
	HandleDNSAnswer(dl, info)

	assert.Contains(info.CNAMEPath, "a.example.com")
	assert.Contains(info.CNAMEPath, "b.example.com")
	assert.Empty(info.ResponseIPs)
}

func TestHandleDNSAnswer_NilIP(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		Answers: []layers.DNSResourceRecord{
			{CNAME: []byte("cdn.example.com")},
		},
	}

	info := &DNSInfo{}
	HandleDNSAnswer(dl, info)

	assert.Empty(info.ResponseIPs)
}

func TestHandleDNSAnswer_Empty(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{}
	info := &DNSInfo{}
	HandleDNSAnswer(dl, info)

	assert.Empty(info.ResponseIPs)
	assert.Empty(info.CNAMEPath)
}

// ******************************
// DecodeDNSPacket
// ******************************

func TestDecodeDNSPacket_Query(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA},
		},
	}

	info := DecodeDNSPacket(dl, "192.168.0.1", "2024-01-01T00:00:00Z")

	assert.NotNil(info)
	assert.Equal("2024-01-01T00:00:00Z", info.Time)
	assert.Equal("192.168.0.1", info.SrcIP)
	assert.Equal("example.com", info.QueryName)
	assert.Equal("A", info.QueryType)
	assert.Empty(info.ResponseIPs)
	assert.Equal(Query, info.RequestType)
}

func TestDecodeDNSPacket_Response(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		QR:      true,
		ANCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA},
		},
		Answers: []layers.DNSResourceRecord{
			{IP: net.ParseIP("1.2.3.4")},
		},
	}

	info := DecodeDNSPacket(dl, "192.168.0.1", "2024-01-01T00:00:00Z")

	assert.NotNil(info)
	assert.Equal("example.com", info.QueryName)
	require.Len(t, info.ResponseIPs, 1)
	assert.Equal("1.2.3.4", info.ResponseIPs[0])
	assert.Equal(Response, info.RequestType)
}

func TestDecodeDNSPacket_ResponseWithCNAME(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		QR:      true,
		ANCount: 2,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA},
		},
		Answers: []layers.DNSResourceRecord{
			{CNAME: []byte("cdn.example.com")},
			{IP: net.ParseIP("1.2.3.4")},
		},
	}

	info := DecodeDNSPacket(dl, "10.0.0.1", "2024-01-01T00:00:00Z")

	assert.NotNil(info)
	assert.Contains(info.CNAMEPath, "cdn.example.com")
	assert.Contains(info.ResponseIPs, "1.2.3.4")
	assert.Equal(Response, info.RequestType)
}

func TestDecodeDNSPacket_NoAnswers(t *testing.T) {
	assert := assert.New(t)

	dl := &layers.DNS{
		QR:      false,
		ANCount: 0,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeAAAA},
		},
	}

	info := DecodeDNSPacket(dl, "10.0.0.1", "2024-01-01T00:00:00Z")

	assert.NotNil(info)
	assert.Empty(info.ResponseIPs)
	assert.Empty(info.CNAMEPath)
	assert.Equal(Query, info.RequestType)
}

// ******************************
// InsertDNSInfo
// ******************************

func TestInsertDNSInfo(t *testing.T) {
	db, err := storage.OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	info := &DNSInfo{
		Time:        "2024-01-01T00:00:00Z",
		SrcIP:       "192.168.0.1",
		QueryName:   "example.com",
		QueryType:   "A",
		CNAMEPath:   "",
		ResponseIPs: []string{"1.2.3.4"},
	}

	err = InsertDNSInfo(info, db)
	assert.NoError(t, err)
}

func TestInsertDNSInfo_MultipleIPs(t *testing.T) {
	db, err := storage.OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	info := &DNSInfo{
		Time:        "2024-01-01T00:00:00Z",
		SrcIP:       "192.168.0.1",
		QueryName:   "example.com",
		QueryType:   "A",
		CNAMEPath:   "cdn.example.com,",
		ResponseIPs: []string{"1.2.3.4", "5.6.7.8"},
	}

	err = InsertDNSInfo(info, db)
	assert.NoError(t, err)
}

func TestInsertDNSInfo_EmptyResponseIPs(t *testing.T) {
	db, err := storage.OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	info := &DNSInfo{
		Time:        "2024-01-01T00:00:00Z",
		SrcIP:       "192.168.0.1",
		QueryName:   "example.com",
		QueryType:   "A",
		ResponseIPs: []string{},
	}

	err = InsertDNSInfo(info, db)
	assert.NoError(t, err)
}
