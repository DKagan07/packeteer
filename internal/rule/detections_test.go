package rule

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"packeteer/internal/conntrack"
	"packeteer/internal/packet"
	"packeteer/internal/storage"
)

// testSetup contains the setup of a test DB and creation of the channel for
// *packet.PacketInfo. It is up to the caller to close the DB
func testSetup(t *testing.T) (*sql.DB, chan *packet.PacketInfo) {
	db, err := storage.OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)

	packetChan := make(chan *packet.PacketInfo)

	return db, packetChan
}

func TestRulePortScanning_TriggerAlert(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	key := fmt.Sprintf("%s->%s", "10.10.10.10", "192.168.1.1")
	rd.portHistory[key] = make(map[string]time.Time)

	now := time.Now()
	port := 80
	ports := []string{}
	m := rd.portHistory[key]
	for i := range 15 { // equal or above threshold
		port += i
		ports = append(ports, fmt.Sprintf("%d", port))
		m[fmt.Sprintf("%d", port)] = now.Add(-time.Second * time.Duration(i))
	}
	sortPorts(ports)

	packet := &packet.PacketInfo{
		Timestamp:     now,
		CaptureLength: 43,
		SrcIP:         "10.10.10.10",
		SrcPort:       "443",
		DestIP:        "192.168.1.1",
		DestPort:      "80",
	}

	rd.RulePortScanning(packet)
	assert.GreaterOrEqual(t, len(m), MaxPortConnections) // alert will be fired

	var timestamp, rule_name, severity, details string
	row := db.QueryRow(
		"SELECT timestamp, rule_name, severity, details FROM alerts LIMIT 1",
	)
	err := row.Scan(
		&timestamp,
		&rule_name,
		&severity,
		&details,
	)
	require.NoError(t, err)
	assert.Equal(t, now.UTC().Format(time.RFC3339), timestamp)
	assert.Equal(t, "AlertPortScan", rule_name)
	assert.Equal(t, "LOW", severity)
	assert.Len(t, rd.portHistory[key], 15)
	assert.Equal(t, fmt.Sprintf("IP '192.168.1.1' has 15 ports on '%+v'", ports), details)
}

func TestRulePortScanning_NoTriggerAlert(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	key := fmt.Sprintf("%s->%s", "10.10.10.10", "192.168.1.1")
	rd.portHistory[key] = make(map[string]time.Time)

	now := time.Now()
	port := 80
	m := rd.portHistory[key]
	for i := range 5 { // below threshold
		port += i
		m[fmt.Sprintf("%d", port)] = now.Add(-time.Second * time.Duration(i))
	}

	packet := &packet.PacketInfo{
		Timestamp:     now,
		CaptureLength: 43,
		SrcIP:         "10.10.10.10",
		SrcPort:       "443",
		DestIP:        "192.168.1.1",
		DestPort:      "80",
	}

	rd.RulePortScanning(packet)
	assert.LessOrEqual(t, len(m), MaxPortConnections) // alert will not be fired

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRulePortScanning_NoTriggerAlert_DueToTime(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	key := fmt.Sprintf("%s->%s", "10.10.10.10", "192.168.1.1")
	rd.portHistory[key] = make(map[string]time.Time)

	now := time.Now()
	port := 80
	m := rd.portHistory[key]
	for i := range 9 { // below threshold
		port += i
		m[fmt.Sprintf("%d", port)] = now.Add(-time.Second * time.Duration(i))
	}

	m[fmt.Sprintf("%d", 420)] = now.Add(-time.Second * time.Duration(70))

	packet := &packet.PacketInfo{
		Timestamp:     now,
		CaptureLength: 43,
		SrcIP:         "10.10.10.10",
		SrcPort:       "443",
		DestIP:        "192.168.1.1",
		DestPort:      "80",
	}

	rd.RulePortScanning(packet)
	assert.LessOrEqual(t, len(m), MaxPortConnections) // alert will not be fired

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRuleLargeOutboundData_TriggerRatioAlert(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	now := time.Now()

	packet := &packet.PacketInfo{
		Timestamp: now,
		SrcIP:     "10.10.10.10",
		SrcPort:   "443",
		DestIP:    "192.168.1.1",
		DestPort:  "80",
	}

	key := conntrack.ConnKey(
		fmt.Sprintf(
			conntrack.ConnKeyStringFormat,
			"10.10.10.10",
			"443",
			"192.168.1.1",
			"80",
			"",
		),
	)
	c := rd.tracker.Connections
	c[key] = &conntrack.Connection{
		SrcIP:         "10.10.10.10",
		DstIP:         "192.168.1.1",
		BytesReceived: 50000000000,
		BytesSent:     43,
	}

	rd.RuleLargeOutboundData(packet)

	var timestamp, rule_name, severity, details string
	row := db.QueryRow(
		"SELECT timestamp, rule_name, severity, details FROM alerts LIMIT 1",
	)
	err := row.Scan(
		&timestamp,
		&rule_name,
		&severity,
		&details,
	)
	require.NoError(t, err)
	assert.Equal(t, now.UTC().Format(time.RFC3339), timestamp)
	assert.Equal(t, "AlertLargeOutboundData", rule_name)
	assert.Equal(t, "CRITICAL", severity)
	assert.Equal(
		t,
		fmt.Sprintf(
			"RATIO: IP %s sending large, asymmetrical data to %s, (%d)bytes",
			packet.SrcIP,
			packet.DestIP,
			50000000000,
		),
		details,
	)
}

func TestRuleLargeOutboundData_TriggerAmountAlert(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	now := time.Now()

	packet := &packet.PacketInfo{
		Timestamp: now,
		SrcIP:     "10.10.10.10",
		SrcPort:   "443",
		DestIP:    "192.168.1.1",
		DestPort:  "80",
	}

	key := conntrack.ConnKey(
		fmt.Sprintf(
			conntrack.ConnKeyStringFormat,
			"10.10.10.10",
			"443",
			"192.168.1.1",
			"80",
			"",
		),
	)
	c := rd.tracker.Connections
	c[key] = &conntrack.Connection{
		SrcIP:         "10.10.10.10",
		DstIP:         "192.168.1.1",
		BytesReceived: 50000000000,
		BytesSent:     50000000000,
	}

	rd.RuleLargeOutboundData(packet)

	var timestamp, rule_name, severity, details string
	row := db.QueryRow(
		"SELECT timestamp, rule_name, severity, details FROM alerts LIMIT 1",
	)
	err := row.Scan(
		&timestamp,
		&rule_name,
		&severity,
		&details,
	)
	require.NoError(t, err)
	assert.Equal(t, now.UTC().Format(time.RFC3339), timestamp)
	assert.Equal(t, "AlertLargeOutboundData", rule_name)
	assert.Equal(t, "CRITICAL", severity)
	assert.Equal(
		t,
		fmt.Sprintf(
			"AMOUNT: IP %s sending large amounts of data to %s, (%d)bytes",
			packet.SrcIP,
			packet.DestIP,
			50000000000,
		),
		details,
	)
}

func TestRuleLargeOutboundData_NoAlert(t *testing.T) {
	db, packetChan := testSetup(t)
	defer db.Close()

	rd := NewRuleDetection(packetChan, db)
	now := time.Now()

	packet := &packet.PacketInfo{
		Timestamp: now,
		SrcIP:     "10.10.10.10",
		SrcPort:   "443",
		DestIP:    "192.168.1.1",
		DestPort:  "80",
	}

	key := conntrack.ConnKey(
		fmt.Sprintf(
			conntrack.ConnKeyStringFormat,
			"10.10.10.10",
			"443",
			"192.168.1.1",
			"80",
			"",
		),
	)
	c := rd.tracker.Connections
	c[key] = &conntrack.Connection{
		SrcIP:         "10.10.10.10",
		DstIP:         "192.168.1.1",
		BytesReceived: 50,
		BytesSent:     50,
	}

	rd.RuleLargeOutboundData(packet)

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
