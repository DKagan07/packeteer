package rule

import (
	"database/sql"
	"fmt"
	"time"

	"packeteer/internal/conntrack"
	"packeteer/internal/packet"
)

// NOTE: Store alerts in the database with timestamp, rule name, severity, and
// relevant details.

const PacketDataMaxBytes = 1024

type RuleDetection struct {
	rulesChan   chan *packet.PacketInfo
	tracker     *conntrack.Tracker                // built here, for all connections
	portHistory map[string]map[string]time.Time   // srcIP -> set of dstPorts (port scan)
	beaconTimes map[conntrack.ConnKey][]time.Time // connection -> timestamps (beaconing)
	db          *sql.DB
}

func NewRuleDetection(pc chan *packet.PacketInfo, db *sql.DB) *RuleDetection {
	tr := conntrack.NewTracker()
	ph := make(map[string]map[string]time.Time)
	bt := make(map[conntrack.ConnKey][]time.Time)

	return &RuleDetection{
		rulesChan:   pc,
		tracker:     &tr,
		portHistory: ph,
		beaconTimes: bt,
		db:          db,
	}
}

// Read is the main loop that will read from the channel
func (r *RuleDetection) Read() {
	for pi := range r.rulesChan {
		r.BuildStorage(pi)

		r.RulePortScanning()
		r.RuleDnsTunnling()
		r.RuleBeaconing()
		r.RuleLargeOutboundData()
	}
}

// Port scan detection — track how many distinct destination ports each source
// IP touches in a time window. If it exceeds a threshold, alert.
func (r *RuleDetection) RulePortScanning() {}

// DNS tunneling suspicion — flag DNS queries where the subdomain portion is
// unusually long (entropy analysis is a bonus here) or where query volume to a
// single domain is abnormally high.
func (r *RuleDetection) RuleDnsTunnling() {}

// Beaconing detection — look for connections that recur at regular intervals.
// Calculate time deltas between connections to the same destination and flag
// if they're suspiciously consistent.
func (r *RuleDetection) RuleBeaconing() {}

// Large outbound transfer — alert when a connection sends significantly more
// data outbound than it receives, especially to an unusual destination.
func (r *RuleDetection) RuleLargeOutboundData() {
}

func (r *RuleDetection) BuildStorage(pi *packet.PacketInfo) {
	// build tracker
	key := conntrack.ConnKey(
		fmt.Sprintf(
			conntrack.ConnKeyStringFormat,
			pi.SrcIP,
			pi.SrcPort,
			pi.DestIP,
			pi.DestPort,
			pi.Protocol,
		),
	)

	if v, ok := r.tracker.Connections[key]; ok {
		v.TotalBytes += int64(pi.CaptureLength)
		v.TimeLastSeen = pi.Timestamp
	} else {
		r.tracker.Connections[key] = &conntrack.Connection{
			Key:           key,
			SrcIP:         pi.SrcIP,
			SrcPort:       pi.SrcPort,
			DstIP:         pi.DestIP,
			DstPort:       pi.DestPort,
			TimeStart:     pi.Timestamp,
			TimeLastSeen:  pi.Timestamp,
			BytesReceived: int64(pi.CaptureLength),
			TotalBytes:    int64(pi.CaptureLength),
			Protocol:      pi.Protocol,
		}
	}

	// build beacon times
	if v, ok := r.beaconTimes[key]; ok {
		v = append(v, pi.Timestamp)
		r.beaconTimes[key] = v
	} else {
		r.beaconTimes[key] = []time.Time{pi.Timestamp}
	}

	// build port history
	portHxKey := fmt.Sprintf("%s->%s", pi.SrcIP, pi.DestIP)
	if v, ok := r.portHistory[portHxKey]; ok {
		v[pi.DestPort] = pi.Timestamp
	} else {
		r.portHistory[portHxKey] = map[string]time.Time{
			pi.DestPort: pi.Timestamp,
		}
	}
}
