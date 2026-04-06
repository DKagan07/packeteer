package rule

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"time"

	"packeteer/internal/conntrack"
	"packeteer/internal/packet"
	"packeteer/internal/storage"
)

// NOTE: Store alerts in the database with timestamp, rule name, severity, and
// relevant details.

// RuleDetection defines the components needed to rules definition, enforcement,
// and storage of those rules
type RuleDetection struct {
	rulesChan   chan *packet.PacketInfo
	tracker     *conntrack.Tracker                // built here, for all connections
	portHistory map[string]map[string]time.Time   // srcIP -> set of dstPorts (port scan)
	beaconTimes map[conntrack.ConnKey][]time.Time // connection -> timestamps (beaconing)
	db          *sql.DB
}

// NewRuleDetection returns a new RulesDetection
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

		r.RulePortScanning(pi)
		r.RuleDnsTunnling()
		r.RuleBeaconing()
		r.RuleLargeOutboundData(pi)
	}
}

// Port scan detection — track how many distinct destination ports each source
// IP touches in a time window. If it exceeds a threshold, alert.
// Low severity
// NOTE: there's a duplication problem: every packet that comes in that matches
// will trigger the alert -- I think that's fine
func (r *RuleDetection) RulePortScanning(pi *packet.PacketInfo) {
	now := time.Now()
	thirtySecondsAgo := now.Add(-MaxPortTime)

	portHxKey := fmt.Sprintf("%s->%s", pi.SrcIP, pi.DestIP)
	dstPorts, ok := r.portHistory[portHxKey]
	if !ok {
		return
	}

	portsPerDstIP := 0
	ports := []string{}
	for port, t := range dstPorts {
		if t.After(thirtySecondsAgo) {
			portsPerDstIP++
		}
		ports = append(ports, port)
	}

	if portsPerDstIP >= MaxPortConnections {
		sortPorts(ports)
		desc := fmt.Sprintf("IP '%s' has %d ports on '%v'", pi.DestIP, portsPerDstIP, ports)
		storage.InsertAlert(
			r.db,
			now.UTC().Format(time.RFC3339),
			AlertPortScan.String(),
			SeverityLow.String(),
			desc,
		)
		// trigger alert
	}
}

func sortPorts(ports []string) {
	sort.Slice(ports, func(i, j int) bool {
		a, _ := strconv.Atoi(ports[i])
		b, _ := strconv.Atoi(ports[j])
		return a < b
	})
}

// DNS tunneling suspicion — flag DNS queries where the subdomain portion is
// unusually long (entropy analysis is a bonus here) or where query volume to a
// single domain is abnormally high.
// High severity
/*
*   DNS Tunneling — Subdomain Length

  - Threshold: subdomain labels longer than 52 characters, or total query name longer than 100 characters
  - Normal subdomains are short: www, mail, api, us-east-1. Rarely more than 20–30 characters per label.
  - DNS tunneling tools (iodine, dnscat2) encode data in the subdomain, producing names like
  dGhpcyBpcyBlbmNvZGVkIGRhdGE.evil.com. The encoded payloads easily push individual labels past 50 characters.
  - The DNS spec allows up to 63 characters per label and 253 total — tunneling tools push right up against these limits.
  - Bonus metric if you want it later: high query volume to a single domain. Normal DNS is bursty — a host resolving 50+
  unique subdomains under the same parent domain in a minute is suspicious (e.g., aaa.evil.com, bbb.evil.com,
  ccc.evil.com...).
*/
func (r *RuleDetection) RuleDnsTunnling() {}

// Beaconing detection — look for connections that recur at regular intervals.
// Calculate time deltas between connections to the same destination and flag
// if they're suspiciously consistent.
// High severity
/* More info:
Beaconing — Interval Consistency

This one isn't about a single threshold value — it's about regularity of timing.

- Approach: collect timestamps for connections to the same destination, compute the
deltas between them, then check the standard deviation (or just the spread) of those
deltas.
- Threshold: if the standard deviation of deltas is less than ~10–15% of the mean
interval, flag it.
  - Example: a host connects to 1.2.3.4 every 60s ± 3s → mean=60, stddev=3, ratio=5% →

suspicious.
  - A human browsing the same site will have wildly irregular intervals (ratio >50%).

- Minimum sample size: require at least 5–10 callbacks before evaluating — you can't
judge regularity from 2 connections.
- Time window: 10–15 minutes. Short enough to catch fast beacons (every 30s–2min), long
enough to collect enough samples.
- Common C2 beacon intervals: 30s, 60s, 5min. Some use jitter to evade this exact
detection, but basic implants don't.
*/
func (r *RuleDetection) RuleBeaconing() {}

// Large outbound transfer — alert when a connection sends significantly more
// data outbound than it receives, especially to an unusual destination.
// Critical severity
/* More info:
*  Large Outbound Data

  This is where BytesReceived (src→dst, i.e., outbound) is the right field — not TotalBytes, because you care about the
  asymmetry. A video call sends a lot of data in both directions; exfiltration sends a lot in one direction.

  - Threshold: flag when BytesReceived (outbound) exceeds 50–100 MB on a single connection, OR when the ratio of outbound to
   inbound is greater than ~10:1 on a connection with meaningful volume (say, >5 MB outbound).
  - The ratio check is the more useful signal. A connection that sent 50 MB but received only 200 KB of commands back is far
   more suspicious than one that transferred 50 MB in each direction.
  - Track this per connection (per ConnKey), not per packet. Individual packets are capped at ~1500 bytes (MTU), so
  per-packet size is not meaningful for exfiltration detection.
  - Time component: you could also check rate — 50 MB over an hour might be normal cloud sync, but 50 MB in 30 seconds to an
   IP you've never seen before is more alarming. For a learning project, starting with just the ratio + absolute threshold
  is perfectly fine.
*/
func (r *RuleDetection) RuleLargeOutboundData(pi *packet.PacketInfo) {
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

	conns := r.tracker.Connections
	v, ok := conns[key]
	if !ok {
		return
	}

	now := time.Now()

	// ratio check
	rec := v.BytesReceived
	sent := v.BytesSent

	if sent > 0 && float64(rec)/float64(sent) >= 10.0 {
		desc := fmt.Sprintf(
			"RATIO: IP %s sending large, asymmetrical data to %s, (%d)bytes",
			v.SrcIP,
			v.DstIP,
			v.BytesReceived,
		)
		storage.InsertAlert(
			r.db,
			now.UTC().Format(time.RFC3339),
			AlertLargeOutboundData.String(),
			SeverityCritical.String(),
			desc,
		)

		// trigger alert
		return
	}

	// checking total outbound data
	// NOTE: this might trigger for long sessions, as this isn't time-gated
	// TODO: Implement time-gating
	if rec > MaxBytesReceived {
		desc := fmt.Sprintf(
			"AMOUNT: IP %s sending large amounts of data to %s, (%d)bytes",
			v.SrcIP,
			v.DstIP,
			v.BytesReceived,
		)

		storage.InsertAlert(
			r.db,
			now.UTC().Format(time.RFC3339),
			AlertLargeOutboundData.String(),
			SeverityCritical.String(),
			desc,
		)

		// trigger alert
		return
	}
}

// BuildStorage builds up the maps and strucutres necessary for defining and
// enforcing the rules
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

	oppositeKey := conntrack.ConnKey(
		fmt.Sprintf(
			conntrack.ConnKeyStringFormat,
			pi.DestIP,
			pi.DestPort,
			pi.SrcIP,
			pi.SrcPort,
			pi.Protocol,
		),
	)

	if v, ok := r.tracker.Connections[key]; ok {
		v.BytesReceived += int64(pi.CaptureLength)
		v.TotalBytes += int64(pi.CaptureLength)
		v.TimeLastSeen = pi.Timestamp
	} else if v, ok := r.tracker.Connections[oppositeKey]; ok {
		v.BytesSent += int64(pi.CaptureLength)
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
