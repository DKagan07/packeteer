package rule

import (
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"packeteer/internal/conntrack"
	"packeteer/internal/packet"
	"packeteer/internal/storage"
)

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

		if pi.DnsInfo != nil {
			r.RuleDnsTunnling(pi.DnsInfo.QueryName)
		}
		r.RulePortScanning(pi)
		r.RuleBeaconing(pi)
		r.RuleLargeOutboundData(pi)
	}
}

// RulePortScanning alerts when a source IP contacts more than MaxPortConnections
// distinct ports on a destination within MaxPortTime. Severity: low.
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

// RuleDnsTunnling flags DNS queries with unusually long subdomain labels
// (>= MaxSubdomainLength) or total query names (>= MaxTotalQueryName), which
// are indicative of data exfiltration via DNS tunneling. Severity: high.
func (r *RuleDetection) RuleDnsTunnling(queryDomain string) {
	now := time.Now()
	domainParts := strings.Split(queryDomain, ".")

	if len(queryDomain) >= MaxTotalQueryName {
		desc := fmt.Sprintf(
			"Query Domain %s is long",
			queryDomain,
		)
		storage.InsertAlert(
			r.db,
			now.UTC().Format(time.RFC3339),
			AlertDnsTunneling.String(),
			SeverityHigh.String(),
			desc,
		)
		PrintAlert(desc, SeverityHigh)
	}

	if len(domainParts) == 2 { // no subdomain
		return
	}

	for i := 0; i < len(domainParts)-2; i++ { // checking all subdomains
		subdomain := domainParts[i]

		if len(subdomain) >= MaxSubdomainLength {
			desc := fmt.Sprintf(
				"Query Subdomain %s is sketchy",
				subdomain,
			)
			storage.InsertAlert(
				r.db,
				now.UTC().Format(time.RFC3339),
				AlertDnsTunneling.String(),
				SeverityHigh.String(),
				desc,
			)
			PrintAlert(desc, SeverityHigh)
		}
	}
}

// RuleBeaconing detects connections to the same destination that recur at
// suspiciously regular intervals (within BeaconingBufferPercent jitter),
// requiring at least MinBeaconingAmount samples inside BeaconingWindow.
// Severity: high.
func (r *RuleDetection) RuleBeaconing(pi *packet.PacketInfo) {
	// current ConnKey
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

	times, ok := r.beaconTimes[key]
	if !ok {
		return
	}

	if len(times) <= MinBeaconingAmount+2 {
		return
	}

	interval := float64(0)
	beaconingTimes := []time.Time{}
	for i := 1; i < len(times); i++ {
		firstT := times[i-1]
		secondT := times[i]

		in := secondT.Sub(firstT).Seconds()

		if interval != 0 && compareTimeWithBuffer(in, interval) {
			beaconingTimes = append(beaconingTimes, firstT)

			if len(beaconingTimes) >= MinBeaconingAmount &&
				withinWindow(beaconingTimes[0], secondT) {
				desc := fmt.Sprintf(
					"IP %s connecting to %s at regular occurrences",
					pi.SrcIP,
					pi.DestIP,
				)
				storage.InsertAlert(
					r.db,
					time.Now().UTC().Format(time.RFC3339),
					AlertBeaconing.String(),
					SeverityHigh.String(),
					desc,
				)
				PrintAlert(desc, SeverityHigh)
				return
			}
		}

		if !compareTimeWithBuffer(in, interval) {
			beaconingTimes = []time.Time{}
		}

		interval = in
	}
}

// compareTimeWithBuffer returns whether or not the current interval is within
// `BeaconingBufferPercent` of the previous (established) interval
func compareTimeWithBuffer(currInterval, prevInterval float64) bool {
	upper := prevInterval + (prevInterval * BeaconingBufferPercent)
	lower := prevInterval - (prevInterval * BeaconingBufferPercent)

	return lower <= currInterval && currInterval <= upper
}

// withinWindow is a comparison function that will determine if there are at
// least `MinBeaconingAmount` of equal intervals within a specific time window
func withinWindow(firstBeaconingTime, currTimeInterval time.Time) bool {
	return firstBeaconingTime.Add(time.Minute * BeaconingWindow).After(currTimeInterval)
}

// pruneBeaconTimes removes timestamps older than BeaconingPruneWindow from the
// front of the slice. Timestamps are in chronological order, so it finds the
// first index still within the window and reslices.
func pruneBeaconTimes(times []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-time.Minute * BeaconingPruneWindow)
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}

// RuleLargeOutboundData alerts on connections with a high outbound-to-inbound
// byte ratio (>= 10:1) or total outbound bytes exceeding MaxBytesReceived,
// both of which may indicate data exfiltration. Severity: critical.
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

		PrintAlert(desc, SeverityCritical)
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

		PrintAlert(desc, SeverityCritical)
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

	// building tracker
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
		r.beaconTimes[key] = pruneBeaconTimes(v, pi.Timestamp)
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

// PrintAlert is the current way that an alert will be triggered - it will be
// printed to stderr, stylized by lipgloss
func PrintAlert(alertDesc string, severity AlertSeverity) {
	s := fmt.Sprintf("[%s] %s", strings.ToUpper(severity.String()), alertDesc)
	style := lipgloss.NewStyle().Foreground(lipgloss.Red)
	desc := style.Render(s)
	fmt.Fprintln(os.Stderr, desc)
}
