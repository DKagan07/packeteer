package rule

import "time"

/*
  Summary Table

  ┌────────────┬────────────────────────────────────────┬────────────────────────────────┬─────────────────────────┐
  │    Rule    │               Key Metric               │           Threshold            │         Window          │
  ├────────────┼────────────────────────────────────────┼────────────────────────────────┼─────────────────────────┤
  │ Port scan  │ unique dst ports per src IP            │ 15 ports                       │ 60s                     │
  ├────────────┼────────────────────────────────────────┼────────────────────────────────┼─────────────────────────┤
  │ DNS tunnel │ subdomain label length                 │ >52 chars                      │ per query               │
  ├────────────┼────────────────────────────────────────┼────────────────────────────────┼─────────────────────────┤
  │ Beaconing  │ stddev/mean of connection deltas       │ <15%                           │ 10–15 min, ≥5 samples   │
  ├────────────┼────────────────────────────────────────┼────────────────────────────────┼─────────────────────────┤
  │ Exfil      │ outbound/inbound byte ratio + absolute │ >10:1 ratio AND >5 MB outbound │ per connection lifetime │
  └────────────┴────────────────────────────────────────┴────────────────────────────────┴─────────────────────────┘
*/

// Variables for thresholds for rules
const (
	MaxPortConnections = 10
	MaxPortTime        = time.Second * 60

	MaxSubdomainLength = 52  // characters
	MaxTotalQueryName  = 100 // characters

	MaxBytesReceived    = 50000000 // bytes, 50mb, in a single connection
	MaxRatioTransferred = 10.0     // ratio of data from src->dest

	MinBeaconingAmount     = 5    // how many times a specific interval is hit to trigger an alarm
	BeaconingWindow        = 15   // minutes
	BeaconingBufferPercent = 0.15 // 15% tolerance for interval comparison
	BeaconingPruneWindow   = 20   // minutes; prune timestamps older than this
)

// AlertName defines the name of the alert
type AlertName string

var (
	AlertPortScan          AlertName = "AlertPortScan"
	AlertDnsTunneling      AlertName = "AlertDNSTunnling"
	AlertBeaconing         AlertName = "AlertBeaconing"
	AlertLargeOutboundData AlertName = "AlertLargeOutboundData"
)

// String stringifies the name of the alert
func (an AlertName) String() string {
	switch an {
	case AlertPortScan:
		return "AlertPortScan"
	case AlertDnsTunneling:
		return "AlertDnsTunneling"
	case AlertBeaconing:
		return "AlertBeaconing"
	case AlertLargeOutboundData:
		return "AlertLargeOutboundData"
	default:
		return "UnknownAlert"
	}
}

// AlertSeverity is an enum that defines the severity of the alert
type AlertSeverity int

const (
	SeverityLow AlertSeverity = iota
	SeverityHigh
	SeverityCritical
)

// String stringifies the severity of the alert
func (as AlertSeverity) String() string {
	switch as {
	case SeverityLow:
		return "LOW"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
