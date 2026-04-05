package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlertSeverity_String(t *testing.T) {
	tests := []struct {
		sev      AlertSeverity
		expected string
	}{
		{
			sev:      SeverityLow,
			expected: "LOW",
		},
		{
			sev:      SeverityHigh,
			expected: "HIGH",
		},
		{
			sev:      SeverityCritical,
			expected: "CRITICAL",
		},
	}

	for _, tt := range tests {
		e := tt.sev.String()
		assert.Equal(t, tt.expected, e)
	}
}

func TestAlertName_String(t *testing.T) {
	tests := []struct {
		name     AlertName
		expected string
	}{
		{
			name:     AlertPortScan,
			expected: "AlertPortScan",
		},
		{
			name:     AlertBeaconing,
			expected: "AlertBeaconing",
		},
		{
			name:     AlertDnsTunneling,
			expected: "AlertDnsTunneling",
		},
		{
			name:     AlertLargeOutboundData,
			expected: "AlertLargeOutboundData",
		},
	}

	for _, tt := range tests {
		e := tt.name.String()
		assert.Equal(t, tt.expected, e)
	}
}
