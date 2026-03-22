package conntrack

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCleanup_RemoveStaleConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &model{}
	tracker := NewTracker()
	now := time.Now()
	staleKey := ConnKey("stale")
	freshKey := ConnKey("fresh")

	tracker.connections[staleKey] = &Connection{
		TimeLastSeen: now.Add(-60 * time.Second),
	}
	tracker.connections[freshKey] = &Connection{
		TimeLastSeen: now.Add(-5 * time.Second),
	}
	assert.Len(t, tracker.connections, 2)

	timeChan := make(chan time.Time, 1)
	go m.Cleanup(ctx, timeChan, &tracker)

	timeChan <- now

	time.Sleep(10 * time.Millisecond)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	assert.NotContains(t, tracker.connections, staleKey)
	assert.Contains(t, tracker.connections, freshKey)
}

func TestIsLongestLiving_SetsWhenNil(t *testing.T) {
	m := &model{}
	conn := &Connection{
		TimeStart: time.Now().Add(-10 * time.Second),
	}

	m.isLongestLiving("conn1", conn)

	assert.NotNil(t, m.longestLivedConn)
	assert.Equal(t, "conn1", m.longestLivedConn.ConnectionName)
	assert.GreaterOrEqual(t, m.longestLivedConn.ConnectionValue, 9)
}

func TestIsLongestLiving_UpdatesWhenLonger(t *testing.T) {
	m := &model{
		longestLivedConn: &connInfo{
			ConnectionName:  "short",
			ConnectionValue: 5,
		},
	}
	conn := &Connection{
		TimeStart: time.Now().Add(-20 * time.Second),
	}

	m.isLongestLiving("long", conn)

	assert.Equal(t, "long", m.longestLivedConn.ConnectionName)
	assert.GreaterOrEqual(t, m.longestLivedConn.ConnectionValue, 19)
}

func TestIsLongestLiving_NoUpdateWhenShorter(t *testing.T) {
	m := &model{
		longestLivedConn: &connInfo{
			ConnectionName:  "long",
			ConnectionValue: 20,
		},
	}
	conn := &Connection{
		TimeStart: time.Now().Add(-5 * time.Second),
	}

	m.isLongestLiving("short", conn)

	assert.Equal(t, "long", m.longestLivedConn.ConnectionName)
	assert.Equal(t, 20, m.longestLivedConn.ConnectionValue)
}

func TestIsMostData_SetsWhenNil(t *testing.T) {
	m := &model{}
	conn := &Connection{
		TotalBytes: 500,
	}

	m.isMostData("conn1", conn)

	assert.NotNil(t, m.highestDataConn)
	assert.Equal(t, "conn1", m.highestDataConn.ConnectionName)
	assert.Equal(t, 500, m.highestDataConn.ConnectionValue)
}

func TestIsMostData_UpdatesWhenMore(t *testing.T) {
	m := &model{
		highestDataConn: &connInfo{
			ConnectionName:  "low",
			ConnectionValue: 100,
		},
	}
	conn := &Connection{
		TotalBytes: 500,
	}

	m.isMostData("high", conn)

	assert.Equal(t, "high", m.highestDataConn.ConnectionName)
	assert.Equal(t, 500, m.highestDataConn.ConnectionValue)
}

func TestIsMostData_NoUpdateWhenLess(t *testing.T) {
	m := &model{
		highestDataConn: &connInfo{
			ConnectionName:  "high",
			ConnectionValue: 500,
		},
	}
	conn := &Connection{
		TotalBytes: 100,
	}

	m.isMostData("low", conn)

	assert.Equal(t, "high", m.highestDataConn.ConnectionName)
	assert.Equal(t, 500, m.highestDataConn.ConnectionValue)
}

func TestCleanup_PopulatesStatsOnTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &model{}
	tracker := NewTracker()
	now := time.Now()

	tracker.connections[ConnKey("short-lived")] = &Connection{
		TimeStart:    now.Add(-5 * time.Second),
		TimeLastSeen: now,
		TotalBytes:   100,
	}
	tracker.connections[ConnKey("long-lived")] = &Connection{
		TimeStart:    now.Add(-30 * time.Second),
		TimeLastSeen: now,
		TotalBytes:   1000,
	}

	timeChan := make(chan time.Time, 1)
	go m.Cleanup(ctx, timeChan, &tracker)

	timeChan <- now

	time.Sleep(10 * time.Millisecond)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	assert.NotNil(t, m.longestLivedConn)
	assert.Equal(t, "long-lived", m.longestLivedConn.ConnectionName)

	assert.NotNil(t, m.highestDataConn)
	assert.Equal(t, "long-lived", m.highestDataConn.ConnectionName)
	assert.Equal(t, 1000, m.highestDataConn.ConnectionValue)
}
