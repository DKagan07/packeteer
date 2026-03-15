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
	go Cleanup(ctx, timeChan, &tracker)

	timeChan <- now

	time.Sleep(10 * time.Millisecond)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	assert.NotContains(t, tracker.connections, staleKey)
	assert.Contains(t, tracker.connections, freshKey)
}
