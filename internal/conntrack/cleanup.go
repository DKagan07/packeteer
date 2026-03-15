package conntrack

import (
	"context"
	"time"
)

const StaleTime = time.Second * 30

// the purpose of this is to have a background go-routine that, whenever
// connections is running, we clean up connections that are over X time-unit old

func CleanupRoutine(ctx context.Context, conns *Tracker) {
	t := time.NewTicker(time.Second * 2)

	go func(timeChan <-chan time.Time, conns *Tracker) {
		defer t.Stop()
		Cleanup(ctx, timeChan, conns)
	}(t.C, conns)
}

func Cleanup(ctx context.Context, timeChan <-chan time.Time, conns *Tracker) {
	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-timeChan:
			conns.mu.Lock()
			tickTime := tick.UTC()
			for k, v := range conns.connections {
				tls := v.TimeLastSeen.UTC()
				if tls.Before(tickTime.Add(-StaleTime)) {
					delete(conns.connections, k)
				}
			}
			conns.mu.Unlock()
		}
	}
}
