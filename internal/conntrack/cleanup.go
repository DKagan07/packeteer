package conntrack

import (
	"context"
	"time"
)

const StaleTime = time.Second * 30

// the purpose of this is to have a background go-routine that, whenever
// connections is running, we clean up connections that are over X time-unit old

func (m *model) CleanupRoutine(ctx context.Context, conns *Tracker) {
	t := time.NewTicker(time.Second * 2)

	go func(timeChan <-chan time.Time, conns *Tracker) {
		defer t.Stop()
		m.Cleanup(ctx, timeChan, conns)
	}(t.C, conns)
}

func (m *model) Cleanup(ctx context.Context, timeChan <-chan time.Time, conns *Tracker) {
	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-timeChan:
			conns.mu.Lock()
			tickTime := tick.UTC()
			for k, v := range conns.connections {
				m.isLongestLiving(string(k), v)
				m.isMostData(string(k), v)

				tls := v.TimeLastSeen.UTC()
				if tls.Before(tickTime.Add(-StaleTime)) {
					delete(conns.connections, k)
				}
			}
			conns.mu.Unlock()
		}
	}
}

func (m *model) isLongestLiving(currConnKey string, currConn *Connection) {
	if m.longestLivedConn == nil {
		m.longestLivedConn = &connInfo{
			ConnectionName:  currConnKey,
			ConnectionValue: int(time.Since(currConn.TimeStart).Seconds()),
		}
		return
	}

	if int(time.Since(currConn.TimeStart).Seconds()) > m.longestLivedConn.ConnectionValue {
		m.longestLivedConn = &connInfo{
			ConnectionName:  currConnKey,
			ConnectionValue: int(time.Since(currConn.TimeStart).Seconds()),
		}
	}
}

func (m *model) isMostData(currConnKey string, currConn *Connection) {
	if m.highestDataConn == nil {
		m.highestDataConn = &connInfo{
			ConnectionName:  currConnKey,
			ConnectionValue: int(currConn.TotalBytes),
		}
		return
	}

	if int(currConn.TotalBytes) > m.highestDataConn.ConnectionValue {
		m.highestDataConn = &connInfo{
			ConnectionName:  currConnKey,
			ConnectionValue: int(currConn.TotalBytes),
		}
	}
}
