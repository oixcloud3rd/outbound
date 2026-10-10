package snell

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/stretchr/testify/require"
)

func TestSnellHappyEyeballs(t *testing.T) {
	for _, tc := range []struct{ rtt, want time.Duration }{
		{0, 250 * time.Millisecond},
		{10 * time.Millisecond, 100 * time.Millisecond},
		{150 * time.Millisecond, 300 * time.Millisecond},
		{800 * time.Millisecond, time.Second},
	} {
		require.Equal(t, tc.want, snellHTTP3Delay(tc.rtt))
	}
	failed := errors.New("dial failed")
	for _, test := range []struct {
		name               string
		h3Delay, tcpDelay  time.Duration
		h3Err, tcpErr      error
		deadline, tcpStart time.Duration
		elapsed            time.Duration
		winner             string
	}{
		{name: "H3 wins before TCP starts", h3Delay: 20 * time.Millisecond, elapsed: 20 * time.Millisecond, winner: "h3"},
		{name: "TCP wins and closes late H3", h3Delay: time.Second, tcpStart: 250 * time.Millisecond, elapsed: 250 * time.Millisecond, winner: "tcp"},
		{name: "H3 error starts TCP immediately", h3Delay: 10 * time.Millisecond, h3Err: failed, tcpStart: 10 * time.Millisecond, elapsed: 10 * time.Millisecond, winner: "tcp"},
		{name: "TCP error still waits for H3", h3Delay: time.Second, tcpErr: failed, tcpStart: 250 * time.Millisecond, elapsed: time.Second, winner: "h3"},
		{name: "H3 wins and closes late TCP", h3Delay: 400 * time.Millisecond, tcpDelay: time.Second, tcpStart: 250 * time.Millisecond, elapsed: 400 * time.Millisecond, winner: "h3"},
		{name: "both fail", h3Err: failed, tcpErr: failed},
		{name: "caller deadline", h3Delay: time.Second, deadline: 50 * time.Millisecond, elapsed: 50 * time.Millisecond},
		{name: "H3 probe times out after TCP wins", h3Delay: 5 * time.Second, tcpStart: 250 * time.Millisecond, elapsed: 250 * time.Millisecond, winner: "tcp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				if test.deadline != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, test.deadline)
					defer cancel()
				}
				h3, tcp := new(raceTestConn), new(raceTestConn)
				start := time.Now()
				var tcpStarted time.Duration
				var tcpCalls atomic.Int32
				var lostCanceled atomic.Bool
				var successes, failures atomic.Int32
				conn, err := raceSnellTransports(ctx, t.Context(), 250*time.Millisecond, 2*time.Second,
					func(ctx context.Context) (netproxy.Conn, error) {
						select {
						case <-time.After(test.h3Delay):
						case <-ctx.Done():
							lostCanceled.Store(true)
							return h3, ctx.Err()
						}
						if test.winner != "h3" {
							lostCanceled.Store(ctx.Err() != nil)
						}
						return h3, test.h3Err
					},
					func(ctx context.Context) (netproxy.Conn, error) {
						tcpStarted = time.Since(start)
						tcpCalls.Add(1)
						time.Sleep(test.tcpDelay)
						if test.winner == "h3" {
							lostCanceled.Store(ctx.Err() != nil)
						}
						return tcp, test.tcpErr
					}, func(ok bool) {
						if ok {
							successes.Add(1)
						} else {
							failures.Add(1)
						}
					})
				require.Equal(t, test.elapsed, time.Since(start))
				if test.winner == "" {
					require.Error(t, err)
					require.Nil(t, conn)
					if test.deadline != 0 {
						require.ErrorIs(t, err, context.DeadlineExceeded)
					} else {
						require.ErrorIs(t, err, failed)
						require.ErrorContains(t, err, "HTTP/3")
						require.ErrorContains(t, err, "TCP")
					}
				} else {
					require.NoError(t, err)
					expected := h3
					if test.winner == "tcp" {
						expected = tcp
					}
					require.Same(t, expected, conn)
					require.Zero(t, expected.closed.Load())
					require.NoError(t, conn.Close())
				}
				time.Sleep(2 * time.Second)
				synctest.Wait()
				require.Equal(t, test.tcpStart, tcpStarted)
				require.Equal(t, int32(1), h3.closed.Load())
				require.Equal(t, tcpCalls.Load(), tcp.closed.Load())
				if test.deadline > 0 || test.h3Delay > 2*time.Second || test.tcpDelay > 0 {
					require.True(t, lostCanceled.Load())
				} else if test.winner == "tcp" && test.h3Err == nil {
					require.False(t, lostCanceled.Load(), "TCP winner leaves the bounded H3 probe running")
				}
				switch {
				case test.deadline > 0:
					require.Zero(t, successes.Load()+failures.Load())
				case test.h3Err != nil || test.h3Delay > 2*time.Second:
					require.EqualValues(t, 1, failures.Load())
					require.Zero(t, successes.Load())
				default:
					require.EqualValues(t, 1, successes.Load())
					require.Zero(t, failures.Load())
				}
			})
		})
	}
	t.Run("close stops orphaned probe without recording failure", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			generation, closeDialer := context.WithCancel(t.Context())
			defer closeDialer()
			var reports atomic.Int32
			exited := make(chan struct{})
			conn, err := raceSnellTransports(t.Context(), generation, 250*time.Millisecond, 2*time.Second,
				func(ctx context.Context) (netproxy.Conn, error) {
					<-ctx.Done()
					close(exited)
					return nil, ctx.Err()
				}, func(context.Context) (netproxy.Conn, error) {
					return new(raceTestConn), nil
				}, func(bool) { reports.Add(1) })
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			closeDialer()
			<-exited
			synctest.Wait()
			require.Zero(t, reports.Load())
		})
	})
}

type raceTestConn struct {
	netproxy.Conn
	closed atomic.Int32
}

func (c *raceTestConn) Close() error { c.closed.Add(1); return nil }

func TestHTTP3SharedHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime, closeDialer := context.WithCancel(t.Context())
		defer closeDialer()
		failed := errors.New("shared handshake failed")
		var calls atomic.Int32
		d := &http3Dialer{
			ctx: lifetime, cancel: closeDialer, timeout: 2 * time.Second,
			auto: true, now: time.Now,
			next: http3DialFunc(func(ctx context.Context, _, _ string) (netproxy.Conn, error) {
				calls.Add(1)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Second):
					return nil, failed
				}
			}),
		}
		first, cancelFirst := context.WithCancel(t.Context())
		firstDone, secondDone := make(chan error, 1), make(chan error, 1)
		go func() { _, err := d.get(first, "tcp"); firstDone <- err }()
		synctest.Wait()
		go func() { _, err := d.get(t.Context(), "tcp"); secondDone <- err }()
		synctest.Wait()
		cancelFirst()
		require.ErrorIs(t, <-firstDone, context.Canceled)
		require.ErrorIs(t, <-secondDone, failed)
		require.Equal(t, int32(1), calls.Load())
		require.True(t, d.retryAfter.IsZero(), "only the tunnel race updates cooldown")
		// Closing the dialer also cancels an independent pending handshake.
		go func() { _, err := d.get(t.Context(), "tcp"); secondDone <- err }()
		synctest.Wait()
		require.NoError(t, d.Close())
		require.Error(t, <-secondDone)
		synctest.Wait()
		require.Nil(t, d.pending)
	})
}

type http3DialFunc func(context.Context, string, string) (netproxy.Conn, error)

func (f http3DialFunc) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	return f(ctx, network, address)
}
