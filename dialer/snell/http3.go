package snell

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	transportTLS "github.com/daeuniverse/outbound/transport/tls"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
	"github.com/olicesx/quic-go/logging"
)

func (s *Snell) isHTTP3() bool { return s.Transport == "h3" || s.Transport == "auto" }

func (s *Snell) http3CongestionControl() (name string, unsupported bool, err error) {
	name = s.CCOverride
	if name == "" {
		name = s.CongestionControl
	}
	switch name {
	case "":
		name = "bbr3"
	case "new_reno":
		name = "reno"
	case "reno", "bbr", "bbr3", "brutal":
	default:
		if s.CCOverride != "" {
			return "", false, fmt.Errorf("snell: unsupported cc_override %q", name)
		}
		name, unsupported = "bbr3", true
	}
	if s.Cwnd < 0 || name == "brutal" && s.Cwnd == 0 {
		return "", false, errors.New("snell: cwnd must be non-negative, and positive for brutal")
	}
	return
}

type http3Session struct {
	conn      quic.Connection
	client    *http3.ClientConn
	transport *quic.Transport
	packet    net.PacketConn
	closeOnce sync.Once
	refs      int // guarded by http3Dialer.mu
	rtt       atomic.Int64
}

type http3PendingDial struct {
	done chan struct{}
	err  error // published by closing done
}

func (s *http3Session) close() {
	s.closeOnce.Do(func() {
		_ = s.conn.CloseWithError(0, "")
		_ = s.transport.Close()
		_ = s.packet.Close()
	})
}

type http3Dialer struct {
	next, fallback netproxy.Dialer
	address        string
	host, path     string
	tlsConfig      *tls.Config
	cc             string
	cwnd           uint64
	auto           bool
	now            func() time.Time
	timeout        time.Duration
	ctx            context.Context
	cancel         context.CancelFunc

	mu         sync.Mutex
	current    *http3Session
	sessions   map[*http3Session]struct{}
	pending    *http3PendingDial
	retryAfter time.Time
}

func newHTTP3Dialer(s *Snell, next, fallback netproxy.Dialer, address string) (*http3Dialer, error) {
	ech, err := transportTLS.DecodeECHConfigList(s.ECHConfig)
	if err != nil {
		return nil, err
	}
	cc, _, err := s.http3CongestionControl()
	if err != nil {
		return nil, err
	}
	host := s.SNI
	if host == "" {
		host = s.ObfsHost
	}
	if host == "" {
		host = s.Server
	}
	hash := sha256.Sum256([]byte(s.PSK))
	ctx, cancel := context.WithCancel(context.Background())
	timeout := 10 * time.Second
	if s.Transport == "auto" {
		timeout = 2 * time.Second
	}
	return &http3Dialer{
		next: next, fallback: fallback, address: address,
		host: host, path: fmt.Sprintf("/ws-tunnel-%x", hash[:12]),
		tlsConfig: &tls.Config{
			ServerName: host, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3}, EncryptedClientHelloConfigList: ech,
			ClientSessionCache: tls.NewLRUClientSessionCache(snellECHSessionCacheCapacity),
		},
		cc: cc, cwnd: uint64(s.Cwnd), auto: s.Transport == "auto",
		now: time.Now, timeout: timeout, ctx: ctx, cancel: cancel,
		sessions: make(map[*http3Session]struct{}),
	}, nil
}

const snellECHSessionCacheCapacity = 32

func (d *http3Dialer) DialContext(ctx context.Context, network, _ string) (netproxy.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	if err := d.ctx.Err(); err != nil {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	cooling := d.auto && d.now().Before(d.retryAfter)
	d.mu.Unlock()
	var conn netproxy.Conn
	var err error
	switch {
	case !d.auto:
		attempt, end := context.WithTimeout(ctx, d.timeout)
		conn, err = d.open(attempt, network)
		end()
	case cooling:
		conn, err = d.fallback.DialContext(ctx, network, d.address)
	default:
		conn, err = raceSnellTransports(ctx, d.ctx, snellHTTP3Delay(d.smoothedRTT()), d.timeout,
			func(ctx context.Context) (netproxy.Conn, error) {
				return d.open(ctx, network)
			},
			func(ctx context.Context) (netproxy.Conn, error) {
				return d.fallback.DialContext(ctx, network, d.address)
			}, d.recordHTTP3Result)
	}
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err == nil {
		err = d.ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *http3Dialer) smoothedRTT() time.Duration {
	d.mu.Lock()
	session := d.current
	d.mu.Unlock()
	if session == nil || session.conn.Context().Err() != nil {
		return 0
	}
	return time.Duration(session.rtt.Load())
}

func (d *http3Dialer) recordHTTP3Result(success bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return
	}
	if success {
		d.retryAfter = time.Time{}
	} else {
		d.retryAfter = d.now().Add(30 * time.Second)
	}
}

func (d *http3Dialer) get(ctx context.Context, network string) (*http3Session, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.mu.Lock()
		if d.ctx.Err() != nil {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		if s := d.current; s != nil && s.conn.Context().Err() == nil {
			s.refs++
			d.mu.Unlock()
			return s, nil
		}
		pending := d.pending
		if pending == nil {
			pending = &http3PendingDial{done: make(chan struct{})}
			d.pending = pending
			// A caller owns only its wait, not the shared QUIC handshake.
			attempt, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.timeout)
			stop := context.AfterFunc(d.ctx, cancel)
			go func() {
				defer cancel()
				defer stop()
				d.dialSession(attempt, network, pending)
			}()
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, net.ErrClosed
		case <-pending.done:
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pending.err != nil {
			return nil, pending.err
		}
	}
}

func (d *http3Dialer) dialSession(ctx context.Context, network string, pending *http3PendingDial) {
	s, err := d.connect(ctx, network)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil && (d.ctx.Err() != nil || ctx.Err() != nil) {
		s.close()
		err = net.ErrClosed
	}
	if err == nil {
		d.current = s
		d.sessions[s] = struct{}{}
		context.AfterFunc(s.conn.Context(), func() {
			s.close()
			d.mu.Lock()
			delete(d.sessions, s)
			if d.current == s {
				d.current = nil
			}
			d.mu.Unlock()
		})
	}
	pending.err = err
	d.pending = nil
	close(pending.done)
}

func (d *http3Dialer) connect(ctx context.Context, network string) (*http3Session, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	magic.Network, magic.Mptcp = "udp", false
	raw, err := d.next.DialContext(ctx, magic.Encode(), d.address)
	if err != nil {
		return nil, err
	}
	// Let the next dialer resolve and address the server. This also works for
	// chained UDP proxies, without bypassing their resolver or routing policy.
	pc := &http3PacketConn{Conn: raw, peer: http3Addr(d.address)}
	tr := &quic.Transport{Conn: pc, DisableAddrParsing: true}
	s := &http3Session{transport: tr, packet: pc}
	// This QUIC fork exposes RTT via tracing rather than ConnectionStats.
	// Leave all transport tuning parameters at their library defaults.
	conn, err := tr.Dial(ctx, pc.peer, d.tlsConfig.Clone(), &quic.Config{
		Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
			return &logging.ConnectionTracer{
				UpdatedMetrics: func(rtt *logging.RTTStats, _, _ logging.ByteCount, _ int) {
					s.rtt.Store(int64(rtt.SmoothedRTT()))
				},
			}
		},
	})
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return nil, err
	}
	s.conn = conn
	state := conn.ConnectionState().TLS
	if !state.ECHAccepted || state.NegotiatedProtocol != http3.NextProtoH3 {
		s.close()
		return nil, errors.New("snell: HTTP/3 requires accepted ECH and h3 ALPN")
	}
	switch d.cc {
	case "bbr":
		congestion.UseBBR(conn)
	case "bbr3":
		congestion.UseBbr3(conn, d.cwnd)
	case "brutal":
		congestion.UseBrutal(conn, d.cwnd)
	case "reno":
		// This QUIC fork installs native New Reno by default.
	}
	s.client = (&http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 8 * 1024}).NewClientConn(conn)
	return s, nil
}

func (d *http3Dialer) open(ctx context.Context, network string) (_ netproxy.Conn, err error) {
	s, err := d.get(ctx, network)
	if err != nil {
		return nil, err
	}
	var tunnel *http3Conn
	defer func() {
		if err != nil {
			if tunnel != nil {
				_ = tunnel.Close()
			} else {
				d.release(s)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.conn.Context().Done():
		return nil, context.Cause(s.conn.Context())
	case <-s.client.ReceivedSettings():
	}
	if !s.client.Settings().EnableExtendedConnect {
		return nil, errors.New("snell: server did not enable HTTP/3 Extended CONNECT")
	}
	stream, err := s.client.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.retire(s)
		}
		return nil, err
	}
	tunnel = &http3Conn{RequestStream: stream, session: s}
	tunnel.release = func() { d.release(s) }
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = tunnel.Close()
		close(done)
	})
	defer func() {
		if !stop() {
			<-done
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect, Proto: "websocket", Host: d.host,
		URL: &url.URL{Scheme: "https", Host: d.host, Path: d.path},
	})
	if err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusServiceUnavailable {
			d.retire(s)
		}
		return nil, fmt.Errorf("snell: HTTP/3 CONNECT status %d", response.StatusCode)
	}
	_ = stream.SetDeadline(time.Time{})
	return tunnel, nil
}

func (d *http3Dialer) retire(s *http3Session) {
	d.mu.Lock()
	if d.current == s {
		d.current = nil
	}
	closeSession := s.refs == 0
	d.mu.Unlock()
	if closeSession {
		s.close()
	}
}

func (d *http3Dialer) release(s *http3Session) {
	d.mu.Lock()
	s.refs--
	closeSession := s.refs == 0 && d.current != s
	d.mu.Unlock()
	if closeSession {
		s.close()
	}
}

func (d *http3Dialer) Close() error {
	d.cancel()
	d.mu.Lock()
	sessions := make([]*http3Session, 0, len(d.sessions))
	for s := range d.sessions {
		sessions = append(sessions, s)
	}
	d.current = nil
	d.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	return nil
}

type http3Conn struct {
	http3.RequestStream
	session *http3Session
	release func()
	closed  atomic.Bool
	writeMu sync.Mutex
}

func (c *http3Conn) LocalAddr() net.Addr  { return c.session.conn.LocalAddr() }
func (c *http3Conn) RemoteAddr() net.Addr { return c.session.conn.RemoteAddr() }
func (c *http3Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := c.session.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(label, context, length)
}
func (c *http3Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.RequestStream.Write(p)
}
func (c *http3Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.RequestStream.Close()
}
func (c *http3Conn) Close() error {
	if !c.closed.Swap(true) {
		c.CancelRead(0)
		c.CancelWrite(0)
		c.release()
	}
	return nil
}

type http3Addr string

func (a http3Addr) Network() string { return "udp" }
func (a http3Addr) String() string  { return string(a) }

type http3PacketConn struct {
	netproxy.Conn
	peer net.Addr
}

func (c *http3PacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *http3PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.peer, err
}
func (c *http3PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
