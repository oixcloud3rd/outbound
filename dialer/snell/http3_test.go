package snell

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestHTTP3Tunnel(t *testing.T) {
	d, transport, requests := newHTTP3Fixture(t, "h3", http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, d.Preconnect(ctx, 1))
	for _, network := range []string{"tcp", "tcp", "udp"} {
		conn, err := d.DialContext(ctx, network, "192.0.2.1:53")
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		_, err = conn.Write([]byte("snell-h3"))
		require.NoError(t, err)
		response := make([]byte, 8)
		_, err = io.ReadFull(conn, response)
		require.NoError(t, err)
		require.Equal(t, "snell-h3", string(response))
		if network == "tcp" {
			require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
			_, err = io.ReadAll(conn)
			require.NoError(t, err)
		}
		require.NoError(t, conn.Close())
	}
	require.Equal(t, int32(2), requests.Load(), "TCP reuses its warmed tunnel; UDP uses a separate stream")
	transport.mu.Lock()
	require.Len(t, transport.sessions, 1, "tunnels share one QUIC session")
	session := transport.current
	transport.mu.Unlock()
	marked := netproxy.MagicNetwork{Network: "tcp", Mark: 123, IPVersion: "6"}.Encode()
	markedRoute, err := d.route(marked)
	require.NoError(t, err)
	defaultRoute, err := d.route("tcp")
	require.NoError(t, err)
	require.NotSame(t, defaultRoute, markedRoute, "route-specific reuse pools must be isolated")
	require.NoError(t, d.Close())
	select {
	case <-session.conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("Close did not release QUIC")
	}
	_, err = d.DialContext(ctx, "tcp", "192.0.2.1:53")
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestHTTP3Fallback(t *testing.T) {
	d, transport, requests := newHTTP3Fixture(t, "auto", http.StatusServiceUnavailable)
	now := time.Now()
	transport.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if i == 2 {
			now = now.Add(31 * time.Second)
		}
		conn, err := transport.DialContext(context.Background(), "tcp", "")
		require.NoError(t, err)
		state := conn.(*tls.Conn).ConnectionState()
		require.True(t, state.ECHAccepted)
		require.Equal(t, snellECHTLSALPN, state.NegotiatedProtocol)
		require.NoError(t, conn.Close())
		require.Equal(t, int32(1+i/2), requests.Load())
	}
	// The same rejected CONNECT must fail in h3 mode, rather than use TCP.
	transport.auto = false
	_, err := transport.DialContext(context.Background(), "tcp", "")
	require.ErrorContains(t, err, "503")
	transport.tlsConfig.RootCAs = x509.NewCertPool()
	_, err = transport.DialContext(context.Background(), "tcp", "")
	require.Error(t, err, "H3 must verify the certificate")
	transport.auto = true
	transport.retryAfter = time.Time{}
	transport.timeout = 10 * time.Millisecond
	transport.next = blockingHTTP3Dialer{}
	conn, err := transport.DialContext(context.Background(), "tcp", "")
	require.NoError(t, err, "H3 establishment timeout permits TCP fallback")
	require.NoError(t, conn.Close())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = transport.DialContext(ctx, "tcp", "")
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, d.Close())

	t.Run("TCP winner leaves a reusable H3 session", func(t *testing.T) {
		_, transport, requests := newHTTP3Fixture(t, "auto", http.StatusOK)
		next := transport.next
		proceed := make(chan struct{})
		var dials atomic.Int32
		transport.next = http3DialFunc(func(ctx context.Context, network, address string) (netproxy.Conn, error) {
			dials.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-proceed:
				return next.DialContext(ctx, network, address)
			}
		})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		conn, err := transport.DialContext(ctx, "tcp", "")
		require.NoError(t, err)
		require.IsType(t, &tls.Conn{}, conn)
		require.NoError(t, conn.Close())
		close(proceed)
		require.Eventually(t, func() bool {
			transport.mu.Lock()
			defer transport.mu.Unlock()
			return requests.Load() == 1 && transport.current != nil && transport.current.refs == 0
		}, 2*time.Second, 10*time.Millisecond)
		conn, err = transport.DialContext(ctx, "tcp", "")
		require.NoError(t, err)
		require.IsType(t, &http3Conn{}, conn)
		require.NoError(t, conn.Close())
		require.EqualValues(t, 1, dials.Load(), "late H3 probe warms the shared session")
		transport.mu.Lock()
		cooling := !transport.retryAfter.IsZero()
		transport.mu.Unlock()
		require.False(t, cooling)
	})
}

type blockingHTTP3Dialer struct{}

func (blockingHTTP3Dialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func newHTTP3Fixture(t *testing.T, mode string, status int) (*http3SnellDialer, *http3Dialer, *atomic.Int32) {
	t.Helper()
	echKey, echConfig, cert, roots := http3TestTLS(t)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{echKey},
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h3", snellECHTLSALPN},
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	service, err := snellv5.NewService(snellv5.ServiceOptions{
		PSK: []byte("test-password"), Identity: true, Handler: http3Echo{},
	})
	require.NoError(t, err)
	go func() {
		for {
			raw, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				conn := tls.Server(raw, serverTLS)
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := conn.Handshake(); err != nil {
					_ = conn.Close()
					return
				}
				if err := service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil); err != nil {
					_ = conn.Close()
				}
			}()
		}
	}()
	s := &Snell{
		Server: "127.0.0.1", Port: tcp.Addr().(*net.TCPAddr).Port, PSK: "test-password",
		Version: 4, Transport: mode, Obfs: "ech-tls", SNI: "inner.example",
		Identity: protocolSnell.IdentityV2, IdentityExplicit: true, Reuse: true,
		ECHConfig: base64.StdEncoding.EncodeToString(echConfig),
	}
	created, _, err := s.Dialer(&dialer.ExtraOption{}, direct.NewDirectDialers("").Symmetric)
	require.NoError(t, err)
	d := created.(*http3SnellDialer)
	t.Cleanup(func() { _ = d.Close() })
	route, err := d.route("tcp")
	require.NoError(t, err)
	transport := route.(*ownedHTTP3Dialer).transport
	transport.tlsConfig.RootCAs = roots
	tcpTLS := transport.tlsConfig.Clone()
	tcpTLS.NextProtos = []string{snellECHTLSALPN}
	transport.fallback = &echTLSDialer{Dialer: http3TestDialer{tlsConfig: tcpTLS}, alpn: snellECHTLSALPN}
	type connectionKey struct{}
	requests := new(atomic.Int32)
	server := &http3.Server{
		TLSConfig: serverTLS,
		ConnContext: func(ctx context.Context, conn quic.Connection) context.Context {
			return context.WithValue(ctx, connectionKey{}, conn)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != http.MethodConnect || r.Proto != "websocket" ||
				r.URL.Path != transport.path || r.Host != s.SNI || !r.TLS.ECHAccepted {
				http.Error(w, "invalid tunnel", http.StatusBadRequest)
				return
			}
			w.WriteHeader(status)
			if status != http.StatusOK {
				return
			}
			conn := &http3TestServerConn{
				Stream: w.(http3.HTTPStreamer).HTTPStream(),
				conn:   r.Context().Value(connectionKey{}).(quic.Connection),
			}
			if err := service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil); err != nil {
				_ = conn.Close()
			}
		}),
	}
	listener, err := quic.ListenEarly(udp, serverTLS, &quic.Config{})
	require.NoError(t, err)
	go func() { _ = server.ServeListener(listener) }()
	t.Cleanup(func() { _ = listener.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return d, transport, requests
}

type http3TestDialer struct{ tlsConfig *tls.Config }

func (d http3TestDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if d.tlsConfig != nil {
		return (&tls.Dialer{Config: d.tlsConfig}).DialContext(ctx, magic.Network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, magic.Network, address)
}

type http3TestServerConn struct {
	http3.Stream
	conn quic.Connection
}

func (c *http3TestServerConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *http3TestServerConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *http3TestServerConn) CloseWrite() error    { return c.Stream.Close() }
func (c *http3TestServerConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}
func (c *http3TestServerConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(label, context, length)
}

type http3Echo struct{}

func (http3Echo) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		_ = N.CloseWrite(conn)
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (http3Echo) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var err error
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(err)
			}
		}()
		for {
			packet := buf.NewSize(4096)
			packet.Resize(2048, 0)
			var destination M.Socksaddr
			destination, err = conn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				return
			}
			if err = conn.WritePacket(packet, destination); err != nil {
				return
			}
		}
	}()
}

func http3TestTLS(t *testing.T) (tls.EncryptedClientHelloKey, []byte, tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	contents := []byte{0, 0, 0x20, 0, 32}
	contents = append(contents, key.PublicKey().Bytes()...)
	contents = append(contents, 0, 4, 0, 1, 0, 1, 0, byte(len("outer.example")))
	contents = append(contents, "outer.example"...)
	contents = append(contents, 0, 0)
	config := binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(contents)))
	config = append(config, contents...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"inner.example", "outer.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signingKey.PublicKey, signingKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes()}, list,
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signingKey}, roots
}
