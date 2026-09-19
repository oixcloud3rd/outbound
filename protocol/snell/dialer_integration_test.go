package snell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	singSnell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testPSK = "test-password-v6"

func TestDialerTCPRoundTrip(t *testing.T) {
	t.Parallel()
	for _, options := range []ClientOptions{
		{Version: Version4},
		{Version: Version5},
		{Version: Version6, Mode: "default"},
		{Version: Version6, Mode: "unshaped"},
		{Version: Version6, Mode: "unsafe-raw"},
	} {
		options := options
		t.Run(clientOptionsName(options), func(t *testing.T) {
			t.Parallel()
			dialer := newTestDialer(t, options)
			conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
			require.NoError(t, err)
			payload := []byte("round-trip")
			_, err = conn.Write(payload)
			require.NoError(t, err)
			require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
			response, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, payload, response)
			require.NoError(t, conn.Close())
		})
	}
}

func TestDialerUDPRoundTrip(t *testing.T) {
	t.Parallel()
	for _, options := range []ClientOptions{
		{Version: Version4},
		{Version: Version5},
		{Version: Version6, Mode: "default"},
		{Version: Version6, Mode: "unshaped"},
		{Version: Version6, Mode: "unsafe-raw"},
	} {
		options := options
		t.Run(clientOptionsName(options), func(t *testing.T) {
			t.Parallel()
			dialer := newTestDialer(t, options)
			conn, err := dialer.DialContext(context.Background(), "udp", "203.0.113.9:443")
			require.NoError(t, err)
			packetConn := conn.(netproxy.PacketConn)
			payload := []byte("datagram")
			_, err = packetConn.Write(payload)
			require.NoError(t, err)
			buffer := make([]byte, 64)
			n, source, err := packetConn.ReadFrom(buffer)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddrPort("203.0.113.9:443"), source)
			require.Equal(t, payload, buffer[:n])
			require.NoError(t, packetConn.Close())
		})
	}
}

func TestDialerConnectionReuse(t *testing.T) {
	t.Parallel()
	for _, options := range []ClientOptions{
		{Version: Version4, Reuse: true},
		{Version: Version5, Reuse: true},
		{Version: Version6, Mode: "unshaped", Reuse: true},
	} {
		options := options
		t.Run(clientOptionsName(options), func(t *testing.T) {
			t.Parallel()
			var physicalConnections atomic.Int32
			dialer := newTestDialerWithCounter(t, options, &physicalConnections)
			for requestIndex := 0; requestIndex < 2; requestIndex++ {
				conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
				require.NoError(t, err)
				payload := []byte("reuse")
				_, err = conn.Write(payload)
				require.NoError(t, err)
				require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
				response, err := io.ReadAll(conn)
				require.NoError(t, err)
				require.Equal(t, payload, response)
				require.NoError(t, conn.Close())
			}
			require.Equal(t, int32(1), physicalConnections.Load())
		})
	}
}

func TestDialerV4Obfs(t *testing.T) {
	t.Parallel()
	for _, obfs := range []string{"http", "tls"} {
		obfs := obfs
		t.Run(obfs, func(t *testing.T) {
			t.Parallel()
			options := ClientOptions{Version: Version5, Obfs: obfs, ObfsHost: "obfs.example"}
			dialer := newTestDialer(t, options)
			conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
			require.NoError(t, err)
			_, err = conn.Write([]byte(obfs))
			require.NoError(t, err)
			require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
			response, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, []byte(obfs), response)
			require.NoError(t, conn.Close())
		})
	}
}

func TestDialerUserKey(t *testing.T) {
	t.Parallel()
	for _, options := range []ClientOptions{
		{Version: Version5, UserKey: "user-key"},
		{Version: Version6, Mode: "default", UserKey: "user-key"},
	} {
		options := options
		t.Run(clientOptionsName(options), func(t *testing.T) {
			t.Parallel()
			dialer := newTestDialer(t, options)
			conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
			require.NoError(t, err)
			_, err = conn.Write([]byte("authenticated"))
			require.NoError(t, err)
			require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
			response, err := io.ReadAll(conn)
			require.NoError(t, err)
			require.Equal(t, []byte("authenticated"), response)
			require.NoError(t, conn.Close())
		})
	}
}

func TestDialerPreservesMagicNetwork(t *testing.T) {
	t.Parallel()
	options := ClientOptions{Version: Version5}
	networks := make(chan string, 1)
	base := &serviceDialer{service: newTestService(t, options), networks: networks}
	dialer, err := NewDialer(base, protocol.Header{
		ProxyAddress: "proxy.example:443",
		Password:     testPSK,
		Feature1:     options,
	})
	require.NoError(t, err)
	want := netproxy.MagicNetwork{Network: "tcp", Mark: 123, Mptcp: true, IPVersion: "4"}
	conn, err := dialer.DialContext(context.Background(), want.Encode(), "destination.example:443")
	require.NoError(t, err)
	got, err := netproxy.ParseMagicNetwork(<-networks)
	require.NoError(t, err)
	require.Equal(t, &want, got)
	require.NoError(t, conn.Close())
}

func TestDialerExplicitIdentity(t *testing.T) {
	t.Parallel()
	prefixes := make(chan []byte, 1)
	base := &identityCaptureDialer{prefixes: prefixes}
	dialer, err := NewDialer(base, protocol.Header{
		ProxyAddress: "proxy.example:443",
		Password:     testPSK,
		Feature1: ClientOptions{
			Version:  Version5,
			Identity: IdentityV1,
		},
	})
	require.NoError(t, err)
	conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
	require.NoError(t, err)
	_, err = conn.Write([]byte("identity"))
	require.NoError(t, err)
	prefix := <-prefixes
	require.Equal(t, "DLSNID01", string(prefix[singSnell.SaltLen:singSnell.SaltLen+8]))
	require.Equal(t, singSnell.IdentityHeaderFromPSK([]byte(testPSK)), prefix[singSnell.SaltLen+8:])
	require.NoError(t, conn.Close())
}

func TestDialerIdentityV2RoundTrip(t *testing.T) {
	t.Parallel()
	options := ClientOptions{Version: Version4, Identity: IdentityV2, ECHTLS: true}
	dialer := newTestDialer(t, options)
	conn, err := dialer.DialContext(context.Background(), "tcp", "destination.example:443")
	require.NoError(t, err)
	_, err = conn.Write([]byte("identity-v2"))
	require.NoError(t, err)
	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
	response, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, []byte("identity-v2"), response)
	require.NoError(t, conn.Close())
}

func TestDialerPreconnectUsesWarmPool(t *testing.T) {
	t.Parallel()
	var physicalConnections atomic.Int32
	options := ClientOptions{
		Version:    Version4,
		Identity:   IdentityV2,
		ECHTLS:     true,
		Reuse:      true,
		Preconnect: 2,
	}
	dialer := newTestDialerWithCounter(t, options, &physicalConnections)
	managed := dialer.(*Dialer)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, managed.Preconnect(ctx, 2))
	require.Equal(t, int32(2), physicalConnections.Load())
	conn, err := managed.DialContext(ctx, "tcp", "destination.example:443")
	require.NoError(t, err)
	require.Equal(t, int32(2), physicalConnections.Load())
	require.NoError(t, conn.Close())
	require.NoError(t, managed.Close())
}

func TestDialerPreconnectLifecycle(t *testing.T) {
	t.Parallel()
	base := &blockingPreconnectDialer{started: make(chan struct{}, 2)}
	created, err := NewDialer(base, protocol.Header{
		ProxyAddress: "proxy.example:443",
		Password:     testPSK,
		Feature1: ClientOptions{
			Version:    Version4,
			Reuse:      true,
			ECHTLS:     true,
			Preconnect: 1,
		},
	})
	require.NoError(t, err)
	managed := created.(*Dialer)
	require.NoError(t, managed.Start(context.Background()))
	select {
	case <-base.started:
	case <-time.After(time.Second):
		t.Fatal("preconnect did not start")
	}
	require.NoError(t, managed.Start(context.Background()))
	require.NoError(t, managed.Close())
	require.Equal(t, int32(1), base.calls.Load())
	require.NoError(t, managed.Close())
}

func newTestDialer(t *testing.T, options ClientOptions) netproxy.Dialer {
	t.Helper()
	return newTestDialerWithCounter(t, options, nil)
}

func newTestDialerWithCounter(t *testing.T, options ClientOptions, counter *atomic.Int32) netproxy.Dialer {
	t.Helper()
	service := newTestService(t, options)
	base := &serviceDialer{service: service, connections: counter}
	if options.Identity == IdentityV2 {
		base.exporter = make([]byte, singSnell.IdentityExporterLength)
		for index := range base.exporter {
			base.exporter[index] = byte(index)
		}
	}
	dialer, err := NewDialer(base, protocol.Header{
		ProxyAddress: "proxy.example:443",
		Password:     testPSK,
		Feature1:     options,
	})
	require.NoError(t, err)
	return dialer
}

func newTestService(t *testing.T, options ClientOptions) singSnell.Service {
	t.Helper()
	handler := echoHandler{}
	if options.Version == Version6 {
		mode, err := snellv6.ParseMode(options.Mode)
		require.NoError(t, err)
		serverOptions := snellv6.ServerOptions{
			PSK:     []byte(testPSK),
			Mode:    mode,
			Handler: handler,
		}
		if options.UserKey != "" {
			service, err := snellv6.NewMultiService[string](serverOptions)
			require.NoError(t, err)
			require.NoError(t, service.UpdateUsers([]string{"user"}, [][]byte{[]byte(options.UserKey)}))
			return service
		}
		service, err := snellv6.NewService(serverOptions)
		require.NoError(t, err)
		return service
	}
	obfsMode, err := singSnell.ParseObfsMode(options.Obfs)
	require.NoError(t, err)
	serviceOptions := snellv5.ServiceOptions{
		PSK:      []byte(testPSK),
		Identity: options.Identity != singSnell.IdentityDisabled,
		ObfsMode: obfsMode,
		Handler:  handler,
	}
	if options.UserKey != "" {
		service, err := snellv5.NewMultiService[string](serviceOptions)
		require.NoError(t, err)
		require.NoError(t, service.UpdateUsers([]string{"user"}, [][]byte{[]byte(options.UserKey)}))
		return service
	}
	service, err := snellv5.NewService(serviceOptions)
	require.NoError(t, err)
	return service
}

type serviceDialer struct {
	service     singSnell.Service
	connections *atomic.Int32
	networks    chan string
	exporter    []byte
}

type identityCaptureDialer struct {
	prefixes chan []byte
}

func (d *identityCaptureDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	go func() {
		prefix := make([]byte, singSnell.SaltLen+8+singSnell.IdentityHeaderLength)
		_, err := io.ReadFull(server, prefix)
		if err == nil {
			d.prefixes <- prefix
		}
		_, _ = io.Copy(io.Discard, server)
		_ = server.Close()
	}()
	return client, nil
}

func (d *serviceDialer) DialContext(_ context.Context, network, _ string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	if d.connections != nil {
		d.connections.Add(1)
	}
	if d.networks != nil {
		d.networks <- network
	}
	go func() {
		serverConn := net.Conn(server)
		if len(d.exporter) != 0 {
			serverConn = &identityExporterConn{Conn: server, exporter: d.exporter}
		}
		err := d.service.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil)
		if err != nil {
			_ = server.Close()
		}
	}()
	if len(d.exporter) != 0 {
		return &identityExporterConn{Conn: client, exporter: d.exporter}, nil
	}
	return client, nil
}

type identityExporterConn struct {
	net.Conn
	exporter []byte
}

type blockingPreconnectDialer struct {
	started chan struct{}
	calls   atomic.Int32
}

func (d *blockingPreconnectDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	d.calls.Add(1)
	d.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *identityExporterConn) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return append([]byte(nil), c.exporter...), nil
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		payload, err := io.ReadAll(conn)
		if err == nil {
			_, err = io.Copy(conn, bytes.NewReader(payload))
		}
		closeWriteErr := N.CloseWrite(conn)
		if err == nil {
			err = closeWriteErr
		}
		closeErr := conn.Close()
		if err == nil {
			err = closeErr
		}
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var closeErr error
		defer func() {
			if err := conn.Close(); closeErr == nil {
				closeErr = err
			}
			if onClose != nil {
				onClose(closeErr)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				closeErr = ctx.Err()
				return
			default:
			}
			buffer := buf.NewSize(64 * 1024)
			buffer.Resize(2048, 0)
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				closeErr = err
				return
			}
			if err = conn.WritePacket(buffer, destination); err != nil {
				closeErr = err
				return
			}
		}
	}()
}

func clientOptionsName(options ClientOptions) string {
	if options.Version == Version6 {
		return "v6-" + options.Mode
	}
	return fmt.Sprintf("v%d", options.Version)
}
