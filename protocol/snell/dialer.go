package snell

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	singSnell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	protocol.Register("snell", NewDialer)
}

type client interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	DialPacketConn(conn net.Conn) (N.NetPacketConn, error)
	Close() error
}

type preconnectClient interface {
	Preconnect(ctx context.Context, count int) error
}

const preconnectTimeout = 10 * time.Second

type Dialer struct {
	server        M.Socksaddr
	transportDial *singDialer
	client        client
	preconnect    int

	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	cancel      context.CancelFunc
	done        chan struct{}
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	options, ok := header.Feature1.(ClientOptions)
	if !ok {
		if pointer, pointerOK := header.Feature1.(*ClientOptions); pointerOK && pointer != nil {
			options = *pointer
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("snell: protocol.Header.Feature1 must contain ClientOptions")
	}
	if err := options.validate(header.Password); err != nil {
		return nil, err
	}
	server, err := parseSocksaddr(header.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("snell: invalid proxy address %q: %w", header.ProxyAddress, err)
	}
	transportDial := &singDialer{next: nextDialer, proxyAddress: header.ProxyAddress}
	dialer := &Dialer{
		server:        server,
		transportDial: transportDial,
		preconnect:    options.Preconnect,
	}
	psk := []byte(header.Password)
	userKey := []byte(options.UserKey)
	switch options.Version {
	case Version4, Version5:
		obfsMode, err := singSnell.ParseObfsMode(options.normalizedObfs())
		if err != nil {
			return nil, err
		}
		v4Client, err := snellv4.NewClient(snellv4.ClientOptions{
			PSK:      psk,
			UserKey:  userKey,
			Identity: options.Identity,
			Reuse:    options.Reuse,
			ObfsMode: obfsMode,
			ObfsHost: options.ObfsHost,
			Dialer:   transportDial,
			Server:   server,
		})
		if err != nil {
			return nil, err
		}
		dialer.client = v4Client
	case Version6:
		mode, err := snellv6.ParseMode(options.Mode)
		if err != nil {
			return nil, err
		}
		v6Client, err := snellv6.NewClient(snellv6.ClientOptions{
			PSK:     psk,
			UserKey: userKey,
			Mode:    mode,
			Reuse:   options.Reuse,
			Dialer:  transportDial,
			Server:  server,
		})
		if err != nil {
			return nil, err
		}
		dialer.client = v6Client
	}
	return dialer, nil
}

// Preconnect synchronously warms reusable Snell v4 sessions. Callers normally
// use Start so warming follows the owning dialer's lifecycle.
func (d *Dialer) Preconnect(ctx context.Context, count int) error {
	if count == 0 {
		return nil
	}
	client, ok := d.client.(preconnectClient)
	if !ok {
		return fmt.Errorf("snell: preconnect is unavailable for version 6")
	}
	return client.Preconnect(ctx, count)
}

// Start begins the optional best-effort preconnect task. It is idempotent so a
// dialer reconstructed or adopted during reload can safely receive Start more
// than once.
func (d *Dialer) Start(ctx context.Context) error {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	if d.started || d.closed {
		return nil
	}
	d.started = true
	if d.preconnect == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	preconnectCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	d.cancel = cancel
	d.done = done
	go func() {
		defer close(done)
		timeoutCtx, timeoutCancel := context.WithTimeout(preconnectCtx, preconnectTimeout)
		defer timeoutCancel()
		_ = d.Preconnect(timeoutCtx, d.preconnect)
	}()
	return nil
}

// Close stops any in-flight preconnect and releases reusable sessions.
func (d *Dialer) Close() error {
	d.lifecycleMu.Lock()
	if d.closed {
		d.lifecycleMu.Unlock()
		return nil
	}
	d.closed = true
	cancel, done := d.cancel, d.done
	d.cancel = nil
	d.done = nil
	d.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return d.client.Close()
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magic.Network != "tcp" && magic.Network != "udp" {
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, magic.Network)
	}
	destination, err := parseSocksaddr(address)
	if err != nil {
		return nil, fmt.Errorf("snell: invalid destination %q: %w", address, err)
	}
	tcpNetwork := netproxy.MagicNetwork{
		Network:   "tcp",
		Mark:      magic.Mark,
		Mptcp:     magic.Mptcp,
		IPVersion: magic.IPVersion,
	}.Encode()
	ctx = context.WithValue(ctx, magicNetworkContextKey{}, tcpNetwork)
	if magic.Network == "tcp" {
		return d.client.DialContext(ctx, destination)
	}
	rawConn, err := d.transportDial.DialContext(ctx, N.NetworkTCP, d.server)
	if err != nil {
		return nil, err
	}
	packet, err := d.client.DialPacketConn(rawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return &packetConn{upstream: packet, target: destination}, nil
}

type magicNetworkContextKey struct{}

type singDialer struct {
	next         netproxy.Dialer
	proxyAddress string
}

func (d *singDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if encoded, ok := ctx.Value(magicNetworkContextKey{}).(string); ok {
		network = encoded
	}
	conn, err := d.next.DialContext(ctx, network, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	if netConn, ok := conn.(net.Conn); ok {
		return netConn, nil
	}
	return &netproxy.FakeNetConn{Conn: conn}, nil
}

func (d *singDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: snell packet transport", netproxy.UnsupportedTunnelTypeError)
}

func parseSocksaddr(address string) (M.Socksaddr, error) {
	metadata, err := protocol.ParseMetadata(address)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.ParseSocksaddrHostPort(metadata.Hostname, metadata.Port), nil
}

type packetConn struct {
	upstream N.NetPacketConn
	target   M.Socksaddr
}

func (c *packetConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *packetConn) Write(p []byte) (int, error) {
	return c.upstream.WriteTo(p, c.target)
}

func (c *packetConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, address, err := c.upstream.ReadFrom(p)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if address == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("snell: missing UDP source")
	}
	source := M.SocksaddrFromNet(address).Unwrap()
	if !source.Addr.IsValid() {
		return 0, netip.AddrPort{}, fmt.Errorf("snell: invalid UDP source %q", address.String())
	}
	return n, source.AddrPort(), nil
}

func (c *packetConn) WriteTo(p []byte, address string) (int, error) {
	destination, err := parseSocksaddr(strings.TrimSpace(address))
	if err != nil {
		return 0, fmt.Errorf("snell: invalid UDP destination %q: %w", address, err)
	}
	return c.upstream.WriteTo(p, destination)
}

func (c *packetConn) Close() error                       { return c.upstream.Close() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.upstream.SetDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.upstream.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.upstream.SetWriteDeadline(t) }

var _ netproxy.PacketConn = (*packetConn)(nil)
