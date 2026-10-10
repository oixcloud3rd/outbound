package snell

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// Partition both Snell reuse pools and QUIC sessions by underlay routing
// parameters. A reused Snell connection otherwise bypasses transport dialing.
type http3SnellDialer struct {
	mu      sync.Mutex
	closed  bool
	routes  map[string]managedSnellDialer
	config  Snell
	option  dialer.ExtraOption
	next    netproxy.Dialer
	address string
}

func newHTTP3SnellDialer(s *Snell, option *dialer.ExtraOption, next netproxy.Dialer, address string) (*http3SnellDialer, error) {
	d := &http3SnellDialer{
		config: *s, next: next, address: address,
		routes: make(map[string]managedSnellDialer),
	}
	if option != nil {
		d.option = *option
	}
	if _, err := d.route("tcp"); err != nil {
		return nil, err
	}
	cc, unsupported, _ := s.http3CongestionControl()
	if unsupported {
		logrus.WithField("cc", cc).Warn("snell: unsupported congestion_control; using default")
	}
	return d, nil
}

func (d *http3SnellDialer) route(network string) (managedSnellDialer, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magic.Network != "tcp" && magic.Network != "udp" {
		return nil, netproxy.UnsupportedTunnelTypeError
	}
	magic.Network = "tcp"
	key := magic.Encode()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if existing := d.routes[key]; existing != nil {
		return existing, nil
	}
	alpn := d.config.ALPN
	if alpn == "" {
		alpn = snellECHTLSALPN
	}
	result, err := d.config.newProtocolDialer(&d.option, &routeDialer{next: d.next, route: *magic},
		d.address, alpn, d.config.Identity, d.config.Preconnect)
	if err != nil {
		return nil, err
	}
	managed := result.(managedSnellDialer)
	d.routes[key] = managed
	return managed, nil
}

func (d *http3SnellDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	route, err := d.route(network)
	if err != nil {
		return nil, err
	}
	return route.DialContext(ctx, network, address)
}

func (d *http3SnellDialer) Start(ctx context.Context) error {
	route, err := d.route("tcp")
	if err != nil {
		return err
	}
	return route.Start(ctx)
}

func (d *http3SnellDialer) Preconnect(ctx context.Context, count int) error {
	route, err := d.route("tcp")
	if err != nil {
		return err
	}
	return route.Preconnect(ctx, count)
}

func (d *http3SnellDialer) Close() error {
	d.mu.Lock()
	d.closed = true
	routes := d.routes
	d.routes = nil
	d.mu.Unlock()
	var err error
	for _, route := range routes {
		err = errors.Join(err, route.Close())
	}
	return err
}

type ownedHTTP3Dialer struct {
	managedSnellDialer
	transport *http3Dialer
}

func (d *ownedHTTP3Dialer) Close() error {
	// Cancel in-flight transport work before waiting for Snell preconnect.
	return errors.Join(d.transport.Close(), d.managedSnellDialer.Close())
}

type routeDialer struct {
	next  netproxy.Dialer
	route netproxy.MagicNetwork
}

func (d *routeDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	route := d.route
	route.Network = magic.Network
	if route.Network == "udp" {
		route.Mptcp = false
	}
	return d.next.DialContext(ctx, route.Encode(), address)
}
