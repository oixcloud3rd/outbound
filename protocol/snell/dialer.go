package snell

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("snell", NewDialer)
}

type Dialer struct {
	next         netproxy.Dialer
	proxyAddress string
	psk          []byte
	options      ClientOptions
	v4Pool       *v4Pool
	v6Mode       v6Mode
	v6Pool       *v6Pool
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
	dialer := &Dialer{
		next:         nextDialer,
		proxyAddress: header.ProxyAddress,
		psk:          []byte(header.Password),
		options:      options,
	}
	if options.Reuse && (options.Version == Version4 || options.Version == Version5) {
		dialer.v4Pool = &v4Pool{create: dialer.newV4Record}
	}
	if options.Version == Version6 {
		mode, err := parseV6Mode(options.Mode)
		if err != nil {
			return nil, err
		}
		dialer.v6Mode = mode
		if options.Reuse {
			dialer.v6Pool = &v6Pool{create: dialer.newV6Record}
		}
	}
	return dialer, nil
}

func (d *Dialer) newV6Record(ctx context.Context, network string) (*v6RecordConn, error) {
	conn, err := d.next.DialContext(ctx, network, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return newV6RecordConn(conn, d.psk, d.v6Mode), nil
}

func (d *Dialer) newV4Record(ctx context.Context, network string) (*v4RecordConn, error) {
	conn, err := d.next.DialContext(ctx, network, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return newV4RecordConn(conn, d.psk, d.options.Identity), nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magic, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magic.Network != "tcp" && magic.Network != "udp" {
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, magic.Network)
	}
	tcpNetwork := netproxy.MagicNetwork{Network: "tcp", Mark: magic.Mark, Mptcp: magic.Mptcp}.Encode()
	if d.options.Version == Version6 {
		return d.dialV6(ctx, tcpNetwork, magic.Network, address)
	}
	if magic.Network == "udp" {
		record, err := d.newV4Record(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		packetConn, err := newV4PacketConn(record, d.options.UserKey, address)
		if err != nil {
			_ = record.Close()
			return nil, err
		}
		return packetConn, nil
	}
	destination, err := protocol.ParseMetadata(address)
	if err != nil {
		return nil, err
	}
	command := commandConnect
	if d.options.Reuse {
		command = commandConnectV2
	}
	request, err := makeTCPRequest(d.options.UserKey, destination, command)
	if err != nil {
		return nil, err
	}
	if d.v4Pool == nil {
		record, err := d.newV4Record(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if _, err = record.Write(request); err != nil {
			_ = record.Close()
			return nil, err
		}
		return &v4ClientConn{record: record, nonReusable: true}, nil
	}
	for attempts := 0; attempts < 2; attempts++ {
		record, uses, err := d.v4Pool.get(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if _, err = record.Write(request); err != nil {
			_ = record.Close()
			continue
		}
		return &v4ClientConn{record: record, pool: d.v4Pool, uses: uses}, nil
	}
	return nil, fmt.Errorf("snell: failed to reuse connection")
}

func (d *Dialer) dialV6(ctx context.Context, tcpNetwork, network, address string) (netproxy.Conn, error) {
	if network == "udp" {
		record, err := d.newV6Record(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		packetConn, err := newV6PacketConn(record, d.options.UserKey, address)
		if err != nil {
			_ = record.Close()
			return nil, err
		}
		return packetConn, nil
	}
	destination, err := protocol.ParseMetadata(address)
	if err != nil {
		return nil, err
	}
	request, err := makeTCPRequest(d.options.UserKey, destination, commandConnectV2)
	if err != nil {
		return nil, err
	}
	if d.v6Pool == nil {
		record, err := d.newV6Record(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if _, err = record.Write(request); err != nil {
			_ = record.Close()
			return nil, err
		}
		return &v6ClientConn{record: record, nonReusable: true}, nil
	}
	for attempts := 0; attempts < 2; attempts++ {
		record, uses, err := d.v6Pool.get(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if _, err = record.Write(request); err != nil {
			_ = record.Close()
			continue
		}
		return &v6ClientConn{record: record, pool: d.v6Pool, uses: uses}, nil
	}
	return nil, fmt.Errorf("snell: failed to reuse version 6 connection")
}
