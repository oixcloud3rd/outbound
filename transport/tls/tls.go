package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/daeuniverse/outbound/pkg/coalesce"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	utls "github.com/metacubex/utls"
)

// Tls is a base Tls struct
type Tls struct {
	dialer              netproxy.Dialer
	addr                string
	serverName          string
	skipVerify          bool
	tlsImplentation     string
	utlsImitate         string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64
	snellECH            bool
	utlsSessionCache    utls.ClientSessionCache

	tlsConfig *tls.Config
}

const snellECHSessionCacheCapacity = 32

func (s *Tls) UnwrapDialer() netproxy.Dialer {
	return s.dialer
}

// NewTls returns a Tls infra.
func NewTls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewTls: %w", err)
	}

	query := u.Query()

	tlsImplentation := u.Scheme
	utlsImitate := query.Get("utlsImitate")
	if utlsImitate == "" {
		utlsImitate = query.Get("client-fingerprint")
	}
	if tlsImplentation == "" && option.TlsImplementation != "" {
		tlsImplentation = option.TlsImplementation
	}
	if tlsImplentation == "" {
		tlsImplentation = "tls"
	}
	if utlsImitate == "" {
		utlsImitate = option.UtlsImitate
	}
	if tlsImplentation == "utls" && utlsImitate == "" {
		utlsImitate = "chrome_auto"
	}
	t := &Tls{
		dialer:          nextDialer,
		addr:            u.Host,
		tlsImplentation: tlsImplentation,
		utlsImitate:     utlsImitate,
		serverName:      query.Get("sni"),
	}
	if t.tlsImplentation == "utls" {
		// Fail an unknown fingerprint at construction time instead of on
		// every dial, after the underlay connection was already established.
		if _, err := nameToUtlsClientHelloID(utlsImitate); err != nil {
			return nil, nil, fmt.Errorf("NewTls: %w", err)
		}
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}
	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))
	t.snellECH, _, err = optionalBool(query, "snell-ech")
	if err != nil {
		return nil, nil, err
	}

	// skipVerify
	allowInsecure, explicit, err := optionalBool(query,
		"skip-cert-verify", "allowInsecure", "allow_insecure", "allowinsecure", "skipVerify", "insecure")
	if err != nil {
		return nil, nil, err
	}
	if !explicit {
		allowInsecure = option.AllowInsecure
	}
	t.skipVerify = allowInsecure
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}
	if len(query.Get("alpn")) > 0 {
		t.tlsConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
	}
	echConfig := query.Get("ech-config")
	if echConfig == "" {
		echConfig = query.Get("echConfig")
	}
	if echConfig != "" {
		decoded, err := DecodeECHConfigList(echConfig)
		if err != nil {
			return nil, nil, err
		}
		t.tlsConfig.MinVersion = tls.VersionTLS13
		t.tlsConfig.EncryptedClientHelloConfigList = decoded
	}
	if t.snellECH {
		if len(t.tlsConfig.EncryptedClientHelloConfigList) == 0 {
			return nil, nil, fmt.Errorf("Snell ECH-TLS requires ech-config")
		}
		t.tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(snellECHSessionCacheCapacity)
		t.tlsConfig.Renegotiation = tls.RenegotiateNever
		t.utlsSessionCache = utls.NewLRUClientSessionCache(snellECHSessionCacheCapacity)
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: tlsImplentation,
		Link:     link,
	}, nil
}

// DecodeECHConfigList decodes a standard padded or unpadded Base64 ECHConfigList
// and validates its outer vector framing.
func DecodeECHConfigList(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid ECHConfigList base64: %w", err)
	}
	if len(decoded) < 2 {
		return nil, fmt.Errorf("invalid ECHConfigList: too short")
	}
	declared := int(binary.BigEndian.Uint16(decoded[:2]))
	if declared == 0 || declared != len(decoded)-2 {
		return nil, fmt.Errorf("invalid ECHConfigList length: declared %d, actual %d", declared, len(decoded)-2)
	}
	if declared < 4 {
		return nil, fmt.Errorf("invalid ECHConfigList: empty config list")
	}
	return decoded, nil
}

func optionalBool(values url.Values, keys ...string) (bool, bool, error) {
	for _, key := range keys {
		list, ok := values[key]
		if !ok || len(list) == 0 {
			continue
		}
		if list[0] == "" {
			return false, true, nil
		}
		value, err := strconv.ParseBool(list[0])
		if err != nil {
			return false, true, fmt.Errorf("invalid boolean %q for %s", list[0], key)
		}
		return value, true, nil
	}
	return false, false, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			netproxy.Conn
			Handshake() error
		}

		// Coalesce the TLS records of one write burst into one socket
		// write. Both crypto/tls and utls issue one underlying Write per
		// record; on bulk relay paths that is ~3 write syscalls per 32KB.
		co := coalesce.New(&netproxy.FakeNetConn{
			Conn:  rc,
			LAddr: nil,
			RAddr: nil,
		})

		switch s.tlsImplentation {
		case "tls":
			tlsConn = tls.Client(co, s.tlsConfig)

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				// rc was dialed above and is owned by this call.
				_ = rc.Close()
				return nil, err
			}

			uConfig := uTLSConfigFromTLSConfig(s.tlsConfig)
			if s.snellECH {
				configureUTLSSnellECH(uConfig, s.utlsSessionCache)
			}
			if s.snellECH {
				tlsConn = &utlsConnWrapper{
					UConn:         utls.UClient(co, uConfig, *clientHelloID),
					nextProtocols: append([]string(nil), uConfig.NextProtos...),
					snellECH:      true,
				}
			} else {
				utlsConn, err := newUTLSClient(co, uConfig, *clientHelloID)
				if err != nil {
					_ = rc.Close()
					return nil, err
				}
				tlsConn = &utlsConnWrapper{UConn: utlsConn}
			}

		default:
			_ = rc.Close()
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		// The handshake writes through the coalescer; a read that blocks on
		// the peer flushes it, but push it out now so the first application
		// write ordering is deterministic.
		if err := co.Flush(); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		// Flush after every protocol Write so unmanaged Write/Read users
		// never observe stalled records.
		return coalesce.NewFlushConn(tlsConn, co), nil
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
