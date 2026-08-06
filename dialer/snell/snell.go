package snell

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	transportTLS "github.com/daeuniverse/outbound/transport/tls"
)

const (
	snellECHTLSALPN         = "snell-ech/1"
	snellECHTLSPreviousALPN = "oix-snell/1"
	snellECHTLSLegacyALPN   = "h2"
	snellPreconnectTimeout  = 10 * time.Second
)

func init() {
	dialer.FromLinkRegister("snell", NewSnell)
}

type Snell struct {
	Name               string
	Server             string
	Port               int
	PSK                string
	Version            int
	UserKey            string
	Reuse              bool
	Obfs               string
	ObfsHost           string
	Mode               string
	Identity           protocolSnell.IdentityVersion
	IdentityExplicit   bool
	ALPN               string
	LegacyFallback     bool
	Preconnect         int
	SNI                string
	ECHConfig          string
	SkipCertVerify     bool
	SkipVerifyExplicit bool
	TLSImplementation  string
	ClientFingerprint  string

	// Deprecated: raw ECH-TLS does not use a WebSocket Host header.
	WSHost string
	// Deprecated: raw ECH-TLS does not use a WebSocket path.
	Path string
}

func NewSnell(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	configuration, err := ParseURL(link)
	if err != nil {
		return nil, nil, err
	}
	return configuration.Dialer(option, nextDialer)
}

func ParseURL(link string) (*Snell, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("snell: parse URL: %w", err)
	}
	if u.Scheme != "snell" {
		return nil, dialer.InvalidParameterErr
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("snell: invalid port")
	}
	query := u.Query()
	version := protocolSnell.Version4
	if value := query.Get("version"); value != "" {
		version, err = strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("snell: invalid version %q", value)
		}
	}
	obfs := strings.ToLower(query.Get("obfs"))
	if obfs == "" {
		obfs = "none"
	}
	identity, identityExplicit, err := parseIdentity(query)
	if err != nil {
		return nil, err
	}
	reuse, err := parseBool(query, false, "reuse")
	if err != nil {
		return nil, err
	}
	legacyFallback, err := parseBool(query, false, "legacy-fallback")
	if err != nil {
		return nil, err
	}
	preconnect, err := parseInt(query, 0, "preconnect")
	if err != nil {
		return nil, err
	}
	alpn, err := resolveSnellECHTLSALPN(query.Get("alpn"), query.Get("protocol"))
	if err != nil {
		return nil, err
	}
	if legacyFallback && alpn == "" {
		alpn = snellECHTLSALPN
	}
	skipVerify, skipVerifyExplicit, err := parseBoolWithPresence(query, false,
		"skip-cert-verify", "allowInsecure", "allow_insecure", "skipVerify", "insecure")
	if err != nil {
		return nil, err
	}
	tlsImplementation, _ := firstQuery(query, "tls-implementation", "tlsImplementation")
	clientFingerprint, _ := firstQuery(query, "client-fingerprint", "utlsImitate", "fp")
	configuration := &Snell{
		Name:               u.Fragment,
		Server:             u.Hostname(),
		Port:               port,
		PSK:                u.User.Username(),
		Version:            version,
		UserKey:            query.Get("userkey"),
		Reuse:              reuse,
		Obfs:               obfs,
		ObfsHost:           query.Get("obfs-host"),
		Mode:               query.Get("mode"),
		Identity:           identity,
		IdentityExplicit:   identityExplicit,
		ALPN:               alpn,
		LegacyFallback:     legacyFallback,
		Preconnect:         preconnect,
		SNI:                query.Get("sni"),
		ECHConfig:          firstValue(query, "ech-config", "echConfig"),
		SkipCertVerify:     skipVerify,
		SkipVerifyExplicit: skipVerifyExplicit,
		TLSImplementation:  tlsImplementation,
		ClientFingerprint:  clientFingerprint,
	}
	if configuration.ECHConfig != "" {
		decoded, decodeErr := transportTLS.DecodeECHConfigList(configuration.ECHConfig)
		if decodeErr != nil {
			return nil, decodeErr
		}
		configuration.ECHConfig = base64.StdEncoding.EncodeToString(decoded)
	}
	if err := configuration.validate(); err != nil {
		return nil, err
	}
	return configuration, nil
}

func (s *Snell) validate() error {
	if s.Server == "" || s.PSK == "" {
		return fmt.Errorf("snell: server and PSK are required")
	}
	if len(s.UserKey) > 255 {
		return fmt.Errorf("snell: user key is longer than 255 bytes")
	}
	if s.Identity > protocolSnell.IdentityV2 {
		return fmt.Errorf("snell: identity must be between 0 and 2")
	}
	if s.Preconnect < 0 || s.Preconnect > 4 {
		return fmt.Errorf("snell: preconnect must be between 0 and 4")
	}
	switch s.Version {
	case protocolSnell.Version4, protocolSnell.Version5:
		if s.Mode != "" {
			return fmt.Errorf("snell: mode is only valid for version 6")
		}
		switch s.Obfs {
		case "none", "http", "tls", "ech-tls":
		default:
			return fmt.Errorf("snell: unsupported obfs %q", s.Obfs)
		}
	case protocolSnell.Version6:
		if len(s.PSK) < 12 || len(s.PSK) > 255 {
			return fmt.Errorf("snell: version 6 PSK length must be between 12 and 255 bytes")
		}
		if s.Obfs != "none" || s.ObfsHost != "" || s.Identity != protocolSnell.IdentityDisabled || s.IdentityExplicit ||
			s.ALPN != "" || s.LegacyFallback || s.Preconnect != 0 ||
			s.ECHConfig != "" || s.SNI != "" ||
			s.SkipVerifyExplicit || s.TLSImplementation != "" || s.ClientFingerprint != "" {
			return fmt.Errorf("snell: version 6 cannot be combined with obfs, identity, or ECH-TLS")
		}
		switch s.Mode {
		case "", "default", "unshaped", "unsafe-raw":
		default:
			return fmt.Errorf("snell: unsupported version 6 mode %q", s.Mode)
		}
	default:
		return fmt.Errorf("snell: unsupported version %d", s.Version)
	}
	if s.Obfs == "ech-tls" {
		if s.ECHConfig == "" {
			return fmt.Errorf("snell: ECH-TLS requires ech-config")
		}
		if s.TLSImplementation != "" && s.TLSImplementation != "tls" && s.TLSImplementation != "utls" {
			return fmt.Errorf("snell: unsupported TLS implementation %q", s.TLSImplementation)
		}
		if s.SkipCertVerify {
			return fmt.Errorf("snell: %s requires certificate verification", snellECHTLSALPN)
		}
		if s.Identity == protocolSnell.IdentityV2 && s.ALPN == snellECHTLSLegacyALPN {
			return fmt.Errorf("snell: identity v2 with h2 requires legacy-fallback from %s", snellECHTLSALPN)
		}
		if s.LegacyFallback && s.ALPN != snellECHTLSALPN {
			return fmt.Errorf("snell: legacy-fallback requires alpn=%s", snellECHTLSALPN)
		}
		if s.Preconnect > 0 && !s.Reuse {
			return fmt.Errorf("snell: preconnect requires ECH-TLS and reuse")
		}
	} else if s.ECHConfig != "" || s.SNI != "" ||
		s.SkipVerifyExplicit || s.TLSImplementation != "" || s.ClientFingerprint != "" ||
		s.ALPN != "" || s.LegacyFallback || s.Preconnect != 0 || s.Identity == protocolSnell.IdentityV2 {
		return fmt.Errorf("snell: ECH-TLS parameters require obfs=ech-tls")
	}
	return nil
}

func (s *Snell) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	primaryALPN := s.ALPN
	if s.Obfs == "ech-tls" && primaryALPN == "" {
		// Preserve the implicit h2 behavior of existing direct share links.
		primaryALPN = snellECHTLSLegacyALPN
	}
	primary, err := s.newProtocolDialer(option, nextDialer, address, primaryALPN, s.Identity, s.Preconnect)
	if err != nil {
		return nil, nil, err
	}
	current := primary
	if s.LegacyFallback {
		legacyIdentity := s.Identity
		if legacyIdentity == protocolSnell.IdentityV2 {
			legacyIdentity = protocolSnell.IdentityV1
		}
		legacy, legacyErr := s.newProtocolDialer(option, nextDialer, address, snellECHTLSLegacyALPN, legacyIdentity, 0)
		if legacyErr != nil {
			_ = closeDialer(primary)
			return nil, nil, legacyErr
		}
		current, err = newLegacyFallbackDialer(primary, legacy, s.Preconnect)
		if err != nil {
			_ = closeDialer(primary)
			_ = closeDialer(legacy)
			return nil, nil, err
		}
	}
	return current, &dialer.Property{Name: s.Name, Address: address, Protocol: "snell", Link: s.ExportToURL()}, nil
}

func (s *Snell) newProtocolDialer(
	option *dialer.ExtraOption,
	nextDialer netproxy.Dialer,
	address string,
	alpn string,
	identity protocolSnell.IdentityVersion,
	preconnect int,
) (netproxy.Dialer, error) {
	current := nextDialer
	protocolObfs := s.Obfs
	if s.Obfs == "ech-tls" {
		tlsURL := s.echTLSURL(option, address, alpn)
		var err error
		current, _, err = transportTLS.NewTls(option, current, tlsURL.String())
		if err != nil {
			return nil, err
		}
		current = &echTLSDialer{Dialer: current, alpn: alpn}
		protocolObfs = "none"
	}
	return protocol.NewDialer("snell", current, protocol.Header{
		ProxyAddress: address,
		Password:     s.PSK,
		IsClient:     true,
		Feature1: protocolSnell.ClientOptions{
			Version:    s.Version,
			UserKey:    s.UserKey,
			Reuse:      s.Reuse,
			Identity:   identity,
			Preconnect: preconnect,
			ECHTLS:     s.Obfs == "ech-tls",
			Mode:       s.Mode,
			Obfs:       protocolObfs,
			ObfsHost:   s.ObfsHost,
		},
	})
}

func (s *Snell) ExportToURL() string {
	u := &url.URL{
		Scheme:   "snell",
		User:     url.User(s.PSK),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	query := u.Query()
	query.Set("version", strconv.Itoa(s.Version))
	if s.UserKey != "" {
		query.Set("userkey", s.UserKey)
	}
	if s.Reuse {
		query.Set("reuse", "true")
	}
	if s.Version == protocolSnell.Version6 {
		if s.Mode != "" && s.Mode != "default" {
			query.Set("mode", s.Mode)
		}
	} else {
		if s.Obfs != "" && s.Obfs != "none" {
			query.Set("obfs", s.Obfs)
		}
		if s.ObfsHost != "" {
			query.Set("obfs-host", s.ObfsHost)
		}
		if s.IdentityExplicit {
			query.Set("identity", strconv.Itoa(int(s.Identity)))
		}
	}
	if s.Obfs == "ech-tls" {
		query.Set("ech-config", s.ECHConfig)
		if s.ALPN != "" {
			query.Set("alpn", s.ALPN)
		}
		if s.LegacyFallback {
			query.Set("legacy-fallback", "true")
		}
		if s.Preconnect != 0 {
			query.Set("preconnect", strconv.Itoa(s.Preconnect))
		}
		if s.SNI != "" {
			query.Set("sni", s.SNI)
		}
		if s.SkipVerifyExplicit {
			query.Set("skip-cert-verify", strconv.FormatBool(s.SkipCertVerify))
		}
		if s.TLSImplementation != "" {
			query.Set("tls-implementation", s.TLSImplementation)
		}
		if s.ClientFingerprint != "" {
			query.Set("client-fingerprint", s.ClientFingerprint)
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *Snell) echTLSURL(option *dialer.ExtraOption, address, alpn string) *url.URL {
	tlsImplementation := s.TLSImplementation
	if tlsImplementation == "" {
		tlsImplementation = option.TlsImplementation
	}
	if tlsImplementation == "" {
		tlsImplementation = "tls"
	}
	sni := s.SNI
	if sni == "" {
		sni = s.ObfsHost
	}
	if sni == "" {
		sni = s.Server
	}
	fingerprint := s.ClientFingerprint
	if fingerprint == "" {
		fingerprint = option.UtlsImitate
	}
	tlsURL := &url.URL{Scheme: tlsImplementation, Host: address}
	tlsQuery := tlsURL.Query()
	tlsQuery.Set("sni", sni)
	tlsQuery.Set("ech-config", s.ECHConfig)
	tlsQuery.Set("alpn", alpn)
	tlsQuery.Set("allowInsecure", common.BoolToString(false))
	tlsQuery.Set("snell-ech", "true")
	if fingerprint != "" {
		tlsQuery.Set("utlsImitate", fingerprint)
	}
	tlsURL.RawQuery = tlsQuery.Encode()
	return tlsURL
}

type echTLSDialer struct {
	netproxy.Dialer
	alpn string
}

func (d *echTLSDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err = transportTLS.ValidateECHConnection(conn, d.alpn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type managedSnellDialer interface {
	netproxy.Dialer
	Start(context.Context) error
	Preconnect(context.Context, int) error
	Close() error
}

type legacyFallbackDialer struct {
	primary managedSnellDialer
	legacy  managedSnellDialer
	count   int

	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	cancel      context.CancelFunc
	done        chan struct{}
}

func newLegacyFallbackDialer(primary, legacy netproxy.Dialer, count int) (netproxy.Dialer, error) {
	primaryManaged, primaryOK := primary.(managedSnellDialer)
	legacyManaged, legacyOK := legacy.(managedSnellDialer)
	if !primaryOK || !legacyOK {
		return nil, errors.New("snell: legacy fallback dialers do not support lifecycle management")
	}
	return &legacyFallbackDialer{
		primary: primaryManaged,
		legacy:  legacyManaged,
		count:   count,
	}, nil
}

func (d *legacyFallbackDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	conn, err := d.primary.DialContext(ctx, network, address)
	if err == nil || !transportTLS.IsALPNCompatibilityError(err) {
		return conn, err
	}
	return d.legacy.DialContext(ctx, network, address)
}

func (d *legacyFallbackDialer) Preconnect(ctx context.Context, count int) error {
	err := d.primary.Preconnect(ctx, count)
	if err == nil || !transportTLS.IsALPNCompatibilityError(err) {
		return err
	}
	return d.legacy.Preconnect(ctx, count)
}

func (d *legacyFallbackDialer) Start(ctx context.Context) error {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	if d.started || d.closed {
		return nil
	}
	d.started = true
	if d.count == 0 {
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
		timeoutCtx, timeoutCancel := context.WithTimeout(preconnectCtx, snellPreconnectTimeout)
		defer timeoutCancel()
		_ = d.Preconnect(timeoutCtx, d.count)
	}()
	return nil
}

func (d *legacyFallbackDialer) Close() error {
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
	return errors.Join(d.primary.Close(), d.legacy.Close())
}

func closeDialer(dialer netproxy.Dialer) error {
	if closer, ok := dialer.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func parseIdentity(values url.Values) (protocolSnell.IdentityVersion, bool, error) {
	identityValue, identityExplicit := firstQuery(values, "identity")
	versionValue, versionExplicit := firstQuery(values, "identity-version")
	identity := protocolSnell.IdentityDisabled
	var err error
	if identityExplicit {
		identity, err = parseIdentityValue(identityValue, true)
		if err != nil {
			return 0, true, err
		}
	}
	if versionExplicit {
		version, versionErr := parseIdentityValue(versionValue, false)
		if versionErr != nil {
			return 0, true, versionErr
		}
		if identityExplicit && version != identity {
			return 0, true, fmt.Errorf("snell: identity and identity-version values conflict")
		}
		identity = version
	}
	return identity, identityExplicit || versionExplicit, nil
}

func parseIdentityValue(value string, allowBool bool) (protocolSnell.IdentityVersion, error) {
	if allowBool {
		if parsed, err := strconv.ParseBool(value); err == nil {
			if parsed {
				return protocolSnell.IdentityV1, nil
			}
			return protocolSnell.IdentityDisabled, nil
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed > 2 {
		return 0, fmt.Errorf("snell: invalid identity value %q", value)
	}
	return protocolSnell.IdentityVersion(parsed), nil
}

func resolveSnellECHTLSALPN(alpn, protocol string) (string, error) {
	if protocol == snellECHTLSPreviousALPN {
		protocol = snellECHTLSALPN
	}
	if alpn == snellECHTLSPreviousALPN {
		alpn = snellECHTLSALPN
	}
	if alpn != "" && protocol != "" && alpn != protocol {
		return "", fmt.Errorf("snell: ECH-TLS alpn and protocol values conflict")
	}
	if alpn == "" {
		alpn = protocol
	}
	if alpn != "" && alpn != snellECHTLSALPN && alpn != snellECHTLSLegacyALPN {
		return "", fmt.Errorf("snell: unsupported ECH-TLS ALPN %q", alpn)
	}
	return alpn, nil
}

func firstQuery(values url.Values, keys ...string) (string, bool) {
	for _, key := range keys {
		if list, ok := values[key]; ok && len(list) > 0 {
			return list[0], true
		}
	}
	return "", false
}

func parseInt(values url.Values, fallback int, key string) (int, error) {
	value, ok := firstQuery(values, key)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("snell: invalid %s value %q", key, value)
	}
	return parsed, nil
}

func firstValue(values url.Values, keys ...string) string {
	value, _ := firstQuery(values, keys...)
	return value
}

func parseBool(values url.Values, fallback bool, keys ...string) (bool, error) {
	parsed, _, err := parseBoolWithPresence(values, fallback, keys...)
	return parsed, err
}

func parseBoolWithPresence(values url.Values, fallback bool, keys ...string) (bool, bool, error) {
	value, ok := firstQuery(values, keys...)
	if !ok || value == "" {
		return fallback, ok, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, true, fmt.Errorf("snell: invalid boolean %q", value)
	}
	return parsed, true, nil
}
