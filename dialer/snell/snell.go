package snell

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	transportTLS "github.com/daeuniverse/outbound/transport/tls"
	"github.com/daeuniverse/outbound/transport/ws"
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
	Identity           bool
	IdentityExplicit   bool
	SNI                string
	WSHost             string
	Path               string
	ECHConfig          string
	SkipCertVerify     bool
	SkipVerifyExplicit bool
	TLSImplementation  string
	ClientFingerprint  string
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
	identityValue, identityExplicit := firstQuery(query, "identity")
	identity := false
	if identityExplicit {
		identity, err = strconv.ParseBool(identityValue)
		if err != nil {
			return nil, fmt.Errorf("snell: invalid identity value %q", identityValue)
		}
	}
	reuse, err := parseBool(query, false, "reuse")
	if err != nil {
		return nil, err
	}
	skipVerify, skipVerifyExplicit, err := parseBoolWithPresence(query, false,
		"skip-cert-verify", "allowInsecure", "allow_insecure", "skipVerify", "insecure")
	if err != nil {
		return nil, err
	}
	tlsImplementation, _ := firstQuery(query, "tls-implementation", "tlsImplementation")
	clientFingerprint, _ := firstQuery(query, "client-fingerprint", "utlsImitate", "fp")
	path, _ := firstQuery(query, "path", "obfs-uri")
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
		SNI:                query.Get("sni"),
		WSHost:             query.Get("ws-host"),
		Path:               path,
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
		if s.Obfs != "none" || s.ObfsHost != "" || s.Identity || s.IdentityExplicit ||
			s.ECHConfig != "" || s.SNI != "" || s.WSHost != "" || s.Path != "" ||
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
		if s.Path == "" || !strings.HasPrefix(s.Path, "/") {
			return fmt.Errorf("snell: ECH-TLS requires a WebSocket path beginning with '/'")
		}
		if s.ECHConfig == "" {
			return fmt.Errorf("snell: ECH-TLS requires ech-config")
		}
		if s.TLSImplementation != "" && s.TLSImplementation != "tls" && s.TLSImplementation != "utls" {
			return fmt.Errorf("snell: unsupported TLS implementation %q", s.TLSImplementation)
		}
	} else if s.ECHConfig != "" || s.SNI != "" || s.WSHost != "" || s.Path != "" ||
		s.SkipVerifyExplicit || s.TLSImplementation != "" || s.ClientFingerprint != "" {
		return fmt.Errorf("snell: ECH-TLS parameters require obfs=ech-tls")
	}
	return nil
}

func (s *Snell) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	current := nextDialer
	var err error
	if s.Obfs == "ech-tls" {
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
		tlsQuery.Set("alpn", "http/1.1")
		skipCertVerify := option.AllowInsecure
		if s.SkipVerifyExplicit {
			skipCertVerify = s.SkipCertVerify
		}
		tlsQuery.Set("allowInsecure", common.BoolToString(skipCertVerify))
		if fingerprint != "" {
			tlsQuery.Set("utlsImitate", fingerprint)
		}
		tlsURL.RawQuery = tlsQuery.Encode()
		current, _, err = transportTLS.NewTls(option, current, tlsURL.String())
		if err == nil {
			wsHost := s.WSHost
			if wsHost == "" {
				wsHost = sni
			}
			wsURL := &url.URL{Scheme: "ws", Host: address, Path: s.Path}
			wsQuery := wsURL.Query()
			wsQuery.Set("host", wsHost)
			wsURL.RawQuery = wsQuery.Encode()
			current, _, err = ws.NewWs(option, current, wsURL.String())
		}
	}
	if err != nil {
		return nil, nil, err
	}
	protocolObfs := s.Obfs
	if protocolObfs == "ech-tls" {
		protocolObfs = "none"
	}
	current, err = protocol.NewDialer("snell", current, protocol.Header{
		ProxyAddress: address,
		Password:     s.PSK,
		IsClient:     true,
		Feature1: protocolSnell.ClientOptions{
			Version:  s.Version,
			UserKey:  s.UserKey,
			Reuse:    s.Reuse,
			Identity: s.Identity,
			Mode:     s.Mode,
			Obfs:     protocolObfs,
			ObfsHost: s.ObfsHost,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return current, &dialer.Property{Name: s.Name, Address: address, Protocol: "snell", Link: s.ExportToURL()}, nil
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
			query.Set("identity", strconv.FormatBool(s.Identity))
		}
	}
	if s.Obfs == "ech-tls" {
		query.Set("path", s.Path)
		query.Set("ech-config", s.ECHConfig)
		if s.SNI != "" {
			query.Set("sni", s.SNI)
		}
		if s.WSHost != "" {
			query.Set("ws-host", s.WSHost)
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

func firstQuery(values url.Values, keys ...string) (string, bool) {
	for _, key := range keys {
		if list, ok := values[key]; ok && len(list) > 0 {
			return list[0], true
		}
	}
	return "", false
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
