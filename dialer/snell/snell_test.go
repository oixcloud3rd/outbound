package snell

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	transportTLS "github.com/daeuniverse/outbound/transport/tls"
	"github.com/stretchr/testify/require"
)

func TestParseAndExportURL(t *testing.T) {
	t.Parallel()
	tests := []string{
		"snell://password@example.com:443?version=4#plain",
		"snell://p%40ss@[2001:db8::1]:8443?version=5&reuse=true&identity=true&obfs=http&obfs-host=cdn.example#v5",
		"snell://123456789012@example.com:443?version=6&mode=unshaped&userkey=user#v6",
		"snell://password@example.com:443?version=4&obfs=ech-tls&sni=origin.example&ech-config=AAQ%2BDAAA#ech",
	}
	for _, link := range tests {
		configuration, err := ParseURL(link)
		require.NoError(t, err, link)
		exported := configuration.ExportToURL()
		reparsed, err := ParseURL(exported)
		require.NoError(t, err, exported)
		require.Equal(t, configuration, reparsed)
	}
}

func TestDefaultsAndAliases(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&echConfig=AAQ%2BDAAA&allowInsecure=false&tlsImplementation=utls&utlsImitate=chrome_auto")
	require.NoError(t, err)
	require.Equal(t, protocolSnell.Version4, configuration.Version)
	require.Equal(t, protocolSnell.IdentityDisabled, configuration.Identity)
	require.False(t, configuration.IdentityExplicit)
	require.False(t, configuration.SkipCertVerify)
	require.Equal(t, "utls", configuration.TLSImplementation)
	require.Equal(t, "chrome_auto", configuration.ClientFingerprint)
}

func TestIdentityRequiresExplicitOption(t *testing.T) {
	t.Parallel()
	base := "snell://password@example.com:443?obfs=ech-tls&ech-config=AAQ%2BDAAA"
	configuration, err := ParseURL(base)
	require.NoError(t, err)
	require.Equal(t, protocolSnell.IdentityDisabled, configuration.Identity)
	require.False(t, configuration.IdentityExplicit)

	configuration, err = ParseURL(base + "&identity=true")
	require.NoError(t, err)
	require.Equal(t, protocolSnell.IdentityV1, configuration.Identity)
	require.True(t, configuration.IdentityExplicit)
	require.Contains(t, configuration.ExportToURL(), "identity=1")
}

func TestIdentityVersionsAndAliases(t *testing.T) {
	t.Parallel()
	base := "snell://password@example.com:443?obfs=ech-tls&ech-config=AAQ%2BDAAA"
	for query, expected := range map[string]protocolSnell.IdentityVersion{
		"identity=false":     protocolSnell.IdentityDisabled,
		"identity=true":      protocolSnell.IdentityV1,
		"identity=0":         protocolSnell.IdentityDisabled,
		"identity=1":         protocolSnell.IdentityV1,
		"identity=2":         protocolSnell.IdentityV2,
		"identity-version=2": protocolSnell.IdentityV2,
	} {
		configuration, err := ParseURL(base + "&" + query)
		require.NoError(t, err, query)
		require.Equal(t, expected, configuration.Identity, query)
	}
	_, err := ParseURL(base + "&identity=1&identity-version=2")
	require.ErrorContains(t, err, "values conflict")
	_, err = ParseURL(base + "&identity=3")
	require.ErrorContains(t, err, "invalid identity")
}

func TestECHTLSModernOptions(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?version=4&reuse=true&obfs=ech-tls&ech-config=AAQ%2BDAAA&identity-version=2&protocol=oix-snell%2F1&legacy-fallback=true&preconnect=4&skip-cert-verify=false")
	require.NoError(t, err)
	require.Equal(t, protocolSnell.IdentityV2, configuration.Identity)
	require.Equal(t, snellECHTLSALPN, configuration.ALPN)
	require.True(t, configuration.LegacyFallback)
	require.Equal(t, 4, configuration.Preconnect)

	exported, err := url.Parse(configuration.ExportToURL())
	require.NoError(t, err)
	require.Equal(t, "2", exported.Query().Get("identity"))
	require.Equal(t, snellECHTLSALPN, exported.Query().Get("alpn"))
	require.Equal(t, "true", exported.Query().Get("legacy-fallback"))
	require.Equal(t, "4", exported.Query().Get("preconnect"))
}

func TestECHTLSRejectsUnsafeOrInvalidOptions(t *testing.T) {
	t.Parallel()
	base := "snell://password@example.com:443?version=4&obfs=ech-tls&ech-config=AAQ%2BDAAA"
	for _, query := range []string{
		"skip-cert-verify=true",
		"alpn=http%2F1.1",
		"alpn=snell-ech%2F1&protocol=h2",
		"identity=2&alpn=h2",
		"preconnect=1",
		"preconnect=5&reuse=true",
	} {
		_, err := ParseURL(base + "&" + query)
		require.Error(t, err, query)
	}
}

func TestRejectV6TransportOptions(t *testing.T) {
	t.Parallel()
	_, err := ParseURL("snell://123456789012@example.com:443?version=6&identity=true")
	require.ErrorContains(t, err, "version 6 cannot")
}

func TestExportEscapesECHConfig(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&ech-config=AAQ%2BDAAA")
	require.NoError(t, err)
	u, err := url.Parse(configuration.ExportToURL())
	require.NoError(t, err)
	require.Equal(t, "AAQ+DAAA", u.Query().Get("ech-config"))
}

func TestECHConfigIsValidatedAndNormalized(t *testing.T) {
	t.Parallel()
	raw := []byte{0, 5, 0xfe, 0x0d, 0, 1, 0}
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&ech-config=" +
		url.QueryEscape(base64.RawStdEncoding.EncodeToString(raw)))
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(raw), configuration.ECHConfig)

	_, err = ParseURL("snell://password@example.com:443?obfs=ech-tls&ech-config=broken")
	require.ErrorContains(t, err, "ECHConfigList")
}

func TestExplicitFalseTLSOptionSurvivesExport(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&ech-config=AAQ%2BDAAA&skip-cert-verify=false")
	require.NoError(t, err)
	require.True(t, configuration.SkipVerifyExplicit)
	require.False(t, configuration.SkipCertVerify)
	require.Contains(t, configuration.ExportToURL(), "skip-cert-verify=false")
}

func TestECHTLSUsesRawTLSAndIgnoresLegacyWebSocketOptions(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&sni=origin.example&ws-host=ws.example&path=/ws&obfs-uri=/legacy&ech-config=AAQ%2BDAAA")
	require.NoError(t, err)
	require.Empty(t, configuration.WSHost)
	require.Empty(t, configuration.Path)

	exported, err := url.Parse(configuration.ExportToURL())
	require.NoError(t, err)
	require.Empty(t, exported.Query().Get("ws-host"))
	require.Empty(t, exported.Query().Get("path"))
	require.Empty(t, exported.Query().Get("obfs-uri"))

	tlsURL := configuration.echTLSURL(&dialer.ExtraOption{}, "example.com:443", snellECHTLSLegacyALPN)
	require.Equal(t, []string{snellECHTLSLegacyALPN}, tlsURL.Query()["alpn"])
	require.Equal(t, "origin.example", tlsURL.Query().Get("sni"))
}

func TestRejectV6ECHTLSFields(t *testing.T) {
	t.Parallel()
	for _, query := range []string{
		"obfs-host=example.com",
		"skip-cert-verify=false",
		"tls-implementation=utls",
		"client-fingerprint=chrome_auto",
	} {
		_, err := ParseURL("snell://123456789012@example.com:443?version=6&" + query)
		require.ErrorContains(t, err, "version 6 cannot", query)
	}
}

func TestLegacyFallbackOnlyHandlesALPNErrors(t *testing.T) {
	t.Parallel()
	primary := &scriptedManagedDialer{dialErr: transportTLS.ErrUnexpectedALPN}
	legacy := &scriptedManagedDialer{}
	dialer, err := newLegacyFallbackDialer(primary, legacy, 0)
	require.NoError(t, err)
	_, err = dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.Equal(t, 1, legacy.dials)

	primary = &scriptedManagedDialer{dialErr: context.DeadlineExceeded}
	legacy = &scriptedManagedDialer{}
	dialer, err = newLegacyFallbackDialer(primary, legacy, 0)
	require.NoError(t, err)
	_, err = dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, legacy.dials)
}

type scriptedManagedDialer struct {
	dialErr error
	dials   int
}

func (d *scriptedManagedDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.dials++
	return nil, d.dialErr
}

func (d *scriptedManagedDialer) Start(context.Context) error { return nil }

func (d *scriptedManagedDialer) Preconnect(context.Context, int) error { return d.dialErr }

func (d *scriptedManagedDialer) Close() error { return nil }

var _ managedSnellDialer = (*scriptedManagedDialer)(nil)
