package snell

import (
	"encoding/base64"
	"net/url"
	"testing"

	protocolSnell "github.com/daeuniverse/outbound/protocol/snell"
	"github.com/stretchr/testify/require"
)

func TestParseAndExportURL(t *testing.T) {
	t.Parallel()
	tests := []string{
		"snell://password@example.com:443?version=4#plain",
		"snell://p%40ss@[2001:db8::1]:8443?version=5&reuse=true&identity=true&obfs=http&obfs-host=cdn.example#v5",
		"snell://123456789012@example.com:443?version=6&mode=unshaped&userkey=user#v6",
		"snell://password@example.com:443?version=4&obfs=ech-tls&sni=origin.example&ws-host=ws.example&path=%2Fsnell&ech-config=AAQ%2BDAAA#ech",
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
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&path=/ws&echConfig=AAQ%2BDAAA&allowInsecure=true&tlsImplementation=utls&utlsImitate=chrome_auto")
	require.NoError(t, err)
	require.Equal(t, protocolSnell.Version4, configuration.Version)
	require.False(t, configuration.Identity)
	require.False(t, configuration.IdentityExplicit)
	require.True(t, configuration.SkipCertVerify)
	require.Equal(t, "utls", configuration.TLSImplementation)
	require.Equal(t, "chrome_auto", configuration.ClientFingerprint)
}

func TestIdentityRequiresExplicitOption(t *testing.T) {
	t.Parallel()
	base := "snell://password@example.com:443?obfs=ech-tls&path=/ws&ech-config=AAQ%2BDAAA"
	configuration, err := ParseURL(base)
	require.NoError(t, err)
	require.False(t, configuration.Identity)
	require.False(t, configuration.IdentityExplicit)

	configuration, err = ParseURL(base + "&identity=true")
	require.NoError(t, err)
	require.True(t, configuration.Identity)
	require.True(t, configuration.IdentityExplicit)
	require.Contains(t, configuration.ExportToURL(), "identity=true")
}

func TestRejectV6TransportOptions(t *testing.T) {
	t.Parallel()
	_, err := ParseURL("snell://123456789012@example.com:443?version=6&identity=true")
	require.ErrorContains(t, err, "version 6 cannot")
}

func TestExportEscapesECHConfig(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&path=/ws&ech-config=AAQ%2BDAAA")
	require.NoError(t, err)
	u, err := url.Parse(configuration.ExportToURL())
	require.NoError(t, err)
	require.Equal(t, "AAQ+DAAA", u.Query().Get("ech-config"))
}

func TestECHConfigIsValidatedAndNormalized(t *testing.T) {
	t.Parallel()
	raw := []byte{0, 5, 0xfe, 0x0d, 0, 1, 0}
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&path=/ws&ech-config=" +
		url.QueryEscape(base64.RawStdEncoding.EncodeToString(raw)))
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(raw), configuration.ECHConfig)

	_, err = ParseURL("snell://password@example.com:443?obfs=ech-tls&path=/ws&ech-config=broken")
	require.ErrorContains(t, err, "ECHConfigList")
}

func TestExplicitFalseTLSOptionSurvivesExport(t *testing.T) {
	t.Parallel()
	configuration, err := ParseURL("snell://password@example.com:443?obfs=ech-tls&path=/ws&ech-config=AAQ%2BDAAA&skip-cert-verify=false")
	require.NoError(t, err)
	require.True(t, configuration.SkipVerifyExplicit)
	require.False(t, configuration.SkipCertVerify)
	require.Contains(t, configuration.ExportToURL(), "skip-cert-verify=false")
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
