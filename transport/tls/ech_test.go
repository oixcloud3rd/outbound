package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	singSnell "github.com/sagernet/sing-snell"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestDecodeECHConfigList(t *testing.T) {
	t.Parallel()
	raw := []byte{0, 4, 0xfe, 0x0d, 0, 0}
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
	} {
		decoded, err := DecodeECHConfigList(encoded)
		require.NoError(t, err)
		require.Equal(t, raw, decoded)
	}
	_, err := DecodeECHConfigList("not-base64")
	require.Error(t, err)
	_, err = DecodeECHConfigList(base64.StdEncoding.EncodeToString([]byte{0, 3, 1, 2}))
	require.Error(t, err)
}

func TestTLSLinkOptionsOverrideExtraOptions(t *testing.T) {
	t.Parallel()
	created, _, err := NewTls(&dialer.ExtraOption{
		AllowInsecure:     true,
		TlsImplementation: "utls",
		UtlsImitate:       "firefox_auto",
	}, rejectingDialer{}, "tls://example.com:443?allowInsecure=false&utlsImitate=chrome_auto")
	require.NoError(t, err)
	configuration := created.(*Tls)
	require.Equal(t, "tls", configuration.tlsImplentation)
	require.Equal(t, "chrome_auto", configuration.utlsImitate)
	require.False(t, configuration.skipVerify)
}

func TestUTLSUsesDefaultFingerprint(t *testing.T) {
	t.Parallel()
	created, _, err := NewTls(&dialer.ExtraOption{}, rejectingDialer{}, "utls://example.com:443")
	require.NoError(t, err)
	require.Equal(t, "chrome_auto", created.(*Tls).utlsImitate)
}

func TestTLSNegotiatesECH(t *testing.T) {
	for _, implementation := range []string{"tls", "utls"} {
		t.Run(implementation, func(t *testing.T) {
			echConfig, echConfigList, echPrivateKey := makeECHConfig(t)
			serverConfig := &gotls.Config{
				MinVersion:   gotls.VersionTLS13,
				NextProtos:   []string{"http/1.1"},
				Certificates: []gotls.Certificate{makeServerCertificate(t)},
				EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{{
					Config:     echConfig,
					PrivateKey: echPrivateKey,
				}},
			}
			base := &echServerDialer{
				config: serverConfig,
				states: make(chan echObservation, 1),
				errors: make(chan error, 1),
			}
			link := implementation + "://server.example:443?sni=secret.example&allowInsecure=true&alpn=http%2F1.1&ech-config=" +
				url.QueryEscape(base64.StdEncoding.EncodeToString(echConfigList)) + "&snell-ech=true"
			if implementation == "utls" {
				link += "&utlsImitate=chrome_auto"
			}
			created, _, err := NewTls(&dialer.ExtraOption{}, base, link)
			require.NoError(t, err)
			connection, err := created.DialContext(context.Background(), "tcp", "ignored.example:443")
			if err != nil {
				select {
				case serverErr := <-base.errors:
					t.Fatalf("client handshake failed: %v; server handshake failed: %v", err, serverErr)
				case <-time.After(time.Second):
					t.Fatalf("client handshake failed: %v", err)
				}
			}
			require.NotNil(t, connection)
			clientExporter, err := singSnell.ExportIdentityKeyingMaterial(connection.(net.Conn))
			require.NoError(t, err)
			select {
			case observation := <-base.states:
				require.True(t, observation.state.ECHAccepted)
				require.Equal(t, "secret.example", observation.state.ServerName)
				require.Equal(t, "http/1.1", observation.state.NegotiatedProtocol)
				require.Equal(t, observation.exporter, clientExporter)
			case serverErr := <-base.errors:
				t.Fatalf("ECH server handshake failed: %v", serverErr)
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for ECH server handshake")
			}
		})
	}
}

func TestSnellECHTLSSessionResumption(t *testing.T) {
	for _, implementation := range []string{"tls", "utls"} {
		t.Run(implementation, func(t *testing.T) {
			echConfig, echConfigList, echPrivateKey := makeECHConfig(t)
			serverConfig := &gotls.Config{
				MinVersion:   gotls.VersionTLS13,
				NextProtos:   []string{"snell-ech/1"},
				Certificates: []gotls.Certificate{makeServerCertificate(t)},
				EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{{
					Config:     echConfig,
					PrivateKey: echPrivateKey,
				}},
			}
			base := &echServerDialer{
				config:    serverConfig,
				states:    make(chan echObservation, 2),
				errors:    make(chan error, 2),
				writeByte: true,
			}
			link := implementation + "://server.example:443?sni=secret.example&allowInsecure=true&alpn=snell-ech%2F1&ech-config=" +
				url.QueryEscape(base64.StdEncoding.EncodeToString(echConfigList)) + "&snell-ech=true"
			if implementation == "utls" {
				link += "&utlsImitate=chrome_auto"
			}
			created, _, err := NewTls(&dialer.ExtraOption{}, base, link)
			require.NoError(t, err)
			for attempt := 0; attempt < 2; attempt++ {
				connection, dialErr := created.DialContext(context.Background(), "tcp", "ignored.example:443")
				require.NoError(t, dialErr)
				payload, readErr := io.ReadAll(connection)
				require.NoError(t, readErr)
				require.Equal(t, []byte{1}, payload)
				observation := <-base.states
				require.Equal(t, attempt == 1 && implementation == "tls", observation.state.DidResume)
			}
		})
	}
}

func makeECHConfig(t *testing.T) (config, configList, privateKey []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(0xfe0d)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(7)
		builder.AddUint16(0x0020)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(key.PublicKey().Bytes())
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint16(0x0001)
			builder.AddUint16(0x0001)
		})
		builder.AddUint8(32)
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte("public.example"))
		})
		builder.AddUint16(0)
	})
	config, err = builder.Bytes()
	require.NoError(t, err)
	builder = cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) { builder.AddBytes(config) })
	configList, err = builder.Bytes()
	require.NoError(t, err)
	return config, configList, key.Bytes()
}

func makeServerCertificate(t *testing.T) gotls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "secret.example"},
		DNSNames:     []string{"secret.example", "public.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	return gotls.Certificate{Certificate: [][]byte{certificate}, PrivateKey: privateKey}
}

type echServerDialer struct {
	config    *gotls.Config
	states    chan echObservation
	errors    chan error
	writeByte bool
}

type echObservation struct {
	state    gotls.ConnectionState
	exporter []byte
}

func (d *echServerDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	go func() {
		connection := gotls.Server(server, d.config)
		if err := connection.Handshake(); err == nil {
			state := connection.ConnectionState()
			exporter, exportErr := state.ExportKeyingMaterial(
				singSnell.IdentityExporterLabel,
				[]byte{},
				singSnell.IdentityExporterLength,
			)
			if exportErr != nil {
				d.errors <- exportErr
			} else {
				if d.writeByte {
					_, _ = connection.Write([]byte{1})
				}
				d.states <- echObservation{state: state, exporter: exporter}
			}
		} else {
			d.errors <- err
		}
		_ = connection.Close()
	}()
	return client, nil
}

type rejectingDialer struct{}

func (rejectingDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, context.Canceled
}

func TestUTLSConfigCopiesECHFields(t *testing.T) {
	t.Parallel()
	ech := []byte{0, 4, 0xfe, 0x0d, 0, 0}
	configuration := uTLSConfigFromTLSConfig(&gotls.Config{
		ServerName:                     "example.com",
		NextProtos:                     []string{"http/1.1"},
		MinVersion:                     gotls.VersionTLS13,
		EncryptedClientHelloConfigList: ech,
	})
	require.Equal(t, "example.com", configuration.ServerName)
	require.Equal(t, []string{"http/1.1"}, configuration.NextProtos)
	require.Equal(t, uint16(gotls.VersionTLS13), configuration.MinVersion)
	require.Equal(t, ech, configuration.EncryptedClientHelloConfigList)
}
