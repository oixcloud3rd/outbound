package tls

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/stretchr/testify/require"
)

type stateTestConn struct {
	net.Conn
	state ConnectionState
}

func (c *stateTestConn) TLSConnectionState() ConnectionState {
	return c.state
}

func TestValidateECHConnection(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &stateTestConn{Conn: client, state: ConnectionState{ECHAccepted: true, NegotiatedProtocol: "snell-ech/1"}}
	require.NoError(t, ValidateECHConnection(conn, "snell-ech/1"))
	conn.state.NegotiatedProtocol = "h2"
	require.ErrorIs(t, ValidateECHConnection(conn, "snell-ech/1"), ErrUnexpectedALPN)
	conn.state.ECHAccepted = false
	require.ErrorIs(t, ValidateECHConnection(conn, "h2"), ErrECHNotAccepted)
}

func TestALPNCompatibilityErrors(t *testing.T) {
	t.Parallel()
	require.True(t, IsALPNCompatibilityError(ErrUnexpectedALPN))
	require.True(t, IsALPNCompatibilityError(errors.New("remote error: tls: no application protocol")))
	require.False(t, IsALPNCompatibilityError(context.DeadlineExceeded))
	require.False(t, IsALPNCompatibilityError(errors.New("x509: certificate signed by unknown authority")))
}

func TestSnellECHConfiguresSessionCaches(t *testing.T) {
	t.Parallel()
	created, _, err := NewTls(
		&dialer.ExtraOption{},
		rejectingDialer{},
		"utls://example.com:443?sni=example.com&allowInsecure=false&alpn=snell-ech%2F1&ech-config=AAQ%2BDAAA&snell-ech=true",
	)
	require.NoError(t, err)
	configuration := created.(*Tls)
	require.NotNil(t, configuration.tlsConfig.ClientSessionCache)
	uConfig := uTLSConfigFromTLSConfig(configuration.tlsConfig)
	configureUTLSSnellECH(uConfig, configuration.utlsSessionCache)
	require.NotNil(t, uConfig.ClientSessionCache)
	require.True(t, uConfig.OmitEmptyPsk)
}
