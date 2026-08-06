package tls

import (
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	ErrECHNotAccepted = errors.New("TLS ECH was not accepted")
	ErrUnexpectedALPN = errors.New("TLS negotiated an unexpected ALPN")
)

// ConnectionState is the transport-neutral subset needed by Snell ECH-TLS.
type ConnectionState struct {
	ECHAccepted        bool
	NegotiatedProtocol string
}

type connectionStateProvider interface {
	TLSConnectionState() ConnectionState
}

// GetConnectionState supports both standard TLS connections and the uTLS
// wrapper returned by this package.
func GetConnectionState(conn netproxy.Conn) (ConnectionState, bool) {
	if provider, ok := conn.(connectionStateProvider); ok {
		return provider.TLSConnectionState(), true
	}
	if provider, ok := conn.(interface {
		ConnectionState() cryptotls.ConnectionState
	}); ok {
		state := provider.ConnectionState()
		return ConnectionState{
			ECHAccepted:        state.ECHAccepted,
			NegotiatedProtocol: state.NegotiatedProtocol,
		}, true
	}
	return ConnectionState{}, false
}

// ValidateECHConnection rejects a successfully established TLS connection
// unless ECH was accepted and the configured application protocol was chosen.
func ValidateECHConnection(conn netproxy.Conn, expectedALPN string) error {
	state, ok := GetConnectionState(conn)
	if !ok {
		return errors.New("snell: invalid ECH-TLS connection")
	}
	if !state.ECHAccepted {
		return fmt.Errorf("snell: %w", ErrECHNotAccepted)
	}
	if state.NegotiatedProtocol != expectedALPN {
		return fmt.Errorf("snell: %w: got %q, want %q", ErrUnexpectedALPN, state.NegotiatedProtocol, expectedALPN)
	}
	return nil
}

// IsALPNCompatibilityError identifies the only failures eligible for Snell's
// explicit legacy fallback. Network and certificate failures must propagate.
func IsALPNCompatibilityError(err error) bool {
	if errors.Is(err, ErrUnexpectedALPN) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no application protocol") || strings.Contains(message, "unsupported application protocols")
}
