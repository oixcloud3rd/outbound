// Package snell implements the Snell v4/v5 client wire protocol and the
// Snell v6 client protocol. The v4 record behavior follows the FlClash Snell
// implementation; v5 TCP/UDP servers intentionally accept the v4 client wire.
package snell

import (
	"errors"
	"fmt"
)

const (
	Version4 = 4
	Version5 = 5
	Version6 = 6
)

const (
	requestVersion byte = 1

	commandConnect   byte = 1
	commandConnectV2 byte = 5
	commandUDP       byte = 6
	udpForward       byte = 1

	replyTunnel byte = 0
	replyError  byte = 2
)

const (
	headerVersion   = 4
	headerPlainLen  = 7
	aeadTagLen      = 16
	headerCipherLen = headerPlainLen + aeadTagLen
	saltLen         = 16
	nonceLen        = 12
	maxPayloadLen   = 0x3fff
)

var (
	ErrPayloadTooLarge = errors.New("snell: payload too large")
	ErrBadReply        = errors.New("snell: invalid server reply")
	ErrBadRecord       = errors.New("snell: invalid record")
)

// ClientOptions contains protocol-specific client settings. Transport
// settings (TLS, WebSocket and simple-obfs) are assembled by dialer/snell.
type ClientOptions struct {
	Version  int
	UserKey  string
	Reuse    bool
	Identity bool
	Mode     string
}

func (o ClientOptions) validate(psk string) error {
	switch o.Version {
	case Version4, Version5:
		if o.Mode != "" {
			return errors.New("snell: mode is only valid for version 6")
		}
	case Version6:
		if o.Identity {
			return errors.New("snell: identity is not supported by version 6")
		}
		if len(psk) < 12 || len(psk) > 255 {
			return errors.New("snell: version 6 PSK length must be between 12 and 255 bytes")
		}
		switch o.Mode {
		case "", "default", "unshaped", "unsafe-raw":
		default:
			return fmt.Errorf("snell: unknown version 6 mode %q", o.Mode)
		}
	default:
		return fmt.Errorf("snell: unsupported version %d", o.Version)
	}
	if psk == "" {
		return errors.New("snell: missing PSK")
	}
	if len(o.UserKey) > 255 {
		return errors.New("snell: user key is longer than 255 bytes")
	}
	return nil
}
