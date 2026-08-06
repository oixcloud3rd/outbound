// Package snell adapts the oixcloud3rd sing-snell fork (which retains the
// upstream module path) to outbound's protocol and netproxy interfaces.
package snell

import (
	"errors"
	"fmt"
	"strings"

	singSnell "github.com/sagernet/sing-snell"
)

const (
	Version4 = 4
	Version5 = 5
	Version6 = 6
)

type IdentityVersion = singSnell.IdentityVersion

const (
	IdentityDisabled = singSnell.IdentityDisabled
	IdentityV1       = singSnell.IdentityV1
	IdentityV2       = singSnell.IdentityV2
)

// ClientOptions contains protocol-specific client settings. ECH-TLS is
// assembled by dialer/snell before the protocol client is created.
type ClientOptions struct {
	Version    int
	UserKey    string
	Reuse      bool
	Identity   IdentityVersion
	Preconnect int
	ECHTLS     bool
	Mode       string
	Obfs       string
	ObfsHost   string
}

func (o ClientOptions) normalizedObfs() string {
	if o.Obfs == "" {
		return "none"
	}
	return strings.ToLower(o.Obfs)
}

func (o ClientOptions) validate(psk string) error {
	if psk == "" {
		return errors.New("snell: missing PSK")
	}
	if len(o.UserKey) > 255 {
		return errors.New("snell: user key is longer than 255 bytes")
	}
	if o.Identity > IdentityV2 {
		return fmt.Errorf("snell: identity must be between 0 and 2")
	}
	if o.Preconnect < 0 || o.Preconnect > 4 {
		return errors.New("snell: preconnect must be between 0 and 4")
	}
	switch o.Version {
	case Version4, Version5:
		if o.Mode != "" {
			return errors.New("snell: mode is only valid for version 6")
		}
		switch o.normalizedObfs() {
		case "none", "http", "tls":
		default:
			return fmt.Errorf("snell: unsupported obfs %q", o.Obfs)
		}
		if o.Identity == IdentityV2 && !o.ECHTLS {
			return errors.New("snell: identity v2 requires ECH-TLS")
		}
		if o.Preconnect > 0 && (!o.ECHTLS || !o.Reuse) {
			return errors.New("snell: preconnect requires ECH-TLS and reuse")
		}
	case Version6:
		if o.Identity != IdentityDisabled {
			return errors.New("snell: identity is not supported by version 6")
		}
		if o.Preconnect != 0 || o.ECHTLS {
			return errors.New("snell: version 6 cannot be combined with ECH-TLS or preconnect")
		}
		if len(psk) < 12 || len(psk) > 255 {
			return errors.New("snell: version 6 PSK length must be between 12 and 255 bytes")
		}
		if o.normalizedObfs() != "none" || o.ObfsHost != "" {
			return errors.New("snell: obfs is not supported by version 6")
		}
		switch o.Mode {
		case "", "default", "unshaped", "unsafe-raw":
		default:
			return fmt.Errorf("snell: unknown version 6 mode %q", o.Mode)
		}
	default:
		return fmt.Errorf("snell: unsupported version %d", o.Version)
	}
	return nil
}
