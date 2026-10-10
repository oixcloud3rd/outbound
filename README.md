# Outbound

1. Combine protocols in daeuniverse/softwind as dialers.
2. Support to New a dialer from share-link, and generate the share-link from a dialer.

## Snell links

Snell v4, v5-compatible v4 wire, and Snell v6 are available through `snell://` links:

The wire protocol, reuse pool, UDP framing, and HTTP/TLS obfuscation are provided by the pinned [oixcloud3rd/sing-snell](https://github.com/oixcloud3rd/sing-snell) fork; outbound supplies the `netproxy` adapter, link format, and ECH-TLS transport composition.

```text
snell://<url-encoded-psk>@server.example:443?version=4&reuse=true#name
snell://<url-encoded-psk>@server.example:443?version=6&mode=unshaped#name
```

v4/v5 support `userkey`, connection reuse, Identity v1 (`identity=1`, with
`identity=true` retained as an alias), Identity v2 (`identity=2`), and `http`,
`tls`, or `ech-tls` obfuscation. Identity remains disabled when it is omitted
from a direct share link. v6 supports `default`, `unshaped`, and `unsafe-raw`
modes; its PSK must contain 12–255 bytes and it cannot be combined with
obfuscation, identity, or preconnect.

By default, ECH-TLS carries the Snell v4 wire directly over TLS 1.3 with ECH. No HTTP/2 or
WebSocket framing is added after the handshake. Existing direct links that omit
`alpn` keep the legacy `h2` value; new configurations should explicitly use
`alpn=snell-ech/1` and Identity v2:

```text
snell://psk@server.example:443?version=5&reuse=true&obfs=ech-tls&sni=origin.example&ech-config=<url-encoded-base64>&alpn=snell-ech%2F1&identity=2&preconnect=2#name
```

`ech-config` is a padded or unpadded standard-Base64 ECHConfigList.
ECH must be accepted by the server and certificate verification cannot be
disabled. `tls-implementation` and `client-fingerprint` are optional; standard
TLS remains the default for direct links. `preconnect=1..4` warms reusable
connections in the background and requires ECH-TLS plus `reuse=true`.

Set `legacy-fallback=true` with `alpn=snell-ech/1` to retry an ALPN-incompatible
server with `h2`; Identity v2 falls back to Identity v1 on that retry. Network,
certificate, and authentication failures are never retried as legacy traffic.
The deprecated `protocol=oix-snell/1` value is normalized to `snell-ech/1`.
Legacy `path`, `obfs-uri`, and `ws-host` query parameters are accepted but
ignored and omitted from canonical exports.

### HTTP/3 transport

`transport=tcp` (also the default), `transport=h3`, and `transport=auto` select
the underlay. H3 is a custom HTTP/3 Extended CONNECT tunnel, **not** official
Snell v5 QUIC mode. It requires v4/v5-compatible wire, `obfs=ech-tls`,
explicit `identity=2`, a valid `ech-config`, and certificate verification.
It cannot be combined with v6 or `legacy-fallback=true`.

```text
snell://psk@server.example:443?version=4&obfs=ech-tls&transport=auto&identity=2&sni=origin.example&ech-config=<url-encoded-base64>&reuse=true&preconnect=1&congestion_control=bbr3#h3
```

The server must accept Extended CONNECT with `:protocol=websocket` at
`/ws-tunnel-` followed by the lowercase hex of the first 12 bytes of
SHA-256(PSK). The tunnel carries raw Snell bytes, without WebSocket frames.
TCP and UDP proxy traffic share QUIC sessions; Snell reuse and preconnect
remain available. H3 uses Go TLS 1.3 with `h3` ALPN and requires accepted ECH.
uTLS, fingerprint and TLS fragmentation settings apply only to TCP fallback.

`h3` allows 10 seconds to establish a tunnel and never falls back. `auto`
follows the Snell Happy Eyeballs implementation in `oixcloud3rd/sing-box`: start H3
first, then race certificate-verified ECH-TLS TCP at the same address and port
after 250 ms without a live session, or twice its smoothed RTT clamped to
100-1000 ms with a live session. H3 failure starts TCP immediately.
The first successful transport wins. If TCP wins, H3 continues probing within
its original 2-second budget: success keeps the QUIC session warm and clears
cooldown; failure starts a 30-second cooldown. The unused H3 stream is closed.
If H3 wins, TCP is canceled and any late connection is closed. Caller cancellation
before a winner stops the race; closing the dialer also stops background probes.
Shared QUIC handshakes have their own bounded lifetime so one canceled waiter
does not cancel others. Only the winner sends Snell data.
TCP retains Identity v2 and defaults to `snell-ech/1` ALPN. QUIC transport
parameters use library defaults rather than custom receive windows or keepalive.

Congestion control affects only client QUIC sending:
`cc_override` takes precedence over `congestion_control`, then the default
**experimental BBR3**. Supported values are `bbr`, `bbr3`, `brutal`, and
`reno` (`new_reno` is an alias). Unknown `congestion_control` values, including
the currently unimplemented `cubic`, warn at dialer construction and use BBR3;
unknown `cc_override` values are errors. `cwnd` is in bytes/second: a required
positive target rate for Brutal, or an optional upper-bound hint for BBR3.
BBR profiles are not supported; explicit `bbr_profile`/`bbr-profile` is rejected.
