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

ECH-TLS carries the Snell v4 wire directly over TLS 1.3 with ECH. No HTTP/2 or
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
