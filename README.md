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

v4/v5 support `userkey`, connection reuse, explicitly enabled `identity=true`, and `http`, `tls`, or `ech-tls` obfuscation. Identity is disabled by default, including for ECH-TLS. v6 supports `default`, `unshaped`, and `unsafe-raw` modes; its PSK must contain 12–255 bytes and it cannot be combined with obfuscation or identity.

ECH-TLS uses Snell v4 wire over WebSocket over TLS 1.3 with ECH:

```text
snell://psk@server.example:443?version=5&reuse=true&obfs=ech-tls&sni=origin.example&ws-host=tunnel.example&path=%2Fsnell&ech-config=<url-encoded-base64>#name
```

`ech-config` is a padded or unpadded standard-Base64 ECHConfigList. The WebSocket path is required. `skip-cert-verify`, `tls-implementation`, and `client-fingerprint` are optional; standard TLS remains the default.
