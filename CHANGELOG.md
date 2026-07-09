# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

Initial release candidate (1.0.0-rc.1).

### Added

- SMTP submission client for React Native over a native TCP/TLS socket.
- Implicit TLS on port 465 and STARTTLS on port 587, with a
  require-TLS-or-abort default.
- Certificate chain and hostname verification on by default. On Android,
  hostname verification is enabled by the shipped Expo config plugin (during
  `expo prebuild`) or the patch-package patch (bare React Native), which set the
  HTTPS endpoint identification algorithm and create the SSLSocket with the real
  hostname in the `react-native-tcp-socket` native transport, on both the
  implicit-TLS and STARTTLS paths.
- Optional per-account trust via an inline CA PEM string, and an optional leaf
  certificate SHA-256 fingerprint pin (`tls.pinnedCertSha256`) checked after the
  handshake.
- AUTH PLAIN, LOGIN, and XOAUTH2 (with a pluggable OAuth2 token provider), sent
  over an established TLS channel.
- MIME message builder: text, HTML (multipart/alternative), and attachments
  (multipart/mixed), RFC 2047 encoded-words, SMTPUTF8 and 8BITMIME gating,
  dot-stuffing, CRLF normalization, and header folding.
- CR/LF/NUL rejection at the serialization boundary, and rejection of C0/C1
  control characters in the subject, display names, and attachment
  filename/content-type.
- RFC 2047 encoded-words on UTF-8 character boundaries, and encoding of
  encoded-word-shaped ASCII.
- Layered timeouts, caps on reply parsing (including `caps.maxQueuedReplies` to
  bound unsolicited replies), and mid-dialog failure handling that does not
  report an unsent message as sent.
- A post-handshake TLS version floor on the device path (the negotiated version
  is checked after the handshake, since the minimum cannot be set pre-handshake
  on device).
- A `verify()` probe (connect, TLS, EHLO, AUTH, QUIT).
- Node `net`/`tls` adapter (used by the test suite) and a `react-native-tcp-socket`
  device adapter.
