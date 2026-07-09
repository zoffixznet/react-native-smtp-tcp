# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

Initial release candidate (1.0.0-rc.1). The 1.0.0 release will be finalized
after the security review.

### Added

- SMTP submission client for React Native over a native TCP/TLS socket.
- Implicit TLS on port 465 (preferred) and STARTTLS on port 587, with a
  require-TLS-or-abort policy for secure accounts.
- Certificate chain and hostname validation on by default, with no option to
  disable it. Optional per-account trust via an inline CA PEM string and
  best-effort SPKI SHA-256 pinning.
- AUTH PLAIN, LOGIN, and XOAUTH2 (with a pluggable OAuth2 token provider),
  gated behind an established, validated TLS channel.
- MIME message builder: text, HTML (multipart/alternative), and attachments
  (multipart/mixed), RFC 2047 encoded-words, SMTPUTF8 and 8BITMIME gating,
  dot-stuffing, CRLF normalization, and header folding.
- Unconditional CR/LF/NUL rejection at the serialization boundary to prevent
  SMTP command and header injection.
- Layered timeouts, DoS caps on reply parsing, and mid-dialog failure handling
  that never reports an unsent message as sent.
- A `verify()` probe (connect, TLS, EHLO, AUTH, QUIT) for a test-send UX.
- Node `net`/`tls` reference adapter (used by the test suite) and a thin
  `react-native-tcp-socket` device adapter.
