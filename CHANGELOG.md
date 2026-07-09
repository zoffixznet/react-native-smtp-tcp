# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

Initial release candidate (1.0.0-rc.1). The 1.0.0 release will be finalized
after the security review.

### Security

- Verify named-host identity on the React Native device path in JavaScript by
  parsing the peer leaf certificate's subjectAltName/CN, because the native
  socket does not check the hostname. Named-host identity now fails closed
  instead of trusting the channel when identity material is missing or does not
  match.
- Enforce a post-handshake TLS version floor so a downgraded handshake is
  refused on device, where the minimum version cannot be set pre-handshake.
- Bound the queue of unsolicited server replies (new `caps.maxQueuedReplies`) so
  a hostile server pacing replies across TCP segments cannot exhaust memory.
- Reject wildcard certificate SANs in a public-suffix / TLD position (for
  example `*.com`, `*.co.uk`) and any wildcard that is not a single leftmost
  label.
- Reject every C0/C1 control character (not only CR/LF/NUL) in the subject,
  display names, and attachment filename/content-type.
- Encode RFC 2047 encoded-words on UTF-8 character boundaries (no split
  multi-byte characters) and encode encoded-word-shaped ASCII rather than
  emitting it verbatim, preventing subject/display-name spoofing.

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
