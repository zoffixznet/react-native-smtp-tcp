# Decisions

Ambiguities resolved during the build, with the option chosen and why. Newest
entries are appended at the end.

## Internal build spec is not published

The internal build specification is deliberately kept out of this repository. It
describes how the library was produced and is not part of the library's public
surface. Keeping it out avoids leaking build context and keeps the repository a
clean, standalone SMTP client as a human author would ship it. The public
documentation (README, this file, PLAN.md) is written independently against the
RFCs.

## Build system and module format

- ESM is the primary output with an accompanying CJS build, since it is cheap
  with the TypeScript compiler and maximizes consumer compatibility. Types are
  emitted alongside. `package.json` exposes `main` (CJS), `module` (ESM),
  `types`, and a `react-native` entry, all under `dist/`.
- The test suite runs against the TypeScript sources through `ts-node`/`tsx` so
  coverage maps to source, not to compiled output.

## Transport TLS validity flag

`react-native-tcp-socket`'s plain-socket `ConnectionOptions` exposes a
`tlsCheckValidity?: boolean`. The library never sets this flag on any path, and
never exposes any option that would let a caller weaken certificate validation.
The STARTTLS upgrade uses `new TLSSocket(sock, opts)` with only `ca`/`cert`/`key`
and never the plain-socket `tls`/`tlsCheckValidity` inline options. This keeps
validation on by default with the device trust store, which is the required
behavior. The lint check also forbids `tlsCheckValidity` from appearing outside
tests.

## secure: 'auto'

`secure: 'auto'` resolves from the port: 465 implies implicit TLS, anything else
implies STARTTLS. When the caller sets `secure: 'auto'` without a port, 465
implicit TLS is chosen as the preferred, unstrippable default (SEC-1, SEC-26).
`auto` never means "try plaintext"; `requireTLS` defaults to true and a secure
account never sends anything sensitive in cleartext.

## Cipher and TLS-version enforcement in the Node adapter

The Node adapter sets `minVersion` (default `TLSv1.2`) and a forward-secret AEAD
cipher list on the `tls.connect` options so the min-version and weak-cipher tests
exercise real refusals. On device, `react-native-tcp-socket` does not expose a
JS cipher/min-version knob; the platform TLS stack governs this. That gap is
documented in the README known-limitations section. The protocol engine still
treats a failed or downgraded handshake as an abort.

## Post-handshake SPKI pinning

Pinning is implemented as a post-handshake check: after `secureConnect`, the
adapter exposes the peer certificate (Node: DER + public key; RN:
`getPeerCertificate()`), and the client compares the SPKI SHA-256 against the
configured `pinnedSpkiSha256`, destroying the socket on mismatch. This is
best-effort on RN because the native module only exposes the certificate after
the handshake completes; PKIX path and hostname checks still run against the
configured trust anchor. This matches the transport's real surface.

## Hostname verification for bare-IP hosts

When `host` is a bare IP, the Node adapter cannot rely on SNI-driven identity
checks alone, so an explicit `tls.servername`/expected-hostname is required and
used for identity verification; without it the connection aborts (SEC-11). On
RN, where there is no SNI override, the same explicit expected hostname is
required and the post-handshake identity check enforces it.

## AUTH mechanism preference

Preference order is XOAUTH2/OAUTHBEARER, then SCRAM-SHA-256, then CRAM-MD5, then
LOGIN, then PLAIN, restricted to the post-TLS advertised set. v1 ships encoders
for PLAIN, LOGIN, and XOAUTH2 (the spec's v1 scope). SCRAM and CRAM-MD5 are
recognized for negotiation ordering but not implemented as senders in v1; if the
server advertises only mechanisms the library cannot perform, it refuses to
authenticate rather than downgrading silently. CRAM-MD5 is deliberately not used
as a primary mechanism.

## Message size accounting for SIZE

The SIZE value sent on MAIL FROM and checked locally is the octet length of the
serialized DATA payload (headers + blank line + body with CRLF line endings)
excluding the terminating `<CRLF>.<CRLF>`, and excluding dot-stuffing added for
transparency, per RFC 1870's "message content" definition.

## Logger redaction

The logger is optional and receives already-redacted strings. AUTH command
arguments and every line of an AUTH exchange are replaced with `***` before they
reach any logger, and credentials are never included in error messages or their
stacks. There is no way to turn redaction off.
