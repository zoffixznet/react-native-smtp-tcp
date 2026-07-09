# Decisions

Engineering decisions and the option chosen, with the reasoning. Newest entries
are appended at the end.

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
implicit TLS is chosen as the default. `auto` does not mean "try plaintext";
`requireTLS` defaults to true, so nothing is sent in cleartext.

## Cipher and TLS-version enforcement in the Node adapter

The Node adapter sets `minVersion` (default `TLSv1.2`) and a forward-secret AEAD
cipher list on the `tls.connect` options so the min-version and weak-cipher tests
exercise real refusals. On device, `react-native-tcp-socket` does not expose a
JS cipher/min-version knob; the platform TLS stack governs this. That gap is
documented in the README known-limitations section. The protocol engine still
treats a failed or downgraded handshake as an abort.

## Native hostname verification on Android

Stock `react-native-tcp-socket` v6.4.1 validates the certificate chain (default
trust manager) but does not verify the hostname: the implicit-TLS path calls
`ssf.createSocket()` with no host and connects by resolved IP, the STARTTLS path
layers TLS using the resolved IP string, and neither sets
`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`. Hostname
verification therefore cannot be added in pure JavaScript on top of it (the
module exposes no certificate DER or parsed SAN).

The library enables it in the native layer at app build time. The Expo config
plugin (during `expo prebuild`) and the patch-package patch (bare React Native)
apply the same source transform to `TcpSocketClient.java`: both paths create the
SSLSocket with the real hostname and set the HTTPS endpoint identification
algorithm before the handshake, so the native handshake rejects a certificate
whose SAN/CN does not match the host. The transform is a set of anchored,
idempotent string replacements shared by the plugin and the patch and unit-tested
in Node. On iOS the default TLS path sets the peer name
(`kCFStreamSSLPeerName`), so the platform verifies the hostname there.

Because verification is enforced by the handshake, the JavaScript layer no longer
parses certificates for identity; it relies on a correct native handshake, the
same way the Node path relies on `rejectUnauthorized`.

## Optional certificate-fingerprint pinning

Pinning is an optional, post-handshake check layered on top of the default chain
and hostname verification, never instead of it. When `tls.pinnedCertSha256` is
set, the client awaits the peer certificate (the native `getPeerCertificate()`
resolves asynchronously) and compares its `fingerprint256` against the configured
pin, normalizing both to lowercase hex, and destroys the socket on mismatch. A
leaf SHA-256 fingerprint is used rather than an SPKI hash because the platforms
expose `fingerprint256` directly and it needs no additional hashing.

## Bare-IP hosts

When `host` is a bare IP, an explicit `tls.servername` is required as the expected
certificate identity; without it the connection aborts. The handshake matches the
certificate's IP SANs against the connected address.

## AUTH mechanism preference

Preference order is XOAUTH2/OAUTHBEARER, then SCRAM-SHA-256, then CRAM-MD5, then
LOGIN, then PLAIN, restricted to the post-TLS advertised set. This version ships
encoders for PLAIN, LOGIN, and XOAUTH2. SCRAM and CRAM-MD5 are
recognized for negotiation ordering but not implemented as senders; if the
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

## Lock-step command sending (no client-side pipelining)

The client always sends synchronizing commands one at a time and waits for each
reply before sending the next, even when the server advertises PIPELINING. This
is the safest correct behavior: each reply is unambiguously the reply to the
last command, so reply-to-command correlation cannot be confused, and it is
trivially impossible to pipeline anything across the STARTTLS boundary. The
capability is still parsed and exposed so consumers can see it. Not pipelining is
always spec-compliant (RFC 2920 requires pipelining only when advertised, never
forbids lock-step); the modest extra round-trips are acceptable for a mobile
submission client that sends one message per connection. The reply reader and
parser still refuse to merge two single-line replies into one multiline reply,
so a server that volunteers extra replies is treated as a protocol violation.

## Device-only behavior is a known limitation

The `react-native-tcp-socket` adapter and the native hostname-verification setup
run only where the native module is present, so they are not exercised by the
Node test suite. The adapter is kept thin over the v6.4.1 API; the pinning
comparison and the drain-before-wrap orchestration it relies on run in Node, and
on-device behavior is documented in the README under known limitations. Package
provenance is configured in the publish workflow (`--provenance --access public`,
`id-token: write`); `npm audit signatures` needs a published package, so it is
documented rather than run against an unpublished build.
