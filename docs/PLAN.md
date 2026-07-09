# Implementation plan

This is the working plan for `react-native-smtp-tcp`: a findings summary, the
chosen design, the implementation order, and a mapping from each requirement to
the test that proves it.

## Findings summary (transport verification)

The transport dependency `react-native-tcp-socket` was verified against its
published source at tag `v6.4.1` and its npm registry metadata. Confirmed:

- Version `6.4.1` is current; peer dependency is `react-native >=0.60.0`.
- Implicit TLS uses `connectTLS(options, cb)`. Internally it constructs a plain
  `Socket`, wraps it in a `TLSSocket`, and re-emits the underlying TCP
  `'connect'` as `'secureConnect'`. The returned object is the `TLSSocket`.
- STARTTLS upgrade is done by constructing `new TLSSocket(existingSocket, opts)`.
  The `TLSSocket` constructor calls `_startTLS()` synchronously and reuses the
  same native socket id (`this._setId(this._socket._id)`). It does not flush or
  drain JS-buffered plaintext bytes. This is the drain-before-wrap hazard the
  spec calls out; the protocol layer must guarantee an empty residual buffer and
  detach plaintext listeners before the wrap.
- TLS certificate options are limited to `ca`, `cert`, `key`, and Android
  KeyStore aliases. There is no public `rejectUnauthorized`, no `servername`
  override, no `checkServerIdentity`, and no pinning callback. `ca` may be a PEM
  string (preferred, avoids Metro assetExts changes) or an asset.
- `getPeerCertificate()` exists on `TLSSocket` for best-effort post-handshake
  pinning.
- The plain `connect`/`createConnection` path accepts a `ConnectionOptions` that
  includes `tlsCheckValidity?: boolean`. The library never sets this to a value
  that would weaken validation; see `docs/DECISIONS.md`.

Given these transport facts, the library depends on the injectable
`SmtpTransport` interface rather than on the native module directly.

## Chosen design

Three pure layers plus adapters:

- `src/protocol/` - the transport-agnostic SMTP engine. No React Native and no
  Node imports. Depends only on the `SmtpTransport` interface.
  - `reply-reader.ts`: a line-exact, byte-bounded reader that surfaces complete
    reply lines and enforces the DoS caps (max line bytes, max reply bytes, max
    continuation lines). Never accumulates an unbounded buffer.
  - `reply-parser.ts`: linear, index-based reply parsing (chars 0-2 = code,
    char 3 = ' ' or '-'), enhanced-status-code parsing, code-consistency checks.
  - `sasl.ts`: AUTH mechanism encoders (PLAIN, LOGIN, XOAUTH2) and strict
    base64 challenge decoding, with credential redaction helpers.
  - `client.ts`: the connection/transaction state machine. Greeting, EHLO/HELO
    fallback, STARTTLS orchestration with the drain-before-wrap invariant,
    post-TLS re-EHLO, AUTH gating behind a validated-TLS invariant, the
    MAIL/RCPT/DATA transaction, SIZE handling, timeouts, and the security
    invariants.
  - `errors.ts`, `types.ts`, `caps.ts`: shared error taxonomy, public types,
    default caps and timeouts.
- `src/message/` - the pure RFC 5322/MIME builder.
  - `validate.ts`: CR/LF/NUL rejection (bare CR and bare LF independently),
    RFC 5321 size limits, address grammar checks, header ftext checks.
  - `encoding.ts`: RFC 2047 encoded-words, base64, quoted-printable, folding.
  - `address.ts`: address normalization and angle-bracket handling.
  - `builder.ts`: the MIME assembly (multipart/alternative, multipart/mixed),
    mandatory headers, Message-ID and Date generation, dot-stuffing, CRLF
    normalization.
- `src/transports/` - two thin adapters implementing `SmtpTransport`.
  - `node.ts`: over Node `net`/`tls`. Used by the whole test suite and as the
    reference adapter. Its `upgradeToTLS` uses `tls.connect({ socket, ... })`.
  - `react-native.ts`: over `react-native-tcp-socket`. The only file that
    imports it. `upgradeToTLS` returns `new TLSSocket(socket, opts)`. Kept as
    thin as possible; on-device execution is a documented known limitation.
- `src/index.ts` - the public API: `createTransport`, config validation
  (prototype-pollution-safe merge), and the exported types.

Coverage target is 90% statements and branches, enforced by `make cover`. The
pure engine is tested in Node against (a) an adversarial in-memory fake socket
and (b) real in-process `smtp-server` and Node `tls` servers with a locally
generated CA. Certificates for tests are generated at test time by a helper, so
no key material is committed.

## Implementation order

1. Package scaffolding: `package.json`, `tsconfig`, lint, Makefile, CI, LICENSE,
   SECURITY.md, CHANGELOG, ignore files, plan and decisions docs. (this commit)
2. Message layer: validation, encoding, address handling, MIME builder + tests.
3. Protocol layer: reply reader, parser, SASL, client state machine + tests.
4. Transports: injectable interface, Node adapter, RN adapter + tests, including
   real in-process SMTP/TLS end-to-end and adversarial fake-socket tests.
5. Public API wiring + integration tests + verify().
6. Publishing hygiene: pack allowlist test, secret/leak scan, dep hygiene tests.
7. Documentation: README, examples, finalize docs.
8. Final pass: full suite, coverage gate, pack/secret-scan, re-read spec, push.

## Requirement-to-test mapping

Security:

- SEC-1 (prefer 465) -> integration tests choosing implicit TLS; `auto` picks
  465 when configured. SEC-26 default-to-465.
- SEC-2 (require-TLS-or-abort) -> T-STARTTLS-STRIP, T-STARTTLS-454.
- SEC-3 (drain before wrap) -> T-STARTTLS-INJECTION, T-PRETLS-GREETING-INJECTION.
- SEC-4 (discard pre-TLS state, re-EHLO) -> T-EHLO-DISCARD.
- SEC-5 (never pipeline after STARTTLS) -> covered in client tests + drain tests.
- SEC-6 (PKIX + hostname) -> T-WRONG-HOSTNAME-CERT, T-UNTRUSTED-CHAIN.
- SEC-7 (no disable-validation) -> T-NO-DISABLE-VALIDATION-LINT.
- SEC-8 (optional certificate pin) -> T-CERT-PIN-POS-NEG, T-TRUST-LIMIT.
- SEC-9 (min TLS 1.2) -> T-MIN-TLS-VERSION.
- SEC-10 (strong ciphers) -> T-WEAK-CIPHER.
- SEC-11 (SNI to hostname / bare IP identity) -> T-IP-SNI.
- SEC-12 (AUTH only over validated TLS) -> T-AUTH-CLEARTEXT-GATE.
- SEC-13 (post-TLS advertised mechanisms, strongest-first) ->
  T-AUTH-MECH-NEGOTIATION.
- SEC-14/15/16/29 (CRLF/NUL injection, fail closed, envelope/header separation)
  -> T-ENVELOPE-CRLF, T-BARE-CR-LF-ADDR, T-NUL-ADDR, T-HEADER-BCC-INJECTION,
  T-HEADER-BLOCK-SMUGGLE, T-MALFORMED-HEADER-NAME, T-FAIL-CLOSED-ABORT,
  T-QUOTED-LOCALPART.
- SEC-17 (never log secrets) -> T-CREDENTIAL-REDACTION, T-EXCEPTION-HYGIENE.
- SEC-18 (secure storage) -> documented; library never persists secrets;
  in-memory credential release covered by a unit test.
- SEC-19 (auth-failure hygiene) -> T-FAILURE-CODES, T-EXCEPTION-HYGIENE.
- SEC-20 (OAuth2/XOAUTH2) -> T-XOAUTH2-FORMAT, T-XOAUTH2-ERROR.
- SEC-21 (DoS caps) -> T-NEVER-FINAL, T-GIANT-LINE, T-SIZE-LIMITS.
- SEC-22 (timeouts + slowloris) -> T-NO-TERMINATOR, T-SLOWLORIS, T-NO-GREETING.
- SEC-23 (mid-dialog close = failure) -> T-MID-DIALOG-RST, T-PARTIAL-EOF.
- SEC-24 (ReDoS-safe) -> T-REDOS, T-MALFORMED-CODES.
- SEC-25 (prototype-pollution-safe merge) -> T-PROTOTYPE-POLLUTION.
- SEC-27 (SMTPUTF8 gating) -> T-SMTPUTF8-GATE, T-RFC2047-NOT-IN-ADDR.
- SEC-28 (8BITMIME gating) -> T-8BITMIME-GATE.

Correctness:

- COR-1..COR-18 -> T-TRANSACTION-ORDER, T-ANGLE-BRACKETS, T-HELO-FALLBACK,
  T-MULTILINE-OK, T-MULTILINE-MISMATCH, T-TRAILING-WS, T-ENHANCED-CODES,
  T-MALFORMED-CODES, T-DOTSTUFF-*, T-DATA-TERMINATOR, T-CRLF-NORMALIZE,
  T-LINE-FOLD-998, T-RFC2047-*, T-MIME-STRUCTURE, T-MANDATORY-HEADERS,
  T-PLAIN-GOLDEN, T-PLAIN-NONASCII, T-LOGIN-SEQUENCE, T-BASE64-STRICTNESS,
  T-PIPELINING-NOT-ADVERTISED, T-PIPELINING-REPLY-COUNT, T-SIZE-LIMITS.

Publishing:

- T-PACK-MANIFEST, T-SECRET-SCAN-TARBALL, T-NO-ABSPATH-NO-APPNAME,
  T-NO-INSTALL-SCRIPT, T-DEP-HYGIENE (T-PROVENANCE-SIG is asserted structurally
  in the workflow; `npm audit signatures` needs the published package so it is
  documented, not run against an unpublished build).

Injectable core / adapters:

- T-INJECTABLE-CORE, T-IMPLICIT-TLS-PATH cover the pure engine and Node path.
- T-RN-ADAPTER-SMOKE, T-TRUST-LIMIT are device-dependent; the RN adapter is kept
  thin and unit-tested with a stubbed module where possible, with real-device
  execution recorded as a known limitation.

## Outcome

The plan above was followed. The result:

- The test suite runs over the 90% coverage gate, enforced by `make cover`. The
  covered paths (STARTTLS drain-before-wrap, certificate and hostname validation,
  the optional certificate pin, injection rejection, reply-parsing caps, AUTH
  gating, timeouts, mid-dialog failure) are exercised with in-memory fake sockets
  and in-process SMTP/TLS servers.
- The pure protocol and message engines import no React Native and no Node
  modules (only the `buffer` package). The Node adapter and the React Native
  adapter are the only platform-specific files; the React Native module is
  imported only by its adapter (the public entry loads it lazily and guarded).
- Packaging is publish-ready: a `files` allowlist, MIT `LICENSE`, `SECURITY.md`,
  `CHANGELOG.md`, correct `package.json` metadata, a passing pack/secret-scan
  check, and a provenance-ready CI plus a manual publish workflow.
- The STARTTLS drain check aborts the connection not only on leftover buffered
  bytes but also on a fully parsed injected reply (queued in the same tick the
  220 resolved) or a mid-reply parser state.
