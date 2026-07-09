# react-native-smtp-tcp

A hardened, dependency-light SMTP submission client for React Native. It speaks
the SMTP protocol in pure TypeScript over a native TCP/TLS socket, so a device
can send email directly through a user-configured SMTP account with no backend
and no third-party email API.

It exists because there is no maintained, drop-in, programmatic SMTP client for
modern React Native. Mature JavaScript SMTP clients (nodemailer and friends) are
Node-only and cannot bundle under React Native, because Metro cannot resolve
Node's `net`, `tls`, and `dns`. The few native React Native SMTP modules are
abandoned or unproven. This library fills the gap by implementing the protocol
itself and delegating only the socket and TLS to a maintained native module.

## Highlights

- Implicit TLS on port 465 (preferred) and STARTTLS on port 587.
- Certificate chain validation is always on, with no option to disable it.
  Hostname verification is enforced on both the Node reference path and, by
  parsing the peer certificate in JavaScript, on the React Native device path
  (see Security and Known limitations for the exact device behavior and why
  SPKI pinning is the most robust device mitigation). Private and self-signed
  servers are supported through an explicit CA PEM string or an SPKI pin, not by
  turning validation off.
- AUTH PLAIN, LOGIN, and XOAUTH2 (with a pluggable OAuth2 token provider), sent
  only over an established, validated TLS channel.
- A MIME builder for text, HTML (multipart/alternative), and attachments
  (multipart/mixed), with RFC 2047 encoded-words, SMTPUTF8 and 8BITMIME gating,
  dot-stuffing, and header folding.
- Unconditional rejection of CR, LF, and NUL in every user-controlled field to
  prevent SMTP command and header injection.
- Layered timeouts, DoS caps on reply parsing, and a strict "never report a
  message as sent unless the server confirmed it" rule.
- A `verify()` probe to test an account and network before sending.

## Requirements and install

This library uses a native socket module, so it needs a development build or a
prebuild. It cannot run in Expo Go.

Install the library and its native transport peer dependency:

```sh
npm install react-native-smtp-tcp react-native-tcp-socket
```

`react-native` and `react-native-tcp-socket` are peer dependencies; they are not
bundled. `react-native-tcp-socket` is a plain autolinked native module with no
Expo config plugin, so:

- Bare React Native: it is picked up by autolinking. Run `pod install` on iOS.
- Expo: run `npx expo prebuild` (or use EAS Build, which runs prebuild) so
  autolinking includes it, then build a development build. It will not work in
  Expo Go.

Prefer passing a CA as an inline PEM string (see below). If instead you import a
`.pem`/`.p12` as an asset, add those extensions to `metro.config.js`
`resolver.assetExts`; the inline-string approach avoids that change entirely.

## Quick start

```ts
import { createTransport } from 'react-native-smtp-tcp';

const transport = createTransport({
  host: 'mail.example.com',
  port: 465,
  secure: 'implicit',
  auth: { user: 'me@example.com', pass: 'app-password' },
});

await transport.verify(); // optional: prove the account works on this network

const info = await transport.sendMail({
  from: { name: 'Me', address: 'me@example.com' },
  to: [{ address: 'you@example.com' }],
  subject: 'Rappel: café',
  text: 'Bonjour.',
  html: '<p>Bonjour.</p>',
});

console.log(info.messageId, info.accepted);
```

## API reference

### `createTransport(options): Transport`

Validates and resolves the options (rejecting prototype-pollution keys) and
returns a `Transport`. Options:

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `host` | `string` | required | Server hostname, or a bare IP (see `tls.servername`). |
| `port` | `number` | 465 or 587 | Submission port. Port 25 is rejected. |
| `secure` | `'implicit' \| 'starttls' \| 'auto'` | `'auto'` | Transport security. `auto` resolves from the port and defaults to implicit TLS on 465. |
| `requireTLS` | `boolean` | `true` | Abort rather than send anything sensitive in cleartext. |
| `auth` | see below | none | Credentials. |
| `tls` | `TlsOptions` | see below | TLS trust and identity options. |
| `timeouts` | `{ connectMs, greetingMs, idleMs, overallMs }` | 15000 / 15000 / 30000 / 60000 | Layered timeouts in milliseconds. |
| `caps` | `{ maxLineBytes, maxReplyBytes, maxContinuationLines, maxQueuedReplies }` | 8192 / 65536 / 200 / 16 | DoS caps for reply parsing. `maxQueuedReplies` bounds unsolicited replies buffered while no command is pending. |
| `logger` | `Logger` | none | Optional debug logger. Credentials are always redacted. |
| `clientId` | `string` | `[127.0.0.1]` | EHLO/HELO client identity (FQDN or address literal). |

`auth` is one of:

```ts
{ user: string; pass: string }                                  // PLAIN / LOGIN
{ user: string; type: 'oauth2'; accessToken: string }           // XOAUTH2 (static token)
{ user: string; type: 'oauth2'; tokenProvider: () => Promise<string> | string } // XOAUTH2 (refresh hook)
```

`tls` (`TlsOptions`):

| Option | Type | Meaning |
| --- | --- | --- |
| `ca` | `string` | Inline CA PEM to trust a private or self-signed server. |
| `pinnedSpkiSha256` | `string` | Base64 SHA-256 of the leaf certificate's SubjectPublicKeyInfo, enforced after the handshake. |
| `servername` | `string` | Expected certificate identity. Required when `host` is a bare IP. |
| `minVersion` | `'TLSv1.2' \| 'TLSv1.3'` | Minimum TLS version. Defaults to TLS 1.2; never lower. |
| `cert`, `key` | `string` | Client certificate and key (PEM) for mutual TLS. |

### `transport.verify(): Promise<{ capabilities }>`

Connects, negotiates TLS, sends EHLO, authenticates, and quits. Use it to test a
new account or to diagnose a network. Throws on any failure.

### `transport.sendMail(message): Promise<SendInfo>`

Builds and sends one message. Returns `{ accepted, rejected, response,
messageId }`. Throws (without reporting the message as sent) on any protocol,
security, or connection failure. `message`:

| Field | Type | Meaning |
| --- | --- | --- |
| `from` | `string \| { name?, address }` | Sender. Also used as the envelope MAIL FROM. |
| `to` | `Array<string \| { name?, address }>` | Recipients. At least one required. |
| `cc`, `bcc` | same as `to` | Additional recipients. `bcc` is in the envelope only, never in a header. |
| `replyTo` | `string \| { name?, address }` | Optional Reply-To. |
| `subject` | `string` | Subject. Non-ASCII is RFC 2047 encoded. |
| `text`, `html` | `string` | Plain and/or HTML body. Both produce multipart/alternative. |
| `attachments` | `Array<{ filename, content, contentType?, encoding?, contentId? }>` | `content` is bytes or a base64 string (set `encoding: 'base64'`). |
| `headers` | `Record<string, string>` | Extra headers. Managed headers cannot be overridden. |
| `messageId`, `date` | `string`, `Date` | Optional overrides. A unique Message-ID and the current Date are generated otherwise. |

### `transport.close(): Promise<void>`

Present for API symmetry. This client opens a fresh connection per operation and
closes it when the operation finishes, so there is nothing persistent to close.

### Errors

All errors extend `SmtpError` and carry a `transient` flag (true when a retry may
succeed). The subclasses are `SmtpConfigError`, `SmtpMessageError`,
`SmtpProtocolError`, `SmtpSecurityError`, `SmtpAuthError`, `SmtpTimeoutError`, and
`SmtpConnectionError`. Authentication failures are always mapped to a single
generic message and never reveal whether the user or the password was wrong.

## Security

- Implicit TLS versus STARTTLS. Prefer port 465 implicit TLS: it has no cleartext
  phase and is structurally immune to STARTTLS stripping and injection. STARTTLS
  on 587 is supported for servers that require it; on that path the client reads
  exactly the STARTTLS reply, refuses to proceed if any unexpected bytes follow
  it, discards everything learned before TLS, and re-issues EHLO inside TLS.
- Validation is always on. Certificate chain (PKIX) validation runs before the
  client authenticates or sends, and there is no switch to disable it (a
  build-time lint forbids such constructs). Hostname verification also runs
  before AUTH/send: on the Node reference path the socket enforces it, and on the
  React Native device path the library parses the peer leaf certificate's
  subjectAltName/CN in JavaScript and verifies the hostname itself, because the
  underlying `react-native-tcp-socket` native module does not check the hostname.
  If the certificate identity cannot be obtained or does not match, the
  connection fails closed before any credential is sent.
- Device hardening with SPKI pinning. Because the device hostname check depends
  on the library parsing the leaf certificate, the most robust mitigation for
  device deployments is an SPKI pin (`tls.pinnedSpkiSha256`): it binds the exact
  leaf public key independent of hostname and is enforced post-handshake. Prefer
  a pin (optionally together with a narrow `tls.ca`) for high-assurance device
  use.
- Private or self-signed servers. Do not disable validation. Instead pass the
  server's CA as an inline PEM string in `tls.ca`, or pin the leaf key with
  `tls.pinnedSpkiSha256`. Chain and hostname checks stay active against that
  trust anchor. To compute the pin from a certificate:

  ```sh
  openssl x509 -in server.crt -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64
  ```

- Bare-IP hosts. When `host` is an IP address, set `tls.servername` to the
  identity the certificate should match; the library validates against it and
  refuses to connect otherwise.
- OAuth2. Basic Auth is being retired by major providers (Google disabled it in
  2025, Microsoft 365 is retiring SMTP-AUTH Basic Auth including app passwords).
  Prefer XOAUTH2 with a `tokenProvider` so tokens refresh.
- Secret handling. The library never persists credentials and never logs a
  password, token, or AUTH payload; AUTH lines are redacted to `***`. Store
  credentials in OS-backed secure storage (Android Keystore / iOS Keychain, for
  example via Expo SecureStore), not in plaintext AsyncStorage.

## Examples

Runnable snippets are in [`examples/`](examples): implicit TLS with a password,
STARTTLS with a password, and OAuth2 with a token provider.

## Troubleshooting

- "Sends on Wi-Fi, fails on cellular." Many mobile carriers and some networks
  block outbound SMTP ports (465, 587, 25). This is a network restriction, not a
  library bug. Use `verify()` to detect it quickly on the current network and
  surface a clear message to the user. There is no way to send on a network that
  blocks the port; the user must switch networks or use a provider API.
- Gmail. Requires either an app password (with 2-Step Verification enabled) or
  OAuth2. Ordinary account passwords do not work. Prefer XOAUTH2.
- Microsoft 365 / Outlook. Basic Auth for SMTP is being retired; use OAuth2
  (XOAUTH2). Some tenants disable SMTP AUTH entirely and require an administrator
  to enable it.
- "Certificate rejected for a private server." Provide the server's CA in
  `tls.ca` as an inline PEM string, or pin with `tls.pinnedSpkiSha256`. Do not
  look for a way to disable validation; there is none by design.
- Expo Go. This library needs a native socket module and cannot run in Expo Go.
  Use a development build or `npx expo prebuild`.

## Platform support

- Android is the primary, tested-by-design target.
- iOS works because the transport is cross-platform, but it is secondary and less
  exercised. Treat on-device iOS as unverified until you test it.

## Known limitations

- On-device native execution is not verified in this project's automated tests.
  The pure protocol and MIME engines and the Node reference transport are proven
  in Node against real in-process SMTP and TLS servers and against adversarial
  fake sockets. The thin `react-native-tcp-socket` adapter can only be exercised
  on a physical device or emulator with the native module present; validate it on
  your target device.
- `react-native-tcp-socket` does not expose a JavaScript knob for the TLS minimum
  version, cipher list, or SNI override, so those cannot be configured
  pre-handshake on device; they are governed by the platform TLS stack (modern
  Android/iOS default to TLS 1.2+ with AEAD suites). The minimum-version and
  cipher preferences configured here are enforced pre-handshake on the Node
  reference path. On device the client applies a post-handshake floor instead: it
  reads the negotiated protocol version and aborts if it is below the configured
  minimum, so a downgraded handshake is refused even though it could not be
  prevented at negotiation time. It cannot refuse a specific weak cipher on device
  beyond what the platform already declines.
- Hostname verification on device is performed by this library in JavaScript by
  parsing the leaf certificate's subjectAltName/CN, because the native module
  does not verify the hostname itself and does not return a parsed
  subjectAltName. This is enforced fail-closed before AUTH/send. For the strongest
  device guarantee, add an SPKI pin (`tls.pinnedSpkiSha256`), which is
  hostname-independent.
- SPKI pinning on device is best-effort and post-handshake, because the native
  module exposes the peer certificate only after the handshake completes. Chain
  validation and the JavaScript hostname check run against the configured trust
  anchor.
- Out of scope for this version: DNS/MX resolution (configure an explicit host),
  DKIM signing (the submission server handles it), connection pooling, and
  IMAP/POP.

## Building and contributing

The `Makefile` is the front door; run `make` (or `make help`) to list targets.
Common ones:

```sh
make install     # install dependencies
make build       # compile to dist/ (ESM + CJS + types)
make test        # run the test suite
make cover       # run tests with coverage (fails under 90%)
make lint        # ESLint plus the disable-validation guard
make typecheck   # type-check without emitting
make pack-check  # build, verify the pack manifest, and scan for leaks/secrets
make check       # typecheck, lint, test
make ci          # typecheck, lint, coverage gate, pack/secret scan
```

## License

MIT. See [LICENSE](LICENSE). Security policy: [SECURITY.md](SECURITY.md).
