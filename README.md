# react-native-smtp-tcp

An SMTP client for React Native. It speaks the SMTP submission protocol in
TypeScript over a native TCP/TLS socket, so an app can send email directly
through a user-configured SMTP account without a backend or a third-party email
API.

Mature JavaScript SMTP clients (nodemailer and similar) are Node-only and cannot
bundle under React Native, because Metro cannot resolve Node's `net`, `tls`, and
`dns`. This library implements the protocol itself and delegates the socket and
TLS to the `react-native-tcp-socket` native module.

## Features

- Implicit TLS on port 465 and STARTTLS on port 587.
- AUTH PLAIN, LOGIN, and XOAUTH2 (with a pluggable OAuth2 token provider).
- A MIME builder for text, HTML (multipart/alternative), and attachments
  (multipart/mixed), with RFC 2047 encoded-words, SMTPUTF8 and 8BITMIME gating,
  dot-stuffing, and header folding.
- CR, LF, and NUL are rejected in user-controlled fields (SMTP command and header
  injection).
- Layered timeouts and caps on reply parsing; a message is reported as sent only
  after the server confirms it.
- A `verify()` probe to test an account and network before sending.

TLS certificate and hostname verification is on by default (see Setup); an
optional certificate pin is available.

## Requirements and install

This library uses a native socket module, so it needs a development build or a
prebuild. It does not run in Expo Go.

```sh
npm install react-native-smtp-tcp react-native-tcp-socket
```

`react-native` and `react-native-tcp-socket` are peer dependencies.

## Setup

The native transport validates the certificate chain, but hostname verification
on Android must be enabled at build time. Enable it with the config plugin (Expo)
or the patch (bare React Native). This is a one-time setup step.

### Expo

Add this package to the `plugins` array in your app config. During
`npx expo prebuild` (and EAS Build) it enables hostname verification in the
native transport:

```json
{
  "expo": {
    "plugins": ["react-native-smtp-tcp"]
  }
}
```

Then build a development build. It does not run in Expo Go.

### Bare React Native

Use [`patch-package`](https://www.npmjs.com/package/patch-package). Copy
`node_modules/react-native-smtp-tcp/patches/react-native-tcp-socket+6.4.1.patch`
into your project's `patches/` directory, add a `postinstall` script, and run
`pod install` on iOS:

```json
{
  "scripts": {
    "postinstall": "patch-package"
  }
}
```

`patch-package` reapplies the patch on every install, and autolinking picks up
`react-native-tcp-socket`.

### CA certificates

Prefer passing a CA as an inline PEM string (see `tls.ca`). If you import a
`.pem`/`.p12` as an asset instead, add those extensions to `metro.config.js`
`resolver.assetExts`.

## Quick start

```ts
import { createTransport } from 'react-native-smtp-tcp';

const transport = createTransport({
  host: 'mail.example.com',
  port: 465,
  secure: 'implicit',
  auth: { user: 'me@example.com', pass: 'app-password' },
});

await transport.verify(); // optional: check the account and network

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
| `requireTLS` | `boolean` | `true` | Abort rather than send anything in cleartext. |
| `auth` | see below | none | Credentials. |
| `tls` | `TlsOptions` | see below | TLS options. |
| `timeouts` | `{ connectMs, greetingMs, idleMs, overallMs }` | 15000 / 15000 / 30000 / 60000 | Layered timeouts in milliseconds. |
| `caps` | `{ maxLineBytes, maxReplyBytes, maxContinuationLines, maxQueuedReplies }` | 8192 / 65536 / 200 / 16 | Caps for reply parsing. `maxQueuedReplies` bounds unsolicited replies buffered while no command is pending. |
| `logger` | `Logger` | none | Optional debug logger. Credentials are redacted. |
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
| `pinnedCertSha256` | `string` | Optional SHA-256 fingerprint of the leaf certificate (colon-separated or plain hex), checked after the handshake. |
| `servername` | `string` | Expected certificate identity. Required when `host` is a bare IP. |
| `minVersion` | `'TLSv1.2' \| 'TLSv1.3'` | Minimum TLS version. Defaults to TLS 1.2. |
| `cert`, `key` | `string` | Client certificate and key (PEM) for mutual TLS. |

### `transport.verify(): Promise<{ capabilities }>`

Connects, negotiates TLS, sends EHLO, authenticates, and quits. Use it to test a
new account or diagnose a network. Throws on failure.

### `transport.sendMail(message): Promise<SendInfo>`

Builds and sends one message. Returns `{ accepted, rejected, response,
messageId }`. Throws (without reporting the message as sent) on any protocol,
TLS, or connection failure. `message`:

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
`SmtpConnectionError`. Authentication failures map to a single generic message
and do not reveal whether the user or the password was wrong.

## TLS notes

- Certificate chain and hostname verification is on by default. Node uses
  `rejectUnauthorized`; on device the config plugin / patch enables native
  endpoint identification, so the handshake rejects a certificate whose SAN/CN
  does not match the host. There is no option to disable validation. If the
  handshake fails, the connection aborts before any credential is sent.
- Private or self-signed servers: pass the server's CA as an inline PEM string in
  `tls.ca`, or pin the leaf certificate with `tls.pinnedCertSha256`. To compute
  the pin:

  ```sh
  openssl x509 -in server.crt -noout -fingerprint -sha256
  ```

- Bare-IP hosts: when `host` is an IP address, set `tls.servername` to the
  expected certificate identity.
- OAuth2: major providers are retiring Basic Auth for SMTP (Google in 2025,
  Microsoft 365 for SMTP-AUTH Basic Auth). Prefer XOAUTH2 with a `tokenProvider`
  so tokens refresh.
- Credentials: the library does not persist credentials and does not log a
  password, token, or AUTH payload (AUTH lines are redacted). Store credentials
  in OS-backed secure storage (Android Keystore / iOS Keychain, for example via
  Expo SecureStore).

## Examples

Runnable snippets are in [`examples/`](examples): implicit TLS with a password,
STARTTLS with a password, and OAuth2 with a token provider.

## Troubleshooting

- "Sends on Wi-Fi, fails on cellular." Many mobile carriers and networks block
  outbound SMTP ports (465, 587, 25). Use `verify()` to detect it on the current
  network. The user must switch networks or use a provider API.
- Gmail: requires an app password (with 2-Step Verification) or OAuth2. Ordinary
  account passwords do not work. Prefer XOAUTH2.
- Microsoft 365 / Outlook: Basic Auth for SMTP is being retired; use OAuth2. Some
  tenants disable SMTP AUTH and require an administrator to enable it.
- "Certificate rejected for a private server." Provide the server's CA in
  `tls.ca`, or pin with `tls.pinnedCertSha256`.
- Expo Go: this library needs a native socket module and does not run in Expo Go.
  Use a development build or `npx expo prebuild`.

## Platform support

- Android: the config plugin / patch enables hostname verification in the native
  transport.
- iOS: `react-native-tcp-socket` sets the peer name on the default TLS path, so
  the platform performs hostname verification there.

## Known limitations

- On-device behavior is not exercised by this project's automated tests. The
  protocol and MIME engines and the Node adapter run in Node against in-process
  SMTP and TLS servers; the `react-native-tcp-socket` adapter and the native
  hostname-verification setup are validated on a real device by the consuming
  app.
- `react-native-tcp-socket` exposes no JavaScript knob for the TLS minimum
  version, cipher list, or SNI override, so those are governed by the platform
  TLS stack on device (modern Android/iOS default to TLS 1.2+). The Node adapter
  sets the minimum version and cipher list pre-handshake; on device the client
  reads the negotiated protocol version after the handshake and aborts if it is
  below the configured minimum.
- The certificate pin is checked after the handshake, because the native module
  exposes the peer certificate only once the handshake completes.
- Out of scope: DNS/MX resolution (configure an explicit host), DKIM signing (the
  submission server handles it), connection pooling, and IMAP/POP.

## Building and contributing

The `Makefile` is the front door; run `make` (or `make help`) to list targets.

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
