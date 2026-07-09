/**
 * Public and internal types for the protocol engine. No React Native or Node
 * imports are allowed in this file.
 */

/** Duck-typed socket the protocol engine depends on. Adapters implement it. */
export interface SmtpTransport {
  write(data: string | Uint8Array, cb?: (err?: Error) => void): boolean;
  end(data?: string | Uint8Array, cb?: () => void): void;
  destroy(err?: Error): void;
  setTimeout(ms: number, cb?: () => void): void;
  on(event: 'data', h: (chunk: Uint8Array) => void): this;
  on(event: 'error', h: (e: Error) => void): this;
  on(event: 'close', h: (hadError: boolean) => void): this;
  on(event: 'connect' | 'secureConnect', h: () => void): this;
  once(event: string, h: (...args: any[]) => void): this;
  removeListener(event: string, h: (...args: any[]) => void): this;
  removeAllListeners(event?: string): this;
  /**
   * Upgrade an already-connected plain socket to TLS in place (STARTTLS).
   * Returns the wrapped secure transport, which emits 'secureConnect' when
   * ready. The caller guarantees the read buffer is empty and plaintext data
   * listeners are detached before this is called (drain-before-wrap).
   */
  upgradeToTLS(opts: TlsUpgradeOptions): SmtpTransport;
  /**
   * Peer certificate access for the optional post-handshake pin check. The
   * native transport resolves this asynchronously (the underlying module returns
   * a promise), so callers await it; the Node adapter returns synchronously and
   * awaiting a plain value is a no-op.
   */
  getPeerCertificate?(): Promise<PeerCertificate | undefined> | PeerCertificate | undefined;
  /** Best-effort negotiated TLS protocol version ("TLSv1.2", "TLSv1.3", ...). */
  getProtocol?(): string | undefined;
}

/** Options passed to a TLS upgrade / implicit-TLS connect. */
export interface TlsUpgradeOptions {
  ca?: string;
  cert?: string;
  key?: string;
  servername?: string;
  minVersion?: string;
  ciphers?: string;
  host?: string;
}

/**
 * Peer certificate view used by the optional certificate-fingerprint pin. The
 * fields mirror what the platforms actually expose after the handshake: a
 * SHA-256 fingerprint (colon-separated hex), a SHA-1 fingerprint, and the
 * base64-encoded public key. There is deliberately no raw DER or parsed
 * subjectAltName here: hostname identity is enforced by the TLS handshake
 * (Node's rejectUnauthorized, or native endpoint identification on device), not
 * in JavaScript.
 */
export interface PeerCertificate {
  /** Colon-separated hex SHA-1 fingerprint, if the platform provides one. */
  fingerprint?: string;
  /** Colon-separated hex SHA-256 fingerprint of the leaf certificate. */
  fingerprint256?: string;
  /** Base64-encoded public key (DER SubjectPublicKeyInfo), if provided. */
  pubkey?: string;
}

/** DoS caps for reply parsing. */
export interface Caps {
  /** Hard maximum bytes for a single reply line (above the 512 spec minimum). */
  maxLineBytes: number;
  /** Hard maximum bytes across a full (possibly multiline) reply. */
  maxReplyBytes: number;
  /** Hard maximum number of continuation lines in one reply. */
  maxContinuationLines: number;
  /**
   * Hard maximum number of complete replies that may sit in the queue awaiting a
   * consumer. A correct server never leaves more than one un-consumed reply
   * outside the greeting race, so this bounds the memory a hostile server can
   * make the client buffer by pacing unsolicited replies across TCP segments.
   */
  maxQueuedReplies: number;
}

/** Layered timeouts (milliseconds). */
export interface Timeouts {
  connectMs: number;
  greetingMs: number;
  idleMs: number;
  overallMs: number;
}

/** How the transport secures the connection. */
export type SecureMode = 'implicit' | 'starttls' | 'auto';

/** Password credentials. */
export interface PasswordAuth {
  user: string;
  pass: string;
  type?: 'login';
}

/** OAuth2 credentials with a static access token. */
export interface OAuth2StaticAuth {
  user: string;
  type: 'oauth2';
  accessToken: string;
}

/** OAuth2 credentials with a token provider (refresh hook). */
export interface OAuth2ProviderAuth {
  user: string;
  type: 'oauth2';
  tokenProvider: () => Promise<string> | string;
}

export type AuthConfig = PasswordAuth | OAuth2StaticAuth | OAuth2ProviderAuth;

/** Optional structured logger. Values passed in are already redacted. */
export interface Logger {
  debug?: (msg: string) => void;
  info?: (msg: string) => void;
  warn?: (msg: string) => void;
  error?: (msg: string) => void;
}

/** A parsed SMTP reply. */
export interface SmtpReply {
  /** The 3-digit basic code. */
  code: number;
  /** Every line's text after the code and separator, in order. */
  lines: string[];
  /** The combined text of all lines joined by LF. */
  text: string;
  /** Enhanced status code parsed from the final line, if present. */
  enhanced?: { class: number; subject: number; detail: number };
}

/** Server capabilities learned from an EHLO reply. */
export interface Capabilities {
  /** Original EHLO greeting domain line. */
  greeting: string;
  startTls: boolean;
  pipelining: boolean;
  eightBitMime: boolean;
  smtpUtf8: boolean;
  enhancedStatusCodes: boolean;
  /** Advertised SIZE limit in octets, or undefined if not advertised. */
  size?: number;
  /** Advertised AUTH mechanisms, uppercased. */
  authMechanisms: string[];
  /** All raw capability tokens (uppercased keyword -> full line). */
  raw: Map<string, string>;
}
