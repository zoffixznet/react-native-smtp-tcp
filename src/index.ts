/**
 * react-native-smtp-tcp
 *
 * Public API. A hardened SMTP submission client for React Native that speaks the
 * SMTP protocol over a native TCP/TLS socket, with implicit TLS (465) preferred
 * and STARTTLS (587) supported, always-on certificate validation, AUTH PLAIN /
 * LOGIN / XOAUTH2, and a MIME builder with attachments.
 */

import { resolveConfig } from './config';
import type { ResolvedConfig, TransportOptions } from './config';
import { SmtpClient } from './protocol/client';
import { buildMessage } from './message/builder';
import type { MailMessage } from './message/builder';
import { certFingerprintMatches } from './protocol/pinning';
import { SmtpSecurityError } from './protocol/errors';
import type {
  SmtpTransport,
  TlsUpgradeOptions,
  Capabilities,
} from './protocol/types';
import {
  connectImplicitTls as nodeConnectImplicit,
  connectPlain as nodeConnectPlain,
} from './transports/node';

export type { TransportOptions, TlsOptions, ResolvedConfig } from './config';
export type { MailMessage, Attachment } from './message/builder';
export type {
  AuthConfig,
  PasswordAuth,
  OAuth2StaticAuth,
  OAuth2ProviderAuth,
  Logger,
  SecureMode,
  Caps,
  Timeouts,
  SmtpTransport,
  Capabilities,
} from './protocol/types';
export {
  SmtpError,
  SmtpConfigError,
  SmtpMessageError,
  SmtpProtocolError,
  SmtpSecurityError,
  SmtpAuthError,
  SmtpTimeoutError,
  SmtpConnectionError,
} from './protocol/errors';

/** Result of a successful send. */
export interface SendInfo {
  accepted: string[];
  rejected: string[];
  response: string;
  messageId: string;
}

/**
 * A factory that opens a transport for the given config. The default uses the
 * React Native native socket; the test suite injects a Node-backed factory. The
 * factory returns a not-yet-secure transport for STARTTLS or an already-secure
 * transport (emitting 'secureConnect') for implicit TLS.
 */
export interface TransportFactory {
  connectPlain(config: ResolvedConfig, tls: TlsUpgradeOptions): SmtpTransport;
  connectImplicitTls(config: ResolvedConfig, tls: TlsUpgradeOptions): SmtpTransport;
}

/** The default transport factory. The RN adapter is loaded lazily so this
 * module can be imported and unit-tested in Node without the native module. */
/**
 * Minimal shape of an RN-style adapter (connectPlain/connectImplicitTls that
 * take {host, port, connectTimeoutMs, tls}). Kept separate so the selection
 * logic is testable without the native module.
 */
export interface RnStyleAdapter {
  connectPlain(o: { host: string; port: number; connectTimeoutMs: number; tls: TlsUpgradeOptions }): SmtpTransport;
  connectImplicitTls(o: { host: string; port: number; connectTimeoutMs: number; tls: TlsUpgradeOptions }): SmtpTransport;
}

/** Open a plaintext connection using the RN adapter when present, else Node. */
export function selectPlainConnect(
  config: ResolvedConfig,
  tls: TlsUpgradeOptions,
  rn: RnStyleAdapter | null,
): SmtpTransport {
  // On device the RN adapter is used. In a non-RN environment (the test suite)
  // the Node adapter runs the exact same engine against real sockets.
  if (rn) {
    return rn.connectPlain({
      host: config.host,
      port: config.port,
      connectTimeoutMs: config.timeouts.connectMs,
      tls,
    });
  }
  return nodeConnectPlain({
    host: config.host,
    port: config.port,
    connectTimeoutMs: config.timeouts.connectMs,
    servername: config.servername,
    tls,
  });
}

/** Open an implicit-TLS connection using the RN adapter when present, else Node. */
export function selectImplicitConnect(
  config: ResolvedConfig,
  tls: TlsUpgradeOptions,
  rn: RnStyleAdapter | null,
): SmtpTransport {
  if (rn) {
    return rn.connectImplicitTls({
      host: config.host,
      port: config.port,
      connectTimeoutMs: config.timeouts.connectMs,
      tls,
    });
  }
  return nodeConnectImplicit({
    host: config.host,
    port: config.port,
    connectTimeoutMs: config.timeouts.connectMs,
    servername: config.servername,
    tls,
  });
}

const defaultFactory: TransportFactory = {
  connectPlain(config, tls) {
    return selectPlainConnect(config, tls, tryLoadRnAdapter());
  },
  connectImplicitTls(config, tls) {
    return selectImplicitConnect(config, tls, tryLoadRnAdapter());
  },
};

type RnAdapter = typeof import('./transports/react-native');
let rnAdapterLookup: RnAdapter | null | undefined;

/** Try to load the RN adapter; returns null when the native module is absent. */
function tryLoadRnAdapter(): RnAdapter | null {
  if (rnAdapterLookup !== undefined) return rnAdapterLookup;
  try {
    if (typeof require !== 'function') {
      rnAdapterLookup = null;
      return rnAdapterLookup;
    }
    // Only resolves when react-native-tcp-socket is installed (on device).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require.resolve('react-native-tcp-socket');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    rnAdapterLookup = require('./transports/react-native') as RnAdapter;
  } catch {
    rnAdapterLookup = null;
  }
  return rnAdapterLookup;
}

/** Options for constructing a Transport (internal factory is injectable). */
export interface CreateTransportOptions extends TransportOptions {
  /** Internal seam: override the transport factory (used by the test suite). */
  transportFactory?: TransportFactory;
}

/** The public transport object returned by {@link createTransport}. */
export class Transport {
  private config: ResolvedConfig;
  private factory: TransportFactory;

  constructor(config: ResolvedConfig, factory: TransportFactory) {
    this.config = config;
    this.factory = factory;
  }

  /**
   * Connect, negotiate TLS, EHLO, authenticate, and QUIT. Proves the account can
   * reach the server and authenticate on the current network. Throws on failure.
   */
  async verify(): Promise<{ capabilities: Capabilities }> {
    const client = await this.openAndNegotiate();
    try {
      const caps = client.getCapabilities();
      if (!caps) throw new SmtpSecurityError('negotiation did not complete');
      return { capabilities: caps };
    } finally {
      await client.quit();
    }
  }

  /** Build and send one message. */
  async sendMail(message: MailMessage): Promise<SendInfo> {
    const client = await this.openAndNegotiate();
    try {
      const caps = client.getCapabilities()!;
      const built = buildMessage(message, {
        smtpUtf8: caps.smtpUtf8,
        eightBitMime: caps.eightBitMime,
      });
      if (built.requiresSmtpUtf8 && !caps.smtpUtf8) {
        throw new SmtpSecurityError(
          'message needs SMTPUTF8 (non-ASCII envelope address) but the server does not advertise it',
        );
      }
      const result = await client.sendTransaction({
        from: built.envelopeFrom,
        to: built.envelopeTo,
        data: built.data,
        sizeBytes: built.sizeBytes,
        smtpUtf8: built.requiresSmtpUtf8,
        eightBitMime: false,
      });
      await client.quit();
      return {
        accepted: result.accepted,
        rejected: result.rejected,
        response: result.response,
        messageId: built.messageId,
      };
    } catch (err) {
      client.close();
      throw err;
    }
  }

  /** Close is a no-op placeholder for API symmetry; connections are per-op. */
  async close(): Promise<void> {
    // This client opens a fresh connection per operation and closes it when the
    // operation finishes, so there is nothing persistent to close. The method
    // exists for API symmetry with pooled clients.
  }

  /** Open a connection and run the full negotiation up to authenticated. */
  private async openAndNegotiate(): Promise<SmtpClient> {
    const tls = this.tlsUpgradeOptions();
    const transport =
      this.config.secure === 'implicit'
        ? this.factory.connectImplicitTls(this.config, tls)
        : this.factory.connectPlain(this.config, tls);

    const client = new SmtpClient(transport, {
      host: this.config.host,
      clientId: this.config.clientId,
      secure: this.config.secure,
      requireTLS: this.config.requireTLS,
      auth: this.config.auth,
      caps: this.config.caps,
      timeouts: this.config.timeouts,
      logger: this.config.logger,
      tlsUpgradeOptions: tls,
      verifyTlsChannel: (t) => this.verifyTlsChannel(t),
    });
    try {
      await client.connect();
      return client;
    } catch (err) {
      client.close();
      throw err;
    }
  }

  private tlsUpgradeOptions(): TlsUpgradeOptions {
    return {
      ca: this.config.tls.ca,
      cert: this.config.tls.cert,
      key: this.config.tls.key,
      servername: this.config.servername,
      minVersion: this.config.tls.minVersion,
      host: this.config.host,
    };
  }

  /**
   * Post-handshake channel checks. The TLS handshake itself enforces the
   * certificate chain and hostname (Node's rejectUnauthorized on the reference
   * path; native endpoint identification on device), so this only applies the
   * optional certificate-fingerprint pin. When a pin is configured and does not
   * match, it throws a SmtpSecurityError so the client aborts before sending.
   */
  private async verifyTlsChannel(transport: SmtpTransport): Promise<void> {
    const pin = this.config.tls.pinnedCertSha256;
    if (!pin) return;
    const cert = await transport.getPeerCertificate?.();
    if (!certFingerprintMatches(cert, pin)) {
      throw new SmtpSecurityError(
        'the server certificate does not match the configured certificate pin',
      );
    }
  }
}

/**
 * Create a Transport from options. Validates and resolves the configuration
 * (prototype-pollution-safe), and picks implicit TLS (465) or STARTTLS (587).
 */
export function createTransport(options: CreateTransportOptions): Transport {
  const config = resolveConfig(options);
  const factory = options.transportFactory ?? defaultFactory;
  return new Transport(config, factory);
}
