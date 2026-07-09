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
import { computeSpkiSha256, pinMatches } from './protocol/pinning';
import { verifyHostname } from './hostname';
import { isIP } from './net-util';
import { SmtpSecurityError } from './protocol/errors';
import type {
  SmtpTransport,
  TlsUpgradeOptions,
  PeerCertificate,
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

/**
 * SHA-256 via the platform crypto. Resolves a WebCrypto-style subtle digest is
 * async, so this uses Node's crypto when present (tests, and RN with a polyfill)
 * via a guarded lazy require, and otherwise throws a clear error when pinning is
 * requested on a platform without a synchronous SHA-256. Pinning is opt-in, so
 * this only matters when a pin is configured.
 */
function sha256(data: Uint8Array): Uint8Array {
  const nodeCrypto = tryLoadNodeCrypto();
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.createHash('sha256').update(data).digest());
  }
  throw new SmtpSecurityError(
    'SPKI pinning requires a synchronous SHA-256 implementation that is not available on this platform',
  );
}

type NodeCrypto = typeof import('crypto');
let nodeCryptoLookup: NodeCrypto | null | undefined;
function tryLoadNodeCrypto(): NodeCrypto | null {
  if (nodeCryptoLookup !== undefined) return nodeCryptoLookup;
  try {
    if (typeof require === 'function') {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      nodeCryptoLookup = require('crypto') as NodeCrypto;
    } else {
      nodeCryptoLookup = null;
    }
  } catch {
    nodeCryptoLookup = null;
  }
  return nodeCryptoLookup;
}

/** The default transport factory. The RN adapter is loaded lazily so this
 * module can be imported and unit-tested in Node without the native module. */
const defaultFactory: TransportFactory = {
  connectPlain(config, tls) {
    // On device the RN adapter is used. In a non-RN environment we fall back to
    // the Node adapter so the exact same engine runs against real sockets in the
    // test suite. Selecting the RN adapter requires the native module.
    const rn = tryLoadRnAdapter();
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
  },
  connectImplicitTls(config, tls) {
    const rn = tryLoadRnAdapter();
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
   * Post-handshake channel verification: hostname identity (defense in depth,
   * and the primary check for bare-IP hosts) and optional SPKI pinning. Throws a
   * SmtpSecurityError to reject.
   */
  private verifyTlsChannel(transport: SmtpTransport): void {
    const cert = transport.getPeerCertificate?.();

    // Hostname identity. For a bare-IP host, the Node/RN socket cannot perform
    // SNI-based identity checks, so this explicit check is authoritative.
    this.verifyIdentity(cert);

    // SPKI pinning, if configured.
    if (this.config.tls.pinnedSpkiSha256) {
      const computed = computeSpkiSha256(cert, sha256);
      if (!pinMatches(computed, this.config.tls.pinnedSpkiSha256)) {
        throw new SmtpSecurityError('the server certificate does not match the configured SPKI pin');
      }
    }
  }

  private verifyIdentity(cert: PeerCertificate | undefined): void {
    const expected = this.config.servername;
    // When the host is a bare IP we must have a certificate and matching SAN.
    if (isIP(this.config.host)) {
      if (!cert || !cert.subjectAltNames) {
        throw new SmtpSecurityError(
          'cannot verify the server identity for a bare-IP host (no certificate details available)',
        );
      }
      if (!verifyHostname(expected, cert.subjectAltNames, cert.commonName)) {
        throw new SmtpSecurityError(
          `the server certificate does not match the expected identity "${expected}"`,
        );
      }
      return;
    }
    // For named hosts, the socket's own rejectUnauthorized already enforces
    // identity; when certificate details are available we double-check.
    if (cert && cert.subjectAltNames) {
      if (!verifyHostname(expected, cert.subjectAltNames, cert.commonName)) {
        throw new SmtpSecurityError(
          `the server certificate does not match the expected identity "${expected}"`,
        );
      }
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
