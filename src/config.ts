/**
 * Public configuration types and prototype-pollution-safe option resolution.
 */

import { SmtpConfigError } from './protocol/errors';
import { DEFAULT_CAPS, DEFAULT_TIMEOUTS, mergeCaps, mergeTimeouts } from './protocol/caps';
import type { AuthConfig, Caps, Logger, SecureMode, Timeouts } from './protocol/types';
import { isIP } from './net-util';

/** TLS options. There is deliberately no switch to disable validation. */
export interface TlsOptions {
  /** Inline CA PEM string (preferred) for a private/self-signed server. */
  ca?: string;
  /**
   * Optional leaf certificate SHA-256 fingerprint pin, checked after the
   * handshake in addition to the default chain and hostname verification.
   * Accepts colon-separated or plain hex.
   */
  pinnedCertSha256?: string;
  /** Expected identity when the host is a bare IP (required in that case). */
  servername?: string;
  /** Minimum TLS version. Defaults to TLSv1.2; never lower. */
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  /** Client certificate PEM (for mutual TLS). */
  cert?: string;
  /** Client key PEM (for mutual TLS). */
  key?: string;
}

/** Options accepted by createTransport. */
export interface TransportOptions {
  host: string;
  port?: number;
  secure?: SecureMode;
  requireTLS?: boolean;
  auth?: AuthConfig;
  tls?: TlsOptions;
  timeouts?: Partial<Timeouts>;
  caps?: Partial<Caps>;
  logger?: Logger;
  /** EHLO/HELO client identity. Defaults to a neutral literal. */
  clientId?: string;
}

/** The fully resolved, validated configuration used internally. */
export interface ResolvedConfig {
  host: string;
  port: number;
  secure: 'implicit' | 'starttls';
  requireTLS: boolean;
  auth?: AuthConfig;
  tls: TlsOptions;
  servername: string;
  timeouts: Timeouts;
  caps: Caps;
  logger?: Logger;
  clientId: string;
}

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Reject prototype-pollution keys anywhere in a plain object graph (shallow +
 * one level for known nested option objects). */
function assertNoPollution(obj: unknown, path: string): void {
  if (obj === null || typeof obj !== 'object') return;
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (DANGEROUS_KEYS.has(key)) {
      throw new SmtpConfigError(`unsafe option key "${key}" at ${path}`);
    }
  }
  // Also guard against a __proto__ that is an own-enumerable data property.
  if (Object.prototype.hasOwnProperty.call(obj, '__proto__')) {
    throw new SmtpConfigError(`unsafe option key "__proto__" at ${path}`);
  }
}

/** Validate and resolve user options into a ResolvedConfig. Fails closed. */
export function resolveConfig(options: TransportOptions): ResolvedConfig {
  if (options === null || typeof options !== 'object') {
    throw new SmtpConfigError('options must be an object');
  }
  assertNoPollution(options, 'options');
  if (options.tls) assertNoPollution(options.tls, 'options.tls');
  if (options.timeouts) assertNoPollution(options.timeouts, 'options.timeouts');
  if (options.caps) assertNoPollution(options.caps, 'options.caps');
  if (options.auth) assertNoPollution(options.auth, 'options.auth');

  if (typeof options.host !== 'string' || options.host.length === 0) {
    throw new SmtpConfigError('host is required');
  }
  const host = options.host;

  const secureMode: SecureMode = options.secure ?? 'auto';
  let port = options.port;
  let secure: 'implicit' | 'starttls';
  if (secureMode === 'implicit') {
    secure = 'implicit';
    port = port ?? 465;
  } else if (secureMode === 'starttls') {
    secure = 'starttls';
    port = port ?? 587;
  } else {
    // auto: derive from the port, defaulting to implicit TLS on 465 which is the
    // preferred, unstrippable transport.
    if (port === 465) secure = 'implicit';
    else if (port === 587 || port === 25) secure = 'starttls';
    else {
      secure = 'implicit';
      port = port ?? 465;
    }
  }
  if (port === 25) {
    throw new SmtpConfigError('port 25 is not a submission port; use 465 or 587');
  }
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    throw new SmtpConfigError('port must be an integer between 1 and 65535');
  }

  const requireTLS = options.requireTLS ?? true;

  const tls: TlsOptions = {};
  if (options.tls) {
    if (options.tls.ca !== undefined) {
      if (typeof options.tls.ca !== 'string') throw new SmtpConfigError('tls.ca must be a PEM string');
      tls.ca = options.tls.ca;
    }
    if (options.tls.cert !== undefined) tls.cert = requireString(options.tls.cert, 'tls.cert');
    if (options.tls.key !== undefined) tls.key = requireString(options.tls.key, 'tls.key');
    if (options.tls.pinnedCertSha256 !== undefined) {
      tls.pinnedCertSha256 = requireString(options.tls.pinnedCertSha256, 'tls.pinnedCertSha256');
    }
    if (options.tls.servername !== undefined) {
      tls.servername = requireString(options.tls.servername, 'tls.servername');
    }
    if (options.tls.minVersion !== undefined) {
      if (options.tls.minVersion !== 'TLSv1.2' && options.tls.minVersion !== 'TLSv1.3') {
        throw new SmtpConfigError('tls.minVersion must be TLSv1.2 or TLSv1.3');
      }
      tls.minVersion = options.tls.minVersion;
    }
  }
  tls.minVersion = tls.minVersion ?? 'TLSv1.2';

  // Determine the identity used for certificate verification. For a bare-IP
  // host an explicit servername is required (SEC-11).
  let servername: string;
  if (isIP(host)) {
    if (!tls.servername) {
      throw new SmtpConfigError(
        'host is a bare IP address; set tls.servername to the expected certificate hostname',
      );
    }
    servername = tls.servername;
  } else {
    servername = tls.servername ?? host;
  }

  validateAuth(options.auth);

  const clientId = options.clientId ?? '[127.0.0.1]';

  return {
    host,
    port: port as number,
    secure,
    requireTLS,
    auth: options.auth,
    tls,
    servername,
    timeouts: mergeTimeouts(DEFAULT_TIMEOUTS, options.timeouts),
    caps: mergeCaps(DEFAULT_CAPS, options.caps),
    logger: options.logger,
    clientId,
  };
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new SmtpConfigError(`${name} must be a string`);
  return value;
}

function validateAuth(auth: AuthConfig | undefined): void {
  if (auth === undefined) return;
  if (auth === null || typeof auth !== 'object') {
    throw new SmtpConfigError('auth must be an object');
  }
  if (typeof (auth as { user?: unknown }).user !== 'string') {
    throw new SmtpConfigError('auth.user is required');
  }
  if ('type' in auth && auth.type === 'oauth2') {
    const hasStatic = typeof (auth as { accessToken?: unknown }).accessToken === 'string';
    const hasProvider = typeof (auth as { tokenProvider?: unknown }).tokenProvider === 'function';
    if (!hasStatic && !hasProvider) {
      throw new SmtpConfigError('OAuth2 auth requires accessToken or tokenProvider');
    }
  } else {
    if (typeof (auth as { pass?: unknown }).pass !== 'string') {
      throw new SmtpConfigError('password auth requires auth.pass');
    }
  }
}
