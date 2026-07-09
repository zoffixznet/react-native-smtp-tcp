/**
 * The SMTP connection and transaction state machine.
 *
 * Drives a single connection through greeting, EHLO/HELO, optional STARTTLS
 * (with the drain-before-wrap invariant and post-TLS re-EHLO), AUTH (gated
 * behind a validated-TLS channel), and the MAIL/RCPT/DATA transaction. It works
 * against the injectable {@link SmtpTransport}, so it has no React Native or
 * Node imports.
 *
 * Security invariants enforced here:
 * - No AUTH, MAIL, RCPT, or DATA is written before an encrypted, validated
 *   channel exists when the account is secure (SEC-2, SEC-12).
 * - The STARTTLS 220 is read with a line-exact reader; the read buffer must be
 *   empty afterwards or the connection aborts; plaintext listeners are detached
 *   before the wrap (SEC-3, SEC-5).
 * - All pre-TLS capability knowledge is discarded and EHLO is re-issued inside
 *   TLS (SEC-4).
 * - Layered timeouts and an overall deadline bound every step (SEC-22).
 * - Mid-dialog EOF/close/reset is treated as a transient failure; a message is
 *   never reported sent on a partial reply (SEC-23).
 */

import { Buffer } from 'buffer';
import { ReplyReader } from './reply-reader';
import {
  ReplyParser,
  isPositive,
  isPermanent,
  isTransient,
} from './reply-parser';
import {
  encodeLoginPass,
  encodeLoginUser,
  encodePlain,
  encodeXOAuth2,
  selectMechanism,
} from './sasl';
import { redactAuthExchangeLine, redactAuthReply, redactCommand } from './redact';
import {
  SmtpAuthError,
  SmtpConnectionError,
  SmtpProtocolError,
  SmtpSecurityError,
  SmtpTimeoutError,
} from './errors';
import { validateClientId } from '../message/validate';
import type {
  AuthConfig,
  Capabilities,
  Caps,
  Logger,
  SmtpReply,
  SmtpTransport,
  Timeouts,
  TlsUpgradeOptions,
} from './types';

const CRLF = '\r\n';

/** Options controlling the client's behavior on one connection. */
export interface ClientOptions {
  host: string;
  clientId: string;
  secure: 'implicit' | 'starttls';
  requireTLS: boolean;
  auth?: AuthConfig;
  caps: Caps;
  timeouts: Timeouts;
  logger?: Logger;
  tlsUpgradeOptions: TlsUpgradeOptions;
  /**
   * Called after the TLS handshake with the transport, so the caller can run
   * hostname and pinning checks. Must throw (a SmtpSecurityError) to reject.
   */
  verifyTlsChannel: (transport: SmtpTransport) => void;
}

/** Internal channel-security state. */
interface ChannelState {
  encrypted: boolean;
  validated: boolean;
}

/** A pending command awaiting its reply. */
interface Pending {
  resolve: (reply: SmtpReply) => void;
  reject: (err: Error) => void;
}

export class SmtpClient {
  private transport: SmtpTransport;
  private reader: ReplyReader;
  private parser = new ReplyParser();
  private caps: Caps;
  private timeouts: Timeouts;
  private opts: ClientOptions;

  private channel: ChannelState = { encrypted: false, validated: false };
  private capabilities: Capabilities | null = null;

  private pending: Pending | null = null;
  /** Replies that completed before a consumer was waiting (e.g. the greeting
   * arriving in the same tick the handler is armed). Delivered in order. */
  private replyQueue: SmtpReply[] = [];
  private closed = false;
  private closedError: Error | null = null;
  private hadError = false;

  private overallDeadline = 0;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private overallTimer: ReturnType<typeof setTimeout> | null = null;

  private dataListener: (chunk: Uint8Array) => void;
  private errorListener: (err: Error) => void;
  private closeListener: (hadError: boolean) => void;

  constructor(transport: SmtpTransport, opts: ClientOptions) {
    this.transport = transport;
    this.opts = opts;
    this.caps = opts.caps;
    this.timeouts = opts.timeouts;
    this.reader = new ReplyReader(this.caps);

    this.dataListener = (chunk) => this.onData(chunk);
    this.errorListener = (err) => this.onError(err);
    this.closeListener = (had) => this.onClose(had);

    this.transport.on('data', this.dataListener);
    this.transport.on('error', this.errorListener);
    this.transport.on('close', this.closeListener);
  }

  // --- Public flow ---------------------------------------------------------

  /** Connect flow up to a validated, EHLO'd, authenticated channel. */
  async connect(): Promise<Capabilities> {
    this.startOverallDeadline();
    if (this.opts.secure === 'implicit') {
      await this.waitForSecureConnect();
      this.channel.encrypted = true;
      this.runTlsChannelVerification();
      await this.readGreeting();
      await this.ehlo();
    } else {
      await this.waitForConnect();
      await this.readGreeting();
      await this.ehlo();
      await this.startTls();
    }
    if (this.opts.auth) {
      await this.authenticate(this.opts.auth);
    }
    return this.capabilities!;
  }

  /** Access the negotiated capabilities (post-TLS). */
  getCapabilities(): Capabilities | null {
    return this.capabilities;
  }

  /** Whether the channel is encrypted and validated. */
  isSecure(): boolean {
    return this.channel.encrypted && this.channel.validated;
  }

  /** Send QUIT and close the connection cleanly. Never throws. */
  async quit(): Promise<void> {
    if (this.closed) return;
    try {
      await this.command('QUIT', { expect: [221], idempotentClose: true });
    } catch {
      // Ignore errors on QUIT; we are closing anyway.
    }
    this.close();
  }

  /** Force-close the connection. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimers();
    try {
      this.transport.removeListener('data', this.dataListener);
      this.transport.removeListener('error', this.errorListener);
      this.transport.removeListener('close', this.closeListener);
      this.transport.destroy();
    } catch {
      // best effort
    }
  }

  // --- Transaction ---------------------------------------------------------

  /**
   * Run one message transaction. `from` and recipients are already validated
   * addr-specs (no brackets). `data` is the serialized message (un-dot-stuffed).
   * Returns accepted/rejected recipients and the final response.
   */
  async sendTransaction(input: {
    from: string;
    to: string[];
    data: string;
    sizeBytes: number;
    smtpUtf8: boolean;
    eightBitMime: boolean;
  }): Promise<{ accepted: string[]; rejected: string[]; response: string }> {
    this.assertReadyToSend();

    const params: string[] = [];
    const caps = this.capabilities!;
    if (caps.size !== undefined && caps.size > 0) {
      if (input.sizeBytes > caps.size) {
        throw new SmtpProtocolError(
          `message size ${input.sizeBytes} exceeds the server limit of ${caps.size}`,
          { transient: false, code: 552 },
        );
      }
      params.push(`SIZE=${input.sizeBytes}`);
    }
    if (input.eightBitMime && caps.eightBitMime) {
      // The body is 7-bit safe (quoted-printable), so BODY=7BIT is accurate;
      // advertise 8BITMIME support alignment only when actually sending 8-bit.
      // We keep the body 7-bit, so no BODY parameter is required.
    }
    if (input.smtpUtf8 && caps.smtpUtf8) {
      params.push('SMTPUTF8');
    }

    const mailCmd = `MAIL FROM:<${input.from}>${params.length ? ' ' + params.join(' ') : ''}`;
    const mailReply = await this.command(mailCmd, { expect: [250] });
    void mailReply;

    const accepted: string[] = [];
    const rejected: string[] = [];
    for (const rcpt of input.to) {
      const reply = await this.command(`RCPT TO:<${rcpt}>`, { expect: null });
      if (isPositive(reply.code)) {
        accepted.push(rcpt);
      } else if (isPermanent(reply.code)) {
        // For a single-user submission, a rejected recipient fails the whole
        // send cleanly: reset the transaction and raise.
        rejected.push(rcpt);
        await this.reset();
        throw new SmtpProtocolError(
          `recipient ${rcpt} was rejected (${reply.code})`,
          { transient: false, code: reply.code, enhancedCode: enhancedStr(reply) },
        );
      } else {
        rejected.push(rcpt);
        await this.reset();
        throw new SmtpProtocolError(
          `recipient ${rcpt} was temporarily rejected (${reply.code})`,
          { transient: true, code: reply.code, enhancedCode: enhancedStr(reply) },
        );
      }
    }
    if (accepted.length === 0) {
      await this.reset();
      throw new SmtpProtocolError('no recipients were accepted', { transient: false });
    }

    // DATA
    await this.command('DATA', { expect: [354] });
    const payload = dotStuff(ensureTrailingCrlf(input.data)) + '.' + CRLF;
    const finalReply = await this.writeData(payload);
    if (!isPositive(finalReply.code)) {
      throw new SmtpProtocolError(
        `message was not accepted (${finalReply.code})`,
        {
          transient: isTransient(finalReply.code),
          code: finalReply.code,
          enhancedCode: enhancedStr(finalReply),
        },
      );
    }
    return { accepted, rejected, response: `${finalReply.code} ${finalReply.text}` };
  }

  private assertReadyToSend(): void {
    if (!this.capabilities) {
      throw new SmtpProtocolError('cannot send before EHLO negotiation');
    }
    if (this.opts.requireTLS && !this.isSecure()) {
      throw new SmtpSecurityError(
        'refusing to send: the channel is not encrypted and validated',
      );
    }
  }

  /** RSET to abort the current transaction. */
  async reset(): Promise<void> {
    try {
      await this.command('RSET', { expect: [250] });
    } catch {
      // If RSET fails the connection is unusable; ignore and let the caller
      // close. A failed RSET does not change the send outcome.
    }
  }

  // --- EHLO / HELO ---------------------------------------------------------

  private async ehlo(): Promise<void> {
    validateClientId(this.opts.clientId);
    const reply = await this.command(`EHLO ${this.opts.clientId}`, { expect: null });
    if (isPositive(reply.code)) {
      this.capabilities = parseCapabilities(reply);
      if (this.capabilities.enhancedStatusCodes) {
        // no-op flag; parser already handles enhanced codes when present
      }
      return;
    }
    // Fall back to HELO only on a 5xx "command not recognized" (500/502), never
    // on a 4xx transient.
    if (reply.code === 500 || reply.code === 502) {
      const helo = await this.command(`HELO ${this.opts.clientId}`, { expect: [250] });
      this.capabilities = {
        greeting: helo.lines[0] ?? '',
        startTls: false,
        pipelining: false,
        eightBitMime: false,
        smtpUtf8: false,
        enhancedStatusCodes: false,
        authMechanisms: [],
        raw: new Map(),
      };
      return;
    }
    if (isTransient(reply.code)) {
      throw new SmtpProtocolError(`EHLO failed transiently (${reply.code})`, {
        transient: true,
        code: reply.code,
      });
    }
    throw new SmtpProtocolError(`EHLO failed (${reply.code})`, {
      transient: false,
      code: reply.code,
    });
  }

  // --- STARTTLS ------------------------------------------------------------

  private async startTls(): Promise<void> {
    const caps = this.capabilities!;
    if (!caps.startTls) {
      // STARTTLS not advertised (stripped/garbled). A secure account must not
      // continue in cleartext.
      throw new SmtpSecurityError(
        'server does not advertise STARTTLS; refusing to continue in cleartext',
      );
    }

    // Send STARTTLS and read exactly its 220 reply with the line-exact reader.
    // STARTTLS is the last command sent on the plaintext channel; nothing is
    // pipelined after it.
    const reply = await this.command('STARTTLS', { expect: null, isStartTls: true });
    if (reply.code !== 220) {
      // e.g. "454 4.7.0 TLS not available": abort, no plaintext continuation.
      throw new SmtpSecurityError(
        `STARTTLS was refused (${reply.code}); refusing to continue in cleartext`,
      );
    }

    // Drain-before-wrap (SEC-3, CVE-2011-0411 / CVE-2026-41319 class): after the
    // single STARTTLS 220 line, NOTHING may remain to be processed. This covers
    // three ways a hostile server can smuggle bytes across the TLS boundary:
    //   - residual bytes still buffered in the reader (partial extra line),
    //   - a fully parsed extra reply that was queued after the 220,
    //   - a continuation line that left the parser mid-reply.
    // Any of these is a response/command injection attempt; abort before TLS.
    if (
      this.reader.hasBufferedBytes() ||
      this.replyQueue.length > 0 ||
      this.parser.inProgress()
    ) {
      throw new SmtpSecurityError(
        'unexpected data received after the STARTTLS reply; aborting before TLS',
      );
    }

    // Detach the plaintext data listener before wrapping so no plaintext handler
    // races the TLS bytes.
    this.transport.removeListener('data', this.dataListener);
    this.reader.reset();
    this.parser.reset();

    // Upgrade in place. The returned transport emits 'secureConnect'.
    const secure = this.transport.upgradeToTLS(this.opts.tlsUpgradeOptions);
    this.swapTransport(secure);
    await this.waitForSecureConnect();
    this.channel.encrypted = true;

    // Post-handshake identity and pinning checks.
    this.runTlsChannelVerification();

    // Discard ALL pre-TLS capability knowledge and re-issue EHLO inside TLS.
    this.capabilities = null;
    await this.ehlo();
  }

  private runTlsChannelVerification(): void {
    try {
      // Post-handshake protocol-version floor. On the RN/device path the native
      // module offers no pre-handshake min-version knob, so this is the only
      // place a downgraded handshake (TLS 1.0/1.1) can be refused. It is
      // best-effort: it only fires when the transport can report the negotiated
      // version, and it never lowers the Node path's pre-handshake enforcement.
      this.enforceMinProtocolVersion();
      this.opts.verifyTlsChannel(this.transport);
      this.channel.validated = true;
    } catch (err) {
      this.channel.validated = false;
      // Destroy immediately so nothing sensitive can be sent.
      this.close();
      if (err instanceof SmtpSecurityError) throw err;
      throw new SmtpSecurityError(
        `TLS channel verification failed: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Refuse a negotiated TLS version below the configured minimum. This gives the
   * RN/device transport a post-handshake floor it otherwise lacks (the native
   * module cannot set minVersion pre-handshake). When the transport does not
   * report a protocol, this is a no-op (best effort).
   */
  private enforceMinProtocolVersion(): void {
    const min = this.opts.tlsUpgradeOptions.minVersion;
    const negotiated = this.transport.getProtocol?.();
    if (!min || !negotiated) return;
    if (tlsVersionRank(negotiated) < tlsVersionRank(min)) {
      throw new SmtpSecurityError(
        `the negotiated TLS version ${negotiated} is below the required minimum ${min}`,
      );
    }
  }

  // --- AUTH ----------------------------------------------------------------

  private async authenticate(auth: AuthConfig): Promise<void> {
    // AUTH only over an encrypted, validated channel.
    if (!this.isSecure()) {
      throw new SmtpSecurityError(
        'refusing to authenticate before an encrypted, validated channel exists',
      );
    }
    const caps = this.capabilities!;
    const wantOAuth2 = 'type' in auth && auth.type === 'oauth2';
    const mech = selectMechanism(caps.authMechanisms, wantOAuth2);
    if (mech === null) {
      throw new SmtpAuthError(
        'no acceptable authentication mechanism is advertised by the server',
        { transient: false },
      );
    }

    if (mech === 'XOAUTH2') {
      const token = await resolveToken(auth);
      await this.authXOAuth2((auth as { user: string }).user, token);
      return;
    }

    const user = (auth as { user: string }).user;
    const pass = (auth as { pass: string }).pass;
    if (mech === 'PLAIN') {
      await this.authPlain(user, pass);
    } else {
      await this.authLogin(user, pass);
    }
  }

  private async authPlain(user: string, pass: string): Promise<void> {
    const ir = encodePlain(user, pass);
    const reply = await this.command(`AUTH PLAIN ${ir}`, { expect: null, isAuth: true });
    this.assertAuthResult(reply);
  }

  private async authLogin(user: string, pass: string): Promise<void> {
    const start = await this.command('AUTH LOGIN', { expect: null, isAuth: true });
    if (start.code !== 334) {
      this.assertAuthResult(start);
      return;
    }
    const afterUser = await this.command(encodeLoginUser(user), {
      expect: null,
      isAuth: true,
      isAuthExchange: true,
    });
    if (afterUser.code !== 334) {
      this.assertAuthResult(afterUser);
      return;
    }
    const afterPass = await this.command(encodeLoginPass(pass), {
      expect: null,
      isAuth: true,
      isAuthExchange: true,
    });
    this.assertAuthResult(afterPass);
  }

  private async authXOAuth2(user: string, token: string): Promise<void> {
    const ir = encodeXOAuth2(user, token);
    const reply = await this.command(`AUTH XOAUTH2 ${ir}`, { expect: null, isAuth: true });
    if (reply.code === 334) {
      // Error challenge: send an empty line, then read the final failure and
      // surface it generically.
      const final = await this.command('', {
        expect: null,
        isAuth: true,
        isAuthExchange: true,
      });
      this.assertAuthResult(final);
      return;
    }
    this.assertAuthResult(reply);
  }

  /**
   * Map an AUTH reply to success or a generic failure. Never distinguishes bad
   * user from bad password, never includes credential material, and treats
   * permanent failures as non-retryable.
   */
  private assertAuthResult(reply: SmtpReply): void {
    if (reply.code === 235) return;
    if (reply.code === 454) {
      throw new SmtpAuthError('authentication failed temporarily', {
        transient: true,
        code: 454,
      });
    }
    if (reply.code === 432) {
      throw new SmtpAuthError('a password transition is required', {
        transient: false,
        code: 432,
      });
    }
    // 535, 534, 530, 538, and anything else: single generic permanent failure.
    throw new SmtpAuthError('authentication failed', {
      transient: false,
      code: reply.code,
    });
  }

  // --- Command / reply plumbing --------------------------------------------

  /**
   * Send a command line and await its reply. `expect` optionally asserts the
   * final code; when null the caller inspects the reply itself. Security flags
   * control redaction and the STARTTLS handling.
   */
  private command(
    line: string,
    opts: {
      expect: number[] | null;
      isAuth?: boolean;
      isAuthExchange?: boolean;
      isStartTls?: boolean;
      idempotentClose?: boolean;
    },
  ): Promise<SmtpReply> {
    return new Promise<SmtpReply>((resolve, reject) => {
      if (this.closed) {
        reject(this.closedError ?? new SmtpConnectionError('connection is closed'));
        return;
      }
      if (this.pending) {
        reject(new SmtpProtocolError('internal: a command is already in flight'));
        return;
      }

      // Command-line length guard (RFC 5321 command line <= 512 octets). AUTH
      // initial responses can legitimately exceed this on some servers, but the
      // hard cap protects the plaintext channel; we allow AUTH lines up to the
      // reply line cap and bound everything else at 512.
      const wire = line + CRLF;
      const limit = opts.isAuth || opts.isAuthExchange ? this.caps.maxLineBytes : 512;
      if (Buffer.byteLength(wire, 'utf8') > limit) {
        reject(new SmtpProtocolError('command line exceeds the maximum length'));
        return;
      }

      this._duringAuth = Boolean(opts.isAuth || opts.isAuthExchange);
      this.log(opts, line);

      this.armIdleTimer();
      this.transport.write(wire, (err) => {
        if (err) {
          this.failPending(new SmtpConnectionError(`write failed: ${err.message}`));
        }
      });

      this.setPending({
        resolve: (reply) => {
          if (opts.expect && !opts.expect.includes(reply.code)) {
            const err = new SmtpProtocolError(
              `unexpected reply ${reply.code} to ${firstWord(line)}`,
              {
                transient: isTransient(reply.code),
                code: reply.code,
                enhancedCode: enhancedStr(reply),
              },
            );
            reject(err);
            return;
          }
          resolve(reply);
        },
        reject,
      });
    });
  }

  private writeData(payload: string): Promise<SmtpReply> {
    return new Promise<SmtpReply>((resolve, reject) => {
      if (this.closed) {
        reject(this.closedError ?? new SmtpConnectionError('connection is closed'));
        return;
      }
      this.armIdleTimer();
      this.transport.write(payload, (err) => {
        if (err) this.failPending(new SmtpConnectionError(`write failed: ${err.message}`));
      });
      this.setPending({ resolve, reject });
    });
  }

  private log(
    opts: { isAuth?: boolean; isAuthExchange?: boolean },
    line: string,
  ): void {
    const logger = this.opts.logger;
    if (!logger || !logger.debug) return;
    let out: string;
    if (opts.isAuthExchange) {
      out = redactAuthExchangeLine();
    } else if (opts.isAuth) {
      out = redactCommand(line);
    } else {
      out = redactCommand(line);
    }
    logger.debug(`C: ${out}`);
  }

  private onData(chunk: Uint8Array): void {
    if (this.closed) return;
    this.armIdleTimer();
    let lines: string[];
    try {
      lines = this.reader.push(chunk);
    } catch (err) {
      this.failPending(err as Error);
      this.close();
      return;
    }
    for (const line of lines) {
      let step;
      try {
        step = this.parser.push(line);
      } catch (err) {
        this.failPending(err as Error);
        this.close();
        return;
      }
      if (this.opts.logger && this.opts.logger.debug) {
        // Redact replies during an AUTH exchange (they may echo challenges).
        this.opts.logger.debug(`S: ${this._duringAuth ? redactAuthReply(line) : line}`);
      }
      if (step.done) {
        this.reader.finishReply();
        const p = this.pending;
        this.pending = null;
        this.clearIdleTimer();
        if (p) {
          p.resolve(step.reply);
        } else {
          // No consumer is waiting yet (e.g. the greeting arrived in the same
          // tick the handler is being armed). Queue it for the next waiter, but
          // never let the queue grow without bound: a hostile server that paces
          // unsolicited replies across TCP segments would otherwise OOM the
          // client (the per-reply parser caps reset between replies). Fail
          // closed once the queue exceeds its cap.
          if (this.replyQueue.length >= this.caps.maxQueuedReplies) {
            const err = new SmtpProtocolError(
              'server sent more unsolicited replies than allowed; aborting',
            );
            this.failPending(err);
            this.closedError = this.closedError ?? err;
            this.close();
            return;
          }
          this.replyQueue.push(step.reply);
        }
      }
    }
  }

  /** Assign the pending handler, delivering a queued reply immediately if one
   * is already available so no reply is lost to a scheduling race. If the
   * connection already closed, reject at once rather than waiting forever. */
  private setPending(p: Pending): void {
    const queued = this.replyQueue.shift();
    if (queued !== undefined) {
      this.clearIdleTimer();
      p.resolve(queued);
      return;
    }
    if (this.closed) {
      this.clearIdleTimer();
      p.reject(
        this.closedError ??
          new SmtpConnectionError('connection closed before the reply completed'),
      );
      return;
    }
    this.pending = p;
  }

  /** True while the pending command is part of an AUTH exchange (replies are
   * redacted while this is set). */
  private _duringAuth = false;

  private onError(err: Error): void {
    this.hadError = true;
    const wrapped =
      err instanceof SmtpTimeoutError
        ? err
        : new SmtpConnectionError(`socket error: ${err.message}`);
    this.failPending(wrapped);
    this.close();
  }

  private onClose(hadError: boolean): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimers();
    // Mid-dialog close with a command in flight is a transient failure (451).
    this.failPending(
      new SmtpConnectionError(
        hadError || this.hadError
          ? 'connection closed unexpectedly during the SMTP dialog'
          : 'connection closed before the reply completed',
      ),
    );
  }

  private failPending(err: Error): void {
    this.closedError = this.closedError ?? err;
    const p = this.pending;
    this.pending = null;
    this.clearIdleTimer();
    if (p) p.reject(err);
  }

  // --- Greeting / connect --------------------------------------------------

  private readGreeting(): Promise<SmtpReply> {
    return new Promise<SmtpReply>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new SmtpTimeoutError('timed out waiting for the server greeting'));
        this.close();
      }, this.timeouts.greetingMs);

      this.setPending({
        resolve: (reply) => {
          clearTimeout(timer);
          if (reply.code !== 220) {
            reject(
              new SmtpProtocolError(`unexpected greeting code ${reply.code}`, {
                transient: isTransient(reply.code),
                code: reply.code,
              }),
            );
            return;
          }
          resolve(reply);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
    });
  }

  private waitForConnect(): Promise<void> {
    return this.waitForEvent('connect', this.timeouts.connectMs, 'connection');
  }

  private waitForSecureConnect(): Promise<void> {
    return this.waitForEvent('secureConnect', this.timeouts.connectMs, 'TLS handshake');
  }

  private waitForEvent(event: 'connect' | 'secureConnect', ms: number, label: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const onEvent = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.transport.removeListener('error', onErr);
        resolve();
      };
      const onErr = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.transport.removeListener(event, onEvent);
        reject(new SmtpConnectionError(`${label} failed: ${err.message}`));
      };
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.transport.removeListener(event, onEvent);
        this.transport.removeListener('error', onErr);
        reject(new SmtpTimeoutError(`${label} timed out`));
        this.close();
      }, ms);
      this.transport.once(event, onEvent);
      this.transport.once('error', onErr);
    });
  }

  private swapTransport(next: SmtpTransport): void {
    // Move error/close listeners to the new (wrapped) transport.
    this.transport.removeListener('error', this.errorListener);
    this.transport.removeListener('close', this.closeListener);
    this.transport = next;
    this.transport.on('data', this.dataListener);
    this.transport.on('error', this.errorListener);
    this.transport.on('close', this.closeListener);
  }

  // --- Timers --------------------------------------------------------------

  private startOverallDeadline(): void {
    this.overallDeadline = Date.now() + this.timeouts.overallMs;
    this.overallTimer = setTimeout(() => {
      this.failPending(new SmtpTimeoutError('the overall operation deadline was exceeded'));
      this.close();
    }, this.timeouts.overallMs);
  }

  private armIdleTimer(): void {
    this.clearIdleTimer();
    const remaining = this.overallDeadline - Date.now();
    // The idle timer is the smaller of the idle window and the time left before
    // the overall deadline, so a slow trickle still hits the overall deadline.
    const ms = Math.max(1, Math.min(this.timeouts.idleMs, remaining));
    this.idleTimer = setTimeout(() => {
      this.failPending(new SmtpTimeoutError('idle timeout waiting for a reply'));
      this.close();
    }, ms);
  }

  private clearIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  private clearTimers(): void {
    this.clearIdleTimer();
    if (this.overallTimer) {
      clearTimeout(this.overallTimer);
      this.overallTimer = null;
    }
  }
}

// --- Free helpers ----------------------------------------------------------

/**
 * Rank a TLS protocol string for a floor comparison. Higher is newer. Unknown or
 * pre-1.2 versions rank at or below TLS 1.0 so they never satisfy a >=1.2 floor.
 */
export function tlsVersionRank(version: string): number {
  switch (version) {
    case 'TLSv1.3':
      return 4;
    case 'TLSv1.2':
      return 3;
    case 'TLSv1.1':
      return 2;
    case 'TLSv1':
    case 'TLSv1.0':
      return 1;
    default:
      // SSLv3 and anything unrecognized are treated as the weakest.
      return 0;
  }
}

/** Ensure the body ends with a CRLF before the terminating dot is appended. */
function ensureTrailingCrlf(data: string): string {
  if (data.endsWith(CRLF)) return data;
  if (data.endsWith('\n')) return data.slice(0, -1) + CRLF;
  return data + CRLF;
}

/**
 * Dot-stuff a CRLF-delimited payload: any line beginning with '.' gets an extra
 * leading '.'. Operates line by line on already-CRLF content.
 */
export function dotStuff(data: string): string {
  // Split on CRLF, add a dot to lines starting with '.', rejoin with CRLF.
  const lines = data.split(CRLF);
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('.')) {
      lines[i] = '.' + lines[i];
    }
  }
  return lines.join(CRLF);
}

/** Parse the EHLO reply into capabilities. */
export function parseCapabilities(reply: SmtpReply): Capabilities {
  const raw = new Map<string, string>();
  let startTls = false;
  let pipelining = false;
  let eightBitMime = false;
  let smtpUtf8 = false;
  let enhancedStatusCodes = false;
  let size: number | undefined;
  const authMechanisms: string[] = [];

  // The first line is the greeting/domain; subsequent lines are capabilities.
  const greeting = reply.lines[0] ?? '';
  for (let i = 1; i < reply.lines.length; i++) {
    const line = reply.lines[i].trim();
    if (line.length === 0) continue;
    const spaceIdx = line.indexOf(' ');
    const keyword = (spaceIdx === -1 ? line : line.slice(0, spaceIdx)).toUpperCase();
    const args = spaceIdx === -1 ? '' : line.slice(spaceIdx + 1);
    raw.set(keyword, line);
    switch (keyword) {
      case 'STARTTLS':
        startTls = true;
        break;
      case 'PIPELINING':
        pipelining = true;
        break;
      case '8BITMIME':
        eightBitMime = true;
        break;
      case 'SMTPUTF8':
        smtpUtf8 = true;
        break;
      case 'ENHANCEDSTATUSCODES':
        enhancedStatusCodes = true;
        break;
      case 'SIZE': {
        const n = parseInt(args.trim(), 10);
        if (Number.isFinite(n) && n >= 0) size = n;
        break;
      }
      case 'AUTH': {
        for (const m of args.split(/\s+/)) {
          if (m) authMechanisms.push(m.toUpperCase());
        }
        break;
      }
      default:
        break;
    }
  }

  return {
    greeting,
    startTls,
    pipelining,
    eightBitMime,
    smtpUtf8,
    enhancedStatusCodes,
    size,
    authMechanisms,
    raw,
  };
}

function firstWord(line: string): string {
  const idx = line.indexOf(' ');
  return idx === -1 ? line : line.slice(0, idx);
}

function enhancedStr(reply: SmtpReply): string | undefined {
  return reply.enhanced
    ? `${reply.enhanced.class}.${reply.enhanced.subject}.${reply.enhanced.detail}`
    : undefined;
}

async function resolveToken(auth: AuthConfig): Promise<string> {
  if ('accessToken' in auth && typeof auth.accessToken === 'string') {
    return auth.accessToken;
  }
  if ('tokenProvider' in auth && typeof auth.tokenProvider === 'function') {
    const token = await auth.tokenProvider();
    if (typeof token !== 'string' || token.length === 0) {
      throw new SmtpAuthError('the token provider returned an invalid token', {
        transient: true,
      });
    }
    return token;
  }
  throw new SmtpAuthError('OAuth2 auth requires an accessToken or tokenProvider', {
    transient: false,
  });
}
