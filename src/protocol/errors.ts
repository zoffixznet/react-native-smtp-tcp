/**
 * Error taxonomy for the SMTP client. Errors never carry credential material.
 *
 * `transient` marks failures that a caller may retry (4yz replies, mid-dialog
 * connection loss treated as 451, temporary AUTH failures). Permanent failures
 * are `transient: false` and should not be retried with the same inputs.
 */

/** Base class for every error thrown by this library. */
export class SmtpError extends Error {
  /** True when the operation may be safely retried later. */
  readonly transient: boolean;
  /** SMTP reply code that caused the error, when applicable. */
  readonly code?: number;
  /** Enhanced status code (class.subject.detail) when the server sent one. */
  readonly enhancedCode?: string;

  constructor(
    message: string,
    opts: { transient?: boolean; code?: number; enhancedCode?: string } = {},
  ) {
    super(message);
    this.name = new.target.name;
    this.transient = opts.transient ?? false;
    this.code = opts.code;
    this.enhancedCode = opts.enhancedCode;
    // Restore the prototype chain for extended built-ins.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Configuration was invalid (bad options, unsafe request). Never retryable. */
export class SmtpConfigError extends SmtpError {
  constructor(message: string) {
    super(message, { transient: false });
  }
}

/** A message could not be built safely (injection attempt, size limit, etc.). */
export class SmtpMessageError extends SmtpError {
  constructor(message: string) {
    super(message, { transient: false });
  }
}

/** The protocol was violated by the peer, or a security invariant failed. */
export class SmtpProtocolError extends SmtpError {}

/** A required security guarantee (TLS, cert validation) could not be met. */
export class SmtpSecurityError extends SmtpError {
  constructor(message: string) {
    super(message, { transient: false });
  }
}

/** Authentication failed. Message is always generic; never leaks credentials. */
export class SmtpAuthError extends SmtpError {}

/** A timeout fired (connect, greeting, idle, or overall deadline). Transient. */
export class SmtpTimeoutError extends SmtpError {
  constructor(message: string) {
    super(message, { transient: true });
  }
}

/** The connection closed or reset mid-dialog. Treated as transient (451). */
export class SmtpConnectionError extends SmtpError {
  constructor(message: string) {
    super(message, { transient: true });
  }
}
