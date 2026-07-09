/**
 * Line-exact, byte-bounded reply reader.
 *
 * Feeds incoming socket bytes in and yields complete reply lines. It enforces
 * the DoS caps so a hostile server cannot make the client buffer without bound:
 * a per-line byte cap, a per-reply total byte cap, and a per-reply continuation
 * line cap. It never accumulates an unbounded buffer waiting for CRLF.
 *
 * It is deliberately not a parser: it splits on CRLF, tracks how many bytes have
 * been consumed toward the current reply, and hands whole lines to the caller.
 * The caller (the reply parser) decides when a reply is complete.
 *
 * A key security property for STARTTLS: after reading the single 220 line, the
 * caller can ask whether any residual bytes remain in the buffer. If bytes
 * remain after the terminating CRLF of the 220 line, the connection must abort
 * (drain-before-wrap). This class exposes {@link hasBufferedBytes} for that.
 */

import { Buffer } from 'buffer';
import type { Caps } from './types';
import { SmtpProtocolError } from './errors';

const CR = 0x0d;
const LF = 0x0a;

export class ReplyReader {
  private buffer: Buffer = Buffer.alloc(0);
  /** Bytes consumed toward the reply currently being assembled. */
  private replyBytes = 0;
  /** Lines emitted for the reply currently being assembled. */
  private replyLines = 0;

  constructor(private readonly caps: Caps) {}

  /**
   * Append incoming bytes and return any complete lines now available. Each
   * returned string is the line content without the trailing CRLF. Throws
   * {@link SmtpProtocolError} if a cap is breached.
   */
  push(chunk: Uint8Array): string[] {
    const incoming = Buffer.from(chunk);
    // Guard the standing buffer size before appending so a giant no-CRLF line
    // cannot grow memory without bound.
    if (this.buffer.length + incoming.length > this.caps.maxLineBytes) {
      // It is only a violation if there is no CRLF within the cap window. Search
      // the combined view up to the cap for a CRLF; if none, abort.
      const combinedLen = this.buffer.length + incoming.length;
      const searchLen = Math.min(combinedLen, this.caps.maxLineBytes + 2);
      const view = Buffer.concat([this.buffer, incoming]).subarray(0, searchLen);
      if (view.indexOf(LF) === -1) {
        throw new SmtpProtocolError(
          `reply line exceeds the maximum of ${this.caps.maxLineBytes} bytes`,
          { transient: false },
        );
      }
    }

    this.buffer = this.buffer.length === 0 ? incoming : Buffer.concat([this.buffer, incoming]);

    const lines: string[] = [];
    let searchStart = 0;
    for (;;) {
      const lfIndex = this.buffer.indexOf(LF, searchStart);
      if (lfIndex === -1) {
        // No complete line yet. Enforce the per-line cap on the pending bytes.
        if (this.buffer.length - searchStart > this.caps.maxLineBytes) {
          throw new SmtpProtocolError(
            `reply line exceeds the maximum of ${this.caps.maxLineBytes} bytes`,
            { transient: false },
          );
        }
        break;
      }
      // Extract the line up to (not including) LF; strip a preceding CR.
      let lineEnd = lfIndex;
      if (lineEnd > searchStart && this.buffer[lineEnd - 1] === CR) {
        lineEnd -= 1;
      }
      const lineBuf = this.buffer.subarray(searchStart, lineEnd);
      if (lineBuf.length > this.caps.maxLineBytes) {
        throw new SmtpProtocolError(
          `reply line exceeds the maximum of ${this.caps.maxLineBytes} bytes`,
          { transient: false },
        );
      }
      const line = lineBuf.toString('utf8');

      // Per-reply accounting.
      this.replyBytes += lfIndex - searchStart + 1;
      this.replyLines += 1;
      if (this.replyBytes > this.caps.maxReplyBytes) {
        throw new SmtpProtocolError(
          `reply exceeds the maximum of ${this.caps.maxReplyBytes} bytes`,
          { transient: false },
        );
      }
      if (this.replyLines > this.caps.maxContinuationLines + 1) {
        throw new SmtpProtocolError(
          `reply exceeds the maximum of ${this.caps.maxContinuationLines} continuation lines`,
          { transient: false },
        );
      }

      lines.push(line);
      searchStart = lfIndex + 1;
    }

    // Drop consumed bytes from the buffer.
    if (searchStart > 0) {
      this.buffer = this.buffer.subarray(searchStart);
    }
    return lines;
  }

  /**
   * Call when a complete reply has been consumed by the parser to reset the
   * per-reply counters for the next reply.
   */
  finishReply(): void {
    this.replyBytes = 0;
    this.replyLines = 0;
  }

  /** True if any bytes remain buffered (used for the STARTTLS drain check). */
  hasBufferedBytes(): boolean {
    return this.buffer.length > 0;
  }

  /** Number of bytes currently buffered. */
  bufferedByteCount(): number {
    return this.buffer.length;
  }

  /** Discard any buffered bytes (used after the drain check aborts). */
  reset(): void {
    this.buffer = Buffer.alloc(0);
    this.replyBytes = 0;
    this.replyLines = 0;
  }
}
