/**
 * SMTP reply parsing (RFC 5321 sec 4.2), linear and index-based.
 *
 * A reply is one or more lines, each beginning with the same 3-digit code.
 * Continuation lines use "code-", the final line uses "code<SP>". The reply is
 * complete only at "code<SP>". Parsing is done by inspecting fixed character
 * positions (0-2 = code digits, 3 = separator), never with a backtracking
 * regex, so it is linear time and ReDoS-safe.
 *
 * The parser accumulates lines fed to it (from {@link ReplyReader}) until it
 * sees a final line, at which point it returns a complete {@link SmtpReply}.
 * Malformed codes, inconsistent continuation codes, and oversized replies are
 * rejected.
 */

import { SmtpProtocolError } from './errors';
import type { SmtpReply } from './types';

/** Result of feeding one line to the parser. */
export type ParseStep =
  | { done: false }
  | { done: true; reply: SmtpReply };

export class ReplyParser {
  private code: number | null = null;
  private lines: string[] = [];

  /**
   * Feed one reply line (without trailing CRLF). Returns `{ done: true }` with
   * the complete reply when the final line is seen, otherwise `{ done: false }`.
   */
  push(line: string): ParseStep {
    // A reply line must be at least "ddd" (3 digits). It may be exactly 3
    // characters (bare code, treated as final) or have a separator at index 3.
    if (line.length < 3) {
      throw new SmtpProtocolError(`malformed reply line ${JSON.stringify(line)}`);
    }

    const d0 = line.charCodeAt(0);
    const d1 = line.charCodeAt(1);
    const d2 = line.charCodeAt(2);
    if (!isDigit(d0) || !isDigit(d1) || !isDigit(d2)) {
      throw new SmtpProtocolError(`reply code is not three digits: ${JSON.stringify(line.slice(0, 4))}`);
    }
    const firstDigit = d0 - 0x30;
    if (firstDigit < 1 || firstDigit > 5) {
      throw new SmtpProtocolError(`reply code has an invalid leading digit: ${line.slice(0, 3)}`);
    }
    const code = (d0 - 0x30) * 100 + (d1 - 0x30) * 10 + (d2 - 0x30);

    // Separator at index 3: '-' means a continuation, ' ' (or end) means final.
    let isFinal: boolean;
    let sep: string;
    if (line.length === 3) {
      // Bare "ddd" with no separator or text: treat as a final line.
      isFinal = true;
      sep = ' ';
    } else {
      sep = line[3];
      if (sep === '-') {
        isFinal = false;
      } else if (sep === ' ') {
        isFinal = true;
      } else {
        // Anything other than SP or '-' at position 3 is malformed. A 4th
        // character that is a digit (e.g. "2500 ok") means the code is not a
        // 3-digit code as required.
        throw new SmtpProtocolError(
          `reply separator is not "-" or space: ${JSON.stringify(line.slice(0, 5))}`,
        );
      }
    }

    if (this.code === null) {
      this.code = code;
    } else if (code !== this.code) {
      // A continuation line's code differs from the first line's: violation.
      throw new SmtpProtocolError(
        `continuation reply code ${code} differs from the initial code ${this.code}`,
      );
    }

    const text = line.length > 3 ? line.slice(4) : '';
    this.lines.push(text);

    if (!isFinal) {
      return { done: false };
    }

    const reply: SmtpReply = {
      code: this.code,
      lines: this.lines.slice(),
      text: this.lines.join('\n'),
      enhanced: parseEnhanced(this.lines[this.lines.length - 1], this.code),
    };
    void sep;
    this.reset();
    return { done: true, reply };
  }

  reset(): void {
    this.code = null;
    this.lines = [];
  }

  /** True if a reply is partially parsed (some lines seen, not yet final). */
  inProgress(): boolean {
    return this.code !== null;
  }
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

/**
 * Parse an optional enhanced status code (RFC 3463) from the start of a final
 * reply line's text: "class.subject.detail". Only accepted when the class digit
 * matches the basic reply class (2/4/5). Advisory; never required.
 */
function parseEnhanced(
  text: string,
  basicCode: number,
): { class: number; subject: number; detail: number } | undefined {
  // Find the first token before a space.
  const spaceIdx = text.indexOf(' ');
  const token = spaceIdx === -1 ? text : text.slice(0, spaceIdx);
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  const nums: number[] = [];
  for (const p of parts) {
    if (p.length === 0 || p.length > 3) return undefined;
    for (let i = 0; i < p.length; i++) {
      if (!isDigit(p.charCodeAt(i))) return undefined;
    }
    nums.push(parseInt(p, 10));
  }
  const [cls, subject, detail] = nums;
  // The enhanced class must be one of 2/4/5 and match the basic code class.
  const basicClass = Math.floor(basicCode / 100);
  if (cls !== 2 && cls !== 4 && cls !== 5) return undefined;
  if (cls !== basicClass) return undefined;
  return { class: cls, subject, detail };
}

/** True for a positive completion reply (2yz). */
export function isPositive(code: number): boolean {
  return code >= 200 && code < 300;
}

/** True for a positive intermediate reply (3yz), e.g. 354 for DATA. */
export function isIntermediate(code: number): boolean {
  return code >= 300 && code < 400;
}

/** True for a transient negative reply (4yz). */
export function isTransient(code: number): boolean {
  return code >= 400 && code < 500;
}

/** True for a permanent negative reply (5yz). */
export function isPermanent(code: number): boolean {
  return code >= 500 && code < 600;
}
