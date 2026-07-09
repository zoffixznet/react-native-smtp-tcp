/** Test re-exports and small wrappers for the message builder tests. */
export { buildMessage, formatDate } from '../../src/message/builder';
import { dotStuff } from '../../src/protocol/client';

/** Dot-stuff a single line and return it without the trailing CRLF. */
export function dotStuffPreview(line: string): string {
  return dotStuff(line);
}
