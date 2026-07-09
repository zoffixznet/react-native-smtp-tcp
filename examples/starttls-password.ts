/**
 * STARTTLS (port 587) with password authentication.
 *
 * Use this for servers that only offer submission on 587. The client upgrades an
 * initially plaintext connection to TLS, then discards everything it learned
 * before TLS and re-issues EHLO inside the encrypted channel. If the server does
 * not offer STARTTLS, or the upgrade fails, the client aborts rather than sending
 * credentials in cleartext.
 */

import { createTransport } from 'react-native-smtp-tcp';

async function main() {
  const transport = createTransport({
    host: 'smtp.example.com',
    port: 587,
    secure: 'starttls',
    requireTLS: true, // default; abort rather than fall back to cleartext
    auth: { user: 'me@example.com', pass: 'your-app-password' },
  });

  const info = await transport.sendMail({
    from: 'me@example.com',
    to: ['you@example.com'],
    subject: 'Meeting notes',
    text: 'Attached are the notes.',
    attachments: [
      {
        filename: 'notes.txt',
        content: 'Line one\nLine two\n',
        contentType: 'text/plain',
      },
    ],
  });

  console.log('sent', info.messageId);
}

main().catch((err) => console.error('send failed:', err.message));
