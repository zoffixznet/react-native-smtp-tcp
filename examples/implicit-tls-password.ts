/**
 * Implicit TLS (port 465) with password authentication.
 *
 * With implicit TLS the connection is encrypted from the first byte, so there is
 * no plaintext phase.
 */

import { createTransport } from 'react-native-smtp-tcp';

async function main() {
  const transport = createTransport({
    host: 'mail.example.com',
    port: 465,
    secure: 'implicit',
    // Use an app password where the provider requires one (for example Gmail).
    auth: { user: 'me@example.com', pass: 'your-app-password' },
  });

  // Optional: prove the account and network work before composing anything.
  await transport.verify();

  const info = await transport.sendMail({
    from: { name: 'Me', address: 'me@example.com' },
    to: [{ address: 'you@example.com' }],
    subject: 'Rappel: café',
    text: 'Bonjour.\nA bientôt.',
    html: '<p>Bonjour.</p><p>A bientôt.</p>',
  });

  console.log('sent', info.messageId, 'accepted', info.accepted);
}

main().catch((err) => {
  // err.transient tells you whether a retry might succeed.
  console.error('send failed:', err.message, 'transient:', err.transient);
});
