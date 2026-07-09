/**
 * OAuth2 (XOAUTH2) with a pluggable token provider.
 *
 * Prefer OAuth2 over passwords: major providers are retiring Basic Auth for SMTP.
 * The `tokenProvider` is called for each connection, so it can return a freshly
 * refreshed access token. Store refresh tokens in OS-backed secure storage.
 */

import { createTransport } from 'react-native-smtp-tcp';

// Replace this with your real token acquisition (for example an OAuth2 library
// plus a token cached in Expo SecureStore / the Keychain / the Keystore).
async function getFreshAccessToken(): Promise<string> {
  // ... refresh if expired, then return the current access token ...
  return 'ya29.a0Af...';
}

async function main() {
  const transport = createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: 'implicit',
    auth: {
      user: 'me@gmail.com',
      type: 'oauth2',
      tokenProvider: getFreshAccessToken,
    },
  });

  const info = await transport.sendMail({
    from: 'me@gmail.com',
    to: ['you@example.com'],
    subject: 'Hello via OAuth2',
    text: 'This message authenticated with XOAUTH2.',
  });

  console.log('sent', info.messageId);
}

main().catch((err) => console.error('send failed:', err.message));
