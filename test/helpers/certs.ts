/**
 * Certificate generation for TLS tests. Uses openssl to create a private CA and
 * leaf certificates with configurable subjectAltNames. Nothing is committed; all
 * key material is generated into a per-run temp directory and cleaned up.
 *
 * This lets the suite prove certificate chain validation, hostname matching,
 * SPKI pinning, and self-signed rejection against a real Node tls server.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

export interface GeneratedCert {
  /** PEM certificate (leaf). */
  cert: string;
  /** PEM private key (leaf). */
  key: string;
  /** PEM CA certificate that signed the leaf, or the self-signed cert itself. */
  ca: string;
  /** Base64 SHA-256 of the leaf's SubjectPublicKeyInfo (for pin tests). */
  spkiSha256: string;
  /** Directory holding the generated files; call cleanup() to remove. */
  dir: string;
}

function openssl(args: string[], cwd: string): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

/** Compute the base64 SHA-256 of a certificate's SPKI using openssl. */
function spkiHash(certPath: string, cwd: string): string {
  const pub = execFileSync(
    'openssl',
    ['x509', '-in', certPath, '-pubkey', '-noout'],
    { cwd },
  );
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'DER'], {
    cwd,
    input: pub,
  });
  const hash = execFileSync('openssl', ['dgst', '-sha256', '-binary'], {
    cwd,
    input: der,
  });
  return Buffer.from(hash).toString('base64');
}

export interface CertOptions {
  /** subjectAltName entries, e.g. ["DNS:localhost", "IP:127.0.0.1"]. */
  altNames?: string[];
  /** Common Name. Defaults to "localhost". */
  commonName?: string;
  /** When true, produce a self-signed leaf (its own CA). */
  selfSigned?: boolean;
}

/**
 * Generate a CA-signed (or self-signed) leaf certificate with the given SANs.
 */
export function generateCert(opts: CertOptions = {}): GeneratedCert {
  const dir = mkdtempSync(join(tmpdir(), 'rnsmtp-certs-'));
  const cn = opts.commonName ?? 'localhost';
  const altNames = opts.altNames ?? ['DNS:localhost', 'IP:127.0.0.1'];
  const sanConfig = altNames.map((n, i) => `${sanType(n)}.${i + 1} = ${sanValue(n)}`).join('\n');

  const extConf = `[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
${sanConfig}
`;
  writeFileSync(join(dir, 'leaf.ext'), extConf);

  if (opts.selfSigned) {
    openssl(['genrsa', '-out', 'leaf.key', '2048'], dir);
    openssl(
      [
        'req', '-new', '-x509', '-key', 'leaf.key', '-out', 'leaf.crt',
        '-days', '2', '-subj', `/CN=${cn}`,
        '-extensions', 'v3_req', '-config', 'leaf.ext',
        '-addext', `subjectAltName=${altNames.join(',')}`,
      ],
      dir,
    );
    const cert = readFileSync(join(dir, 'leaf.crt'), 'utf8');
    const key = readFileSync(join(dir, 'leaf.key'), 'utf8');
    return {
      cert,
      key,
      ca: cert,
      spkiSha256: spkiHash(join(dir, 'leaf.crt'), dir),
      dir,
    };
  }

  // Create a CA.
  openssl(['genrsa', '-out', 'ca.key', '2048'], dir);
  openssl(
    [
      'req', '-new', '-x509', '-key', 'ca.key', '-out', 'ca.crt',
      '-days', '2', '-subj', '/CN=Test Root CA',
    ],
    dir,
  );

  // Create the leaf CSR and sign it with the CA.
  openssl(['genrsa', '-out', 'leaf.key', '2048'], dir);
  openssl(['req', '-new', '-key', 'leaf.key', '-out', 'leaf.csr', '-subj', `/CN=${cn}`], dir);
  openssl(
    [
      'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
      '-CAcreateserial', '-out', 'leaf.crt', '-days', '2',
      '-extfile', 'leaf.ext', '-extensions', 'v3_req',
    ],
    dir,
  );

  return {
    cert: readFileSync(join(dir, 'leaf.crt'), 'utf8'),
    key: readFileSync(join(dir, 'leaf.key'), 'utf8'),
    ca: readFileSync(join(dir, 'ca.crt'), 'utf8'),
    spkiSha256: spkiHash(join(dir, 'leaf.crt'), dir),
    dir,
  };
}

/** Remove a generated cert directory. */
export function cleanupCert(cert: GeneratedCert): void {
  try {
    rmSync(cert.dir, { recursive: true, force: true });
  } catch {
    // best effort
  }
}

function sanType(entry: string): string {
  return entry.startsWith('IP:') ? 'IP' : 'DNS';
}
function sanValue(entry: string): string {
  const colon = entry.indexOf(':');
  return colon === -1 ? entry : entry.slice(colon + 1);
}
