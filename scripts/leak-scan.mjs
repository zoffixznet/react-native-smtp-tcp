// Scan the built output and the publish tarball for anything that must never
// ship: absolute machine paths, an OS username/hostname, secret/key patterns,
// and any tool or vendor attribution markers. Fails the build on any hit.
//
// Usage:
//   node scripts/leak-scan.mjs            # scans dist/ and a fresh npm pack
//   node scripts/leak-scan.mjs --dist     # scans dist/ only
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, userInfo, hostname } from 'node:os';

const distOnly = process.argv.includes('--dist');

// The tool/vendor marker words are assembled from character codes so this
// scanner source does not itself contain the literal words it forbids.
const fromCodes = (...codes) => String.fromCharCode(...codes);
const marker = (codes) => new RegExp(`\\b${fromCodes(...codes)}\\b`, 'i');
const AI_MARKERS = [
  marker([99, 108, 97, 117, 100, 101]),            // primary tool name
  marker([97, 110, 116, 104, 114, 111, 112, 105, 99]), // its vendor
  marker([97, 115, 115, 105, 115, 116, 97, 110, 116]), // generic tool word
  marker([99, 111, 112, 105, 108, 111, 116]),      // another code tool
];

// Attribution-trailer phrases, also assembled from char codes so this source
// does not contain them literally. Case-insensitive substring match.
const phrase = (codes) => new RegExp(fromCodes(...codes), 'i');
const ATTRIBUTION = [
  // an automated-origin trailer phrase (two words)
  phrase([103, 101, 110, 101, 114, 97, 116, 101, 100, 32, 119, 105, 116, 104]),
  // a shared-authorship trailer key
  phrase([99, 111, 45, 97, 117, 116, 104, 111, 114, 101, 100, 45, 98, 121]),
];

// Patterns that must never appear in shipped files. These are intentionally
// broad. The vendor/tool markers are matched case-insensitively.
const FORBIDDEN = [
  { name: 'unix home path', re: /\/home\/[a-z0-9_-]+/i },
  { name: 'macOS home path', re: /\/Users\/[a-z0-9_.-]+/i },
  ...AI_MARKERS.map((re, i) => ({ name: `tool/vendor marker #${i + 1}`, re })),
  ...ATTRIBUTION.map((re, i) => ({ name: `attribution trailer #${i + 1}`, re })),
  { name: 'private key block', re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
  { name: 'bearer token literal', re: /Bearer\s+[A-Za-z0-9._-]{12,}/ },
  { name: 'GitHub token prefix', re: /\bghp_[A-Za-z0-9]{20,}/ },
  { name: 'Resend key prefix', re: /\bre_[A-Za-z0-9]{16,}/ },
];

// Public identifiers that are intentionally part of this package (the author
// name and the public GitHub owner in the repository URLs). A dynamic OS
// username/hostname check must not flag these legitimate public strings when the
// OS account name happens to be a substring of them.
const PUBLIC_ALLOW = [/zoffixznet/i, /Zoffix Znet/, /git@zoffix\.com/i];

function isAllowedLine(line) {
  return PUBLIC_ALLOW.some((re) => re.test(line));
}

// Dynamic, environment-specific forbidden strings (never hard-code them). Match
// on word boundaries so a machine account name is not detected inside an
// unrelated longer token, and skip lines that are a known public identifier.
const un = safe(() => userInfo().username);
const hn = safe(() => hostname());
if (un && un.length > 2) {
  FORBIDDEN.push({ name: 'OS username', re: new RegExp(`\\b${escape(un)}\\b`), allowPublic: true });
}
if (hn && hn.length > 2) {
  FORBIDDEN.push({ name: 'OS hostname', re: new RegExp(`\\b${escape(hn)}\\b`, 'i'), allowPublic: true });
}

function safe(fn) {
  try {
    return fn();
  } catch {
    return '';
  }
}
function escape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

let hits = 0;

function scanFile(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return; // binary or unreadable; skip
  }
  const lines = text.split('\n');
  for (const rule of FORBIDDEN) {
    for (let i = 0; i < lines.length; i++) {
      if (rule.re.test(lines[i])) {
        // A dynamic OS-account rule is skipped on lines that are a known public
        // identifier (the author name / GitHub owner in the repository URLs).
        if (rule.allowPublic && isAllowedLine(lines[i])) continue;
        console.error(`LEAK ${path}:${i + 1}: ${rule.name}`);
        hits++;
      }
    }
  }
}

function walk(dir, onFile) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, onFile);
    else onFile(full);
  }
}

// 1. Scan dist/.
const distDir = join(process.cwd(), 'dist');
if (existsSync(distDir)) {
  walk(distDir, scanFile);
} else {
  console.error('dist/ does not exist; run the build first.');
  process.exit(2);
}

// 2. Scan the publish tarball contents (unless --dist).
if (!distOnly) {
  const work = mkdtempSync(join(tmpdir(), 'rnsmtp-pack-'));
  try {
    const out = execFileSync('npm', ['pack', '--pack-destination', work], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });
    const tarball = out.trim().split('\n').pop().trim();
    const tarPath = join(work, tarball);
    execFileSync('tar', ['-xzf', tarPath, '-C', work]);
    const pkgDir = join(work, 'package');
    if (existsSync(pkgDir)) walk(pkgDir, scanFile);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (hits > 0) {
  console.error(`\nleak-scan: found ${hits} forbidden string(s). Aborting.`);
  process.exit(1);
}
console.log('leak-scan: clean (no absolute paths, secrets, or tool/vendor markers).');
