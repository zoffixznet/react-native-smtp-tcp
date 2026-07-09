// Fail the build if any source path constructs a TLS context with validation
// disabled, outside isolated test fixtures. This guards SEC-7: the library must
// never expose or default to a switch that disables certificate/chain/hostname
// validation.
//
// Forbidden constructs in src/ (case-insensitive):
//   rejectUnauthorized set to false / a falsy value
//   InsecureSkipVerify (Go-style, defensive)
//   checkServerIdentity replaced with an always-true function
//   tlsCheckValidity set to false (react-native-tcp-socket plain-socket option)
//   NODE_TLS_REJECT_UNAUTHORIZED assignment
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(process.cwd(), 'src');

const FORBIDDEN = [
  {
    name: 'rejectUnauthorized:false',
    re: /rejectUnauthorized\s*:\s*(false|0|null|undefined)/i,
    // The Node adapter sets rejectUnauthorized:true; that is allowed. Only the
    // falsy form is forbidden, matched above.
  },
  { name: 'insecureSkipVerify', re: /insecureSkipVerify/i },
  { name: 'tlsCheckValidity:false', re: /tlsCheckValidity\s*:\s*false/i },
  { name: 'NODE_TLS_REJECT_UNAUTHORIZED', re: /NODE_TLS_REJECT_UNAUTHORIZED/i },
  {
    name: 'checkServerIdentity-always-true',
    re: /checkServerIdentity\s*:\s*\(\s*\)\s*=>\s*(true|undefined|null|void 0)/i,
  },
];

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) files.push(...walk(full));
    else if (/\.(ts|tsx|js|mjs)$/.test(entry)) files.push(full);
  }
  return files;
}

let failures = 0;
for (const file of walk(SRC)) {
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n');
  for (const rule of FORBIDDEN) {
    for (let i = 0; i < lines.length; i++) {
      if (rule.re.test(lines[i])) {
        console.error(`${file}:${i + 1}: forbidden TLS-disable construct (${rule.name}): ${lines[i].trim()}`);
        failures++;
      }
    }
  }
}

if (failures > 0) {
  console.error(`\nlint-no-disable-validation: found ${failures} forbidden construct(s).`);
  process.exit(1);
}
console.log('lint-no-disable-validation: no validation-disabling constructs in src/.');
