#!/usr/bin/env node
import { checkDkim, parseDkim, lintDkim } from '../src/index.js';

const HELP = `Usage: dkim-checker <domain> [selector ...] [options]
       dkim-checker --record "v=DKIM1; k=rsa; p=MIIBIjANBg..."

Looks up <selector>._domainkey.<domain>, decodes the public key and reports
key length, revoked or testing keys and syntax errors. Without a selector it
probes the selectors used by common mail providers.

Options:
  -s, --selector <s>  Selector to check (repeatable, or comma-separated)
  --record <dkim>     Lint a key record string offline instead of querying DNS
  --json              Print the full report as JSON
  --strict            Exit with code 1 on warnings too
  -h, --help          Show this help

Online version (no install): https://promopilot.link/en/tools/dkim-checker.php
`;

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
if (!args.length || flag('-h') || flag('--help')) { process.stdout.write(HELP); process.exit(args.length ? 0 : 2); }

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const ICON = { error: c(31, '✖'), warning: c(33, '!'), info: c(36, 'i') };
const keyText = (k) => (!k ? 'unreadable' : k.revoked ? 'revoked (empty p=)' : `${k.type.toUpperCase()} ${k.bits ?? '?'} bits`);

const positional = [];
const selectors = [];
let record;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-s' || a === '--selector') selectors.push(...String(args[++i] || '').split(','));
  else if (a === '--record') record = args[++i];
  else if (!a.startsWith('-')) positional.push(a);
}
selectors.push(...positional.slice(1));

try {
  let report;
  if (record) {
    const parsed = parseDkim(record);
    const issues = [...parsed.errors.map((m) => ({ level: 'error', code: 'syntax', message: m })), ...lintDkim(parsed)];
    report = { record, tags: parsed.tags, key: parsed.key, issues, ok: !issues.some((i) => i.level === 'error') };
  } else {
    report = await checkDkim(positional[0], { selectors: selectors.filter(Boolean) });
  }
  if (flag('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else if (record) {
    console.log(`${c(1, 'Key:')} ${keyText(report.key)}`);
    console.log('');
    if (!report.issues.length) console.log(c(32, '✔ DKIM key record looks good'));
    for (const i of report.issues) console.log(`  ${ICON[i.level]} ${i.message}`);
  } else {
    console.log(`${c(1, 'Domain:')} ${report.domain}${report.probed ? c(2, '  (probing common selectors)') : ''}`);
    console.log('');
    for (const s of report.selectors) {
      const status = s.found ? c(32, keyText(s.key)) : s.error ? c(31, `DNS error: ${s.error}`) : c(2, 'not found');
      console.log(`  ${c(1, s.selector.padEnd(14))} ${status}${s.found && s.tags.t ? `  t=${s.tags.t}` : ''}`);
    }
    console.log('');
    if (!report.issues.length) console.log(c(32, '✔ DKIM looks good'));
    for (const i of report.issues) console.log(`  ${ICON[i.level]} ${i.selector ? `[${i.selector}] ` : ''}${i.message}`);
  }
  const failing = report.issues.filter((i) => i.level === 'error' || (flag('--strict') && i.level === 'warning'));
  process.exit(failing.length || (!record && !report.ok) ? 1 : 0);
} catch (err) {
  console.error(c(31, `Error: ${err.message}`));
  process.exit(2);
}
