import { resolveTxt as dnsResolveTxt } from 'node:dns/promises';
import { isDkim, parseDkim, lintDkim, COMMON_SELECTORS } from './parse.js';

export { isDkim, parseDkim, lintDkim, COMMON_SELECTORS } from './parse.js';

async function defaultResolveTxt(name) {
  const records = await dnsResolveTxt(name);
  return records.map((chunks) => chunks.join(''));
}

function cleanDomain(input) {
  const s = String(input || '').trim().toLowerCase();
  if (!s) throw new TypeError('A domain is required');
  return s.replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '');
}

async function lookup(resolveTxt, name) {
  try { return (await resolveTxt(name)).filter(isDkim); } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return [];
    throw err;
  }
}

/** Check one selector. */
async function checkSelector(resolveTxt, domain, selector) {
  const name = `${selector}._domainkey.${domain}`;
  const issues = [];
  const records = await lookup(resolveTxt, name);
  if (!records.length) return { selector, name, found: false, record: null, key: null, tags: {}, issues };
  if (records.length > 1) issues.push({ level: 'error', code: 'multiple-keys', message: `${name} has ${records.length} DKIM records; there must be one.` });
  const parsed = parseDkim(records[0]);
  for (const e of parsed.errors) issues.push({ level: 'error', code: 'syntax', message: e });
  issues.push(...lintDkim(parsed));
  return { selector, name, found: true, record: records[0], key: parsed.key, tags: parsed.tags, issues };
}

/**
 * Check DKIM keys of a domain. Without selectors, probes COMMON_SELECTORS.
 * @param {string} domain
 * @param {{selectors?: string[], resolveTxt?: (name: string) => Promise<string[]>, concurrency?: number}} [options]
 */
export async function checkDkim(domain, options = {}) {
  const resolveTxt = options.resolveTxt || defaultResolveTxt;
  const host = cleanDomain(domain);
  const probing = !options.selectors?.length;
  const selectors = probing ? COMMON_SELECTORS : options.selectors.map((s) => s.trim().toLowerCase());
  const results = [];
  const queue = [...selectors];
  const workers = Array.from({ length: options.concurrency || 8 }, async () => {
    while (queue.length) {
      const s = queue.shift();
      results.push(await checkSelector(resolveTxt, host, s).catch((err) => ({
        selector: s, name: `${s}._domainkey.${host}`, found: false, error: err.code || err.message, issues: [],
      })));
    }
  });
  await Promise.all(workers);
  results.sort((a, b) => selectors.indexOf(a.selector) - selectors.indexOf(b.selector));
  const found = results.filter((r) => r.found);
  const issues = [];
  if (!found.length) {
    issues.push(probing
      ? { level: 'warning', code: 'no-selector-found', message: `No DKIM key found for ${selectors.length} common selectors. Pass your selector (see the s= tag in the DKIM-Signature header of a sent message).` }
      : { level: 'error', code: 'no-dkim', message: `No DKIM key published for selector(s) ${selectors.join(', ')}.` });
  }
  for (const r of probing ? found : results) {
    if (!r.found && !probing) continue;
    for (const i of r.issues) issues.push({ ...i, selector: r.selector });
  }
  return {
    domain: host, probed: probing, selectors: probing ? found : results,
    issues, ok: found.length > 0 && !issues.some((i) => i.level === 'error'),
  };
}
