import { createPublicKey } from 'node:crypto';

/** Selectors used by popular providers, tried when no selector is given. */
export const COMMON_SELECTORS = [
  'default', 'dkim', 'mail', 'selector1', 'selector2', 'google', 'k1', 'k2', 'k3', 's1', 's2',
  'smtp', 'email', 'key1', 'key2', 'mx', 'mandrill', 'mailjet', 'sendgrid', 'smtpapi', 'zoho',
  'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'everlytickey1', 'cm', 'mte1', 'pm',
];

/** True when a TXT string looks like a DKIM key record. */
export const isDkim = (txt) => /(^|;)\s*(v\s*=\s*DKIM1|p\s*=)/i.test(String(txt));

/**
 * Parse a DKIM key record (RFC 6376 §3.6.1) and inspect the public key.
 * @param {string} record
 * @returns {{tags: Record<string,string>, errors: string[], key: {type: string, bits: number|null, revoked: boolean}|null}}
 */
export function parseDkim(record) {
  const errors = [];
  const tags = {};
  for (const part of String(record).split(';').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq < 1) { errors.push(`Malformed tag "${part}" (expected name=value)`); continue; }
    const name = part.slice(0, eq).trim().toLowerCase();
    if (name in tags) errors.push(`Duplicate tag "${name}"`);
    tags[name] = part.slice(eq + 1).replace(/\s+/g, '');
  }
  if (tags.v !== undefined && tags.v !== 'DKIM1') errors.push(`v must be "DKIM1", got "${tags.v}"`);
  if (tags.p === undefined) { errors.push('Missing required tag "p" (public key)'); return { tags, errors, key: null }; }
  const type = (tags.k || 'rsa').toLowerCase();
  if (!['rsa', 'ed25519'].includes(type)) errors.push(`Unknown key type k=${tags.k}`);
  if (tags.p === '') return { tags, errors, key: { type, bits: null, revoked: true } };
  if (!/^[A-Za-z0-9+/]+=*$/.test(tags.p)) { errors.push('p= is not valid base64'); return { tags, errors, key: null }; }
  let bits = null;
  try {
    const der = Buffer.from(tags.p, 'base64');
    if (type === 'ed25519') {
      if (der.length !== 32) throw new Error('an Ed25519 key must be 32 bytes');
      bits = 256;
    } else {
      bits = createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyDetails.modulusLength;
    }
  } catch (err) {
    errors.push(`Public key cannot be decoded: ${err.message}`);
  }
  if (tags.h) for (const h of tags.h.split(':')) if (!['sha1', 'sha256'].includes(h.toLowerCase())) errors.push(`Unknown hash algorithm h=${h}`);
  return { tags, errors, key: { type, bits, revoked: false } };
}

/** Policy warnings for a parsed key record. */
export function lintDkim(parsed) {
  const out = [];
  const add = (level, code, message) => out.push({ level, code, message });
  const { tags, key } = parsed;
  if (key?.revoked) add('warning', 'revoked', 'p= is empty: this key is revoked and signatures with this selector fail.');
  if (key?.type === 'rsa' && key.bits) {
    if (key.bits < 1024) add('error', 'weak-key', `RSA key is only ${key.bits} bits; receivers ignore keys under 1024 bits.`);
    else if (key.bits < 2048) add('warning', 'short-key', `RSA key is ${key.bits} bits; 2048 is the recommended minimum.`);
  }
  if (tags.t && tags.t.split(':').includes('y')) add('warning', 'testing', 't=y: the domain is in testing mode and receivers may treat failures as unsigned.');
  if (tags.h && !tags.h.split(':').includes('sha256')) add('warning', 'sha1-only', 'h= allows only sha1, which is deprecated.');
  return out;
}
