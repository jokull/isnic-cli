#!/usr/bin/env node
/**
 * isnic — read-only CLI for the ISNIC .is registry, built on their public RDAP API.
 *
 * Everything is a read operation:
 *   list    your domains (registrant/admin/billing/tech/zone) + statuses
 *   info    full RDAP record for a domain
 *   check   .is availability (rdap dac endpoint)
 *   whois   generic lookup: domain | entity/handle | nameserver
 *   ispstat DNS-provider domain list (may require provider access)
 *
 * API base: https://rdap.isnic.is   (spec: https://www.isnic.is/en/api/rdap)
 *
 * Auth: HTTP Basic with your NIC handle as user and either your account
 * password or an RDAP/RPP API key as password. Password auth fails when
 * TOTP 2FA is enabled — use an API key then (created in the account UI
 * under "Mín síða" → API → "Aðgangslyklar fyrir RDAP og RPP").
 *
 * Credentials are read from, in order of precedence:
 *   1. --handle/--password/--api-key flags
 *   2. ISNIC_HANDLE / ISNIC_PASSWORD (or ISNIC_API_KEY) env vars
 *   3. macOS Keychain (only when ISNIC_KEYCHAIN=1 or config { "keychain": true })
 *      — see `isnic keychain add`
 *   4. ~/.config/isnic/config.json  { "handle": "...", "password": "..." | "apiKey": "..." }
 */
import { domainToASCII } from 'node:url';
import { readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { homedir } from 'node:os';

const RDAP_BASE = 'https://rdap.isnic.is';
const CONFIG_PATH = join(homedir(), '.config', 'isnic', 'config.json');
const KEYCHAIN_SERVICE = 'isnic-cli';
const KEYCHAIN_SERVICE_KEY = 'isnic-cli-api';

const HELP = `isnic — read-only ISNIC (.is) registry CLI over RDAP

Usage:
  isnic list                     List your domains (auth required) with statuses & expiry
  isnic info <domain>            Full RDAP record for one domain
  isnic check <domain> [...]     .is availability check (rdap dac)
  isnic whois <query>            Lookup: domain, contact handle, or nameserver
  isnic ispstat                  DNS-provider domain list (auth required; may be denied)
  isnic keychain <add|remove|status>  Store/read the secret in the macOS Keychain
  isnic config                   Show credential source / status
  isnic help                     This help

Options:
  --handle <h> --password <p>    Override credentials (also ISNIC_HANDLE / ISNIC_PASSWORD / ISNIC_API_KEY)
  --json                         Machine-readable JSON output
  --no-color                     Disable ANSI colors
  -h, --help                     This help

Credentials precedence: flags > env vars > macOS Keychain (ISNIC_KEYCHAIN=1)
> ~/.config/isnic/config.json. Password auth is rejected when TOTP 2FA is on —
use an API key instead (isnic keychain add --api-key).

Rate limits (documented): domain/entity lookups 50 req / 30 min (own domains exempt when
authenticated), nameserver 1500 req / h, availability check 7200 req / 30 min.

Write operations (renew, autocharge, contacts, nameservers, DNSSEC, transfer) are NOT
implemented — they require ISNIC's EPP or RPP (Restful Provisioning Protocol) access.
`;

/* ------------------------------------------------------------------ utils */

const isTTY = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const c = (code, s) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s) => c('2', s);
const green = (s) => c('32', s);
const yellow = (s) => c('33', s);
const red = (s) => c('31', s);
const cyan = (s) => c('36', s);

function fail(msg, code = 1) {
  console.error(red('error:') + ' ' + msg);
  process.exit(code);
}

function toASCII(name) {
  const n = String(name).trim().toLowerCase();
  if (!n) return n;
  try {
    return domainToASCII(n).replace(/\.$/, '');
  } catch {
    return n;
  }
}

/* ------------------------------------------------------- macOS Keychain */

function isMac() {
  return process.platform === 'darwin';
}

/** Read a secret from the macOS Keychain (service+account). Returns null when missing/unavailable. */
function keychainGet(service, account) {
  if (!isMac()) return null;
  try {
    const out = execFileSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], {
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10000,
    });
    const s = out.toString().trim();
    return s || null;
  } catch {
    return null;
  }
}

/** Store a secret in the macOS Keychain (upsert). */
function keychainSet(service, account, secret) {
  if (!isMac()) throw new Error('macOS Keychain is only available on macOS');
  execFileSync('security', ['add-generic-password', '-U', '-s', service, '-a', account, '-w', secret], {
    stdio: 'ignore',
    timeout: 10000,
  });
}

function keychainDelete(service, account) {
  if (!isMac()) throw new Error('macOS Keychain is only available on macOS');
  try {
    execFileSync('security', ['delete-generic-password', '-s', service, '-a', account], {
      stdio: 'ignore',
      timeout: 10000,
    });
    return true;
  } catch {
    return false; // entry did not exist
  }
}

/** Prompt for a secret without echoing it to the terminal (TTY only; piped stdin passes through). */
function promptSecret(prompt) {
  return new Promise((resolve) => {
    const terminal = process.stdin.isTTY && process.stdout.isTTY;
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal });
    if (terminal) {
      rl._writeToOutput = function (s) {
        if (s === prompt) rl.output.write(s);
        else rl.output.write('\x1b[2K\r' + prompt + '*'.repeat(s.length));
      };
    }
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function keychainEnabled(env) {
  if (process.env.ISNIC_KEYCHAIN === '1') return true;
  if (env.file && env.file.keychain === true) return true;
  return false;
}

function getConfig() {
  const env = {
    handle: process.env.ISNIC_HANDLE,
    password: process.env.ISNIC_PASSWORD,
    apiKey: process.env.ISNIC_API_KEY,
  };
  if (existsSync(CONFIG_PATH)) {
    try {
      const raw = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
      env.file = { path: CONFIG_PATH, ...raw };
      if (!env.handle) env.handle = raw.handle;
      if (!env.password) env.password = raw.password;
      if (!env.apiKey) env.apiKey = raw.apiKey;
    } catch (e) {
      console.error(dim(`warning: could not read ${CONFIG_PATH}: ${e.message}`));
    }
  }
  // macOS Keychain — only consulted when explicitly enabled (avoid surprise
  // Keychain access prompts on anonymous commands like `check`).
  if (keychainEnabled(env) && env.handle && !env.password && !env.apiKey) {
    const pw = keychainGet(KEYCHAIN_SERVICE, env.handle);
    const key = keychainGet(KEYCHAIN_SERVICE_KEY, env.handle);
    if (key) env.apiKey = key;
    else if (pw) env.password = pw;
    env.fromKeychain = !!(key || pw);
  }
  return env;
}

function authHeader(env) {
  const secret = env.apiKey || env.password;
  if (!env.handle || !secret) return null;
  const b64 = Buffer.from(`${env.handle}:${secret}`).toString('base64');
  return { Authorization: `Basic ${b64}` };
}

async function rdap(path, { auth = false, env } = {}) {
  const headers = { Accept: 'application/rdap+json' };
  if (auth && env?.handle && (env.password || env.apiKey)) {
    const h = authHeader(env);
    if (h) Object.assign(headers, h);
  }
  let res;
  try {
    res = await fetch(RDAP_BASE + path, { headers, signal: AbortSignal.timeout(25000) });
  } catch (e) {
    throw new Error(`network error: ${e.message}`);
  }
  let body = null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('json')) {
    try { body = await res.json(); } catch { /* ignore */ }
  }
  return { status: res.status, body, headers: res.headers };
}

/* ------------------------------------------------------------ table output */

function table(rows, { headers, json = false } = {}) {
  if (json) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }
  if (rows.length === 0) {
    console.log(dim('(no rows)'));
    return;
  }
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i]).length))
  );
  const fmtRow = (cells) =>
    cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  ').trimEnd();
  console.log(cyan(fmtRow(headers)));
  console.log(dim('-'.repeat(widths.reduce((a, b) => a + b + 2, 0))));
  for (const r of rows) console.log(fmtRow(r));
}

function daysLeft(isoDate) {
  const ms = new Date(isoDate + 'T00:00:00Z') - Date.now();
  return Math.ceil(ms / 86400000);
}

function expiryCell(iso, json) {
  if (!iso) return '?';
  const d = daysLeft(iso);
  const cell = `${iso} (${d > 0 ? d + 'd' : d === 0 ? 'today' : Math.abs(d) + 'd ago'})`;
  if (json) return { date: iso, daysLeft: d };
  if (d < 0) return red(cell);
  if (d <= 30) return yellow(cell);
  return cell;
}

function statusCell(statuses, json) {
  const s = (statuses || []).join(',') || '—';
  if (json) return statuses || [];
  const low = s.toLowerCase();
  if (low.includes('server hold') || low.includes('pending delete') || low.includes('redemption')) return red(s);
  if (low.includes('pending')) return yellow(s);
  if (low.includes('active')) return green(s);
  return s;
}

/* ----------------------------------------------------------------- commands */

async function cmdList({ env, json }) {
  const { status, body } = await rdap('/rdap/lists/my_domains', { auth: true, env });
  if (status === 401 || status === 403) {
    fail(`HTTP ${status}: authentication failed for my_domains. Check ISNIC_HANDLE/ISNIC_PASSWORD. `
      + `If TOTP 2FA is enabled on the account, password auth is rejected — create an RDAP/RPP API key and use ISNIC_API_KEY.`);
  }
  if (status !== 200 || !body?.domainSearchResults) {
    fail(`unexpected response (HTTP ${status}): ${JSON.stringify(body).slice(0, 300)}`);
  }
  const rows = body.domainSearchResults.map((r) => {
    const ev = Object.fromEntries((r.events || []).map((e) => [e.eventAction, e.eventDate]));
    const regs = (r.entities || [])
      .filter((e) => (e.roles || []).includes('registrant'))
      .map((e) => e.handle)
      .join(',');
    return {
      domain: r.ldhName || '?',
      status: statusCell(r.status, json),
      registered: ev.registration ? ev.registration.slice(0, 10) : '?',
      expires: expiryCell(ev['soft expiration'] ? ev['soft expiration'].slice(0, 10) : null, json),
      registrant: regs || '—',
    };
  });
  rows.sort((a, b) => {
    const da = a.expires.daysLeft ?? Infinity;
    const db = b.expires.daysLeft ?? Infinity;
    return da - db;
  });
  const headers = ['DOMAIN', 'STATUS', 'REGISTERED', 'EXPIRES', 'REGISTRANT'];
  if (json) {
    console.log(JSON.stringify(rows, null, 2));
  } else {
    table(rows.map((r) => [r.domain, r.status, r.registered, r.expires, r.registrant]), { headers });
    console.log(dim(`\n${rows.length} domain(s) — via ${RDAP_BASE}/rdap/lists/my_domains`));
  }
}

async function cmdInfo({ env, json }, args) {
  if (args.length !== 1) fail('usage: isnic info <domain>', 2);
  const domain = toASCII(args[0]);
  const { status, body } = await rdap(`/rdap/domain/${encodeURIComponent(domain)}`, { auth: env.handle && (env.password || env.apiKey) });
  if (status === 404) {
    console.log(`${domain}: ${red('not registered')} (or unavailable for RDAP)`);
    return;
  }
  if (status === 429) {
    fail(`HTTP 429: domain lookup rate limit (50 req / 30 min). Own domains are exempt when authenticated — set credentials.`);
  }
  if (status !== 200 || !body) fail(`unexpected response (HTTP ${status})`);
  const ev = Object.fromEntries((body.events || []).map((e) => [e.eventAction, e.eventDate]));
  const ns = (body.nameservers || []).map((n) => n.ldhName).join('\n') || '—';
  const entities = (body.entities || []).map((e) => ({
    roles: (e.roles || []).join(','),
    handle: e.handle,
  }));
  const ds = body.secureDNS?.dsData || body.secureDNS?.maxSigLife !== undefined ? body.secureDNS : null;

  if (json) {
    console.log(JSON.stringify(body, null, 2));
    return;
  }
  console.log(cyan(`== ${body.ldhName || domain} ==`));
  const lines = [
    ['status', statusCell(body.status, false)],
    ['registered', ev.registration ? ev.registration.slice(0, 10) : '?'],
    ['last changed', ev['last changed'] ? ev['last changed'].slice(0, 10) : '?'],
    ['expires', ev['soft expiration'] ? expiryCell(ev['soft expiration'].slice(0, 10), false) : '?'],
    ['nameservers', ns],
    ['handle', body.handle || '—'],
  ];
  if (ds) lines.push(['DNSSEC', ds.signed ? 'signed' : JSON.stringify(ds).slice(0, 120)]);
  const w = Math.max(...lines.map(([k]) => k.length));
  const pad = ' '.repeat(w + 4);
  for (const [k, v] of lines) {
    const [first, ...rest] = String(v).split('\n');
    console.log(`  ${dim(k.padEnd(w))}  ${first}`);
    for (const line of rest) console.log(`  ${pad}${line}`);
  }
  if (entities.length) {
    console.log(dim(`\n  contacts`));
    for (const e of entities) console.log(`    ${dim(e.roles.padEnd(14))} ${e.handle || '—'}`);
  }
}

async function cmdCheck({ env, json }, args) {
  if (args.length === 0) fail('usage: isnic check <domain> [...]', 2);
  const rows = [];
  for (const raw of args) {
    const domain = toASCII(raw);
    const { status, body } = await rdap(`/rdap/dac/${encodeURIComponent(domain)}`);
    if (status === 404) rows.push({ domain, available: true, detail: 'available' });
    else if (status === 200) rows.push({ domain, available: false, detail: (body?.description || []).join(',') || 'not available' });
    else rows.push({ domain, available: null, detail: `HTTP ${status}` });
  }
  if (json) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }
  table(rows.map((r) => [
    r.domain,
    r.available === true ? green('AVAILABLE') : r.available === false ? red('TAKEN') : yellow('?'),
    r.detail,
  ]), { headers: ['DOMAIN', 'AVAILABILITY', 'DETAIL'] });
  console.log(dim(`\nvia ${RDAP_BASE}/rdap/dac/ — 404 = available, 200 = not available`));
}

async function cmdWhois({ env, json }, args) {
  if (args.length !== 1) fail('usage: isnic whois <domain|handle|nameserver>', 2);
  const q = args[0];
  const labels = q.split('.').filter(Boolean);
  // Routing heuristic:
  //  - NIC-handle pattern (e.g. JSA5-IS)           -> entity
  //  - hostnames with 3+ labels (e.g. ns1.foo.is)  -> nameserver first
  //  - everything else                             -> domain first
  let kinds;
  if (/^[a-z0-9][a-z0-9_-]{0,30}-is$/i.test(q)) kinds = ['entity'];
  else if (labels.length > 2) kinds = ['nameserver', 'domain', 'entity'];
  else kinds = ['domain', 'nameserver', 'entity'];

  let body = null, kind = null, status = 0;
  for (const k of kinds) {
    const qv = k === 'entity' ? q : toASCII(q);
    const r = await rdap(`/rdap/${k}/${encodeURIComponent(qv)}`, { auth: env.handle && (env.password || env.apiKey) });
    status = r.status;
    if (r.status === 200) { body = r.body; kind = k; break; }
    if (r.status === 429) { fail('HTTP 429: lookup rate limit reached (see help).'); }
  }
  if (!body) {
    console.log(`${q}: ${red('not found')} (last HTTP ${status})`);
    return;
  }
  if (json) { console.log(JSON.stringify(body, null, 2)); return; }
  if (kind === 'domain') { await cmdInfo({ env, json: false }, [q]); return; }
  // entity / nameserver: compact summary
  const vcardName = (() => {
    try {
      const va = body.vcardArray?.[1] || [];
      const fn = va.find((row) => row[0] === 'fn');
      return fn ? fn[3] : null;
    } catch { return null; }
  })();
  console.log(cyan(`== ${body.handle || q} ==`));
  const lines = [
    ['type', kind],
    ['name', vcardName || body.ldhName || '—'],
    ['status', statusCell(body.status, false)],
  ];
  const w = Math.max(...lines.map(([k]) => k.length));
  for (const [k, v] of lines) console.log(`  ${dim(k.padEnd(w))}  ${v}`);
}

async function cmdIspstat({ env, json }) {
  const { status, body } = await rdap('/rdap/lists/ispstat', { auth: true, env });
  if (status === 401 || status === 403) {
    console.error(dim('note: ispstat is limited to registered DNS providers; this account was denied.'));
    console.error(dim(`      (HTTP ${status}${body?.message ? ': ' + body.message : ''})`));
    process.exit(1);
  }
  if (status !== 200 || !body?.domainSearchResults) fail(`unexpected response (HTTP ${status})`);
  if (json) { console.log(JSON.stringify(body, null, 2)); return; }
  const rows = body.domainSearchResults.map((r) => {
    const ev = Object.fromEntries((r.events || []).map((e) => [e.eventAction, e.eventDate]));
    return [r.ldhName, statusCell(r.status, false), ev['soft expiration']?.slice(0, 10) || '?'];
  });
  table(rows, { headers: ['DOMAIN', 'STATUS', 'EXPIRES'] });
}

function cmdConfig({ env }) {
  console.log('RDAP base:  ' + cyan(RDAP_BASE));
  console.log('handle:     ' + (env.handle ? cyan(env.handle) : red('not set')));
  const hasSecret = !!(env.password || env.apiKey);
  console.log('secret:     ' + (hasSecret ? dim('set (' + (env.apiKey ? 'api key' : 'password') + ')') : red('not set')));
  const src = env.fromKeychain ? 'macOS Keychain'
    : env.file ? env.file.path
    : process.env.ISNIC_HANDLE ? 'environment'
    : 'none';
  console.log('source:     ' + dim(src));
  console.log('keychain:   ' + (keychainEnabled(env) ? green('enabled') : dim('off (set ISNIC_KEYCHAIN=1 or {"keychain":true} in config)')) + (isMac() ? '' : dim('  — macOS only')));
  if (env.handle && !hasSecret && keychainEnabled(env)) {
    console.log(dim('\nStore the secret in the macOS Keychain:'));
    console.log(dim('  isnic keychain add        # password'));
    console.log(dim('  isnic keychain add --api-key   # RDAP/RPP API key (use when 2FA is on)'));
  } else if (env.handle && !hasSecret) {
    console.log(dim('\nSet ISNIC_HANDLE + ISNIC_PASSWORD (or ISNIC_API_KEY), store it in the macOS Keychain:'));
    console.log(dim('  ISNIC_KEYCHAIN=1 isnic keychain add'));
    console.log(dim('or write a config file:'));
    console.log(dim(`  mkdir -p ~/.config/isnic && printf '{"handle":"YOURHANDLE-IS","password":"..."}' > ~/.config/isnic/config.json && chmod 600 ~/.config/isnic/config.json`));
  }
}

async function cmdKeychain({ env }, args) {
  if (!isMac()) fail('macOS Keychain is only available on macOS', 2);
  const sub = args[0];
  const useKey = args.includes('--api-key');
  const service = useKey ? KEYCHAIN_SERVICE_KEY : KEYCHAIN_SERVICE;
  const handle = env.handle;
  if (!handle) fail('set ISNIC_HANDLE (or --handle) first so the item can be keyed to it', 2);

  if (sub === 'add') {
    const secret = await promptSecret(useKey ? 'API key: ' : 'Password: ');
    if (!secret) fail('empty secret, aborting');
    keychainSet(service, handle, secret);
    console.log(green(`stored ${useKey ? 'API key' : 'password'} for ${handle} in the macOS Keychain (service "${service}")`));
    console.log(dim('Enable it with ISNIC_KEYCHAIN=1 (or {"keychain":true} in ~/.config/isnic/config.json).'));
    return;
  }
  if (sub === 'remove') {
    const removed = keychainDelete(service, handle);
    console.log(removed ? dim(`removed ${service}/${handle}`) : dim(`nothing stored for ${service}/${handle}`));
    return;
  }
  if (sub === 'status' || sub === undefined) {
    const pw = keychainGet(KEYCHAIN_SERVICE, handle);
    const key = keychainGet(KEYCHAIN_SERVICE_KEY, handle);
    console.log(`keychain:   ${keychainEnabled(env) ? green('enabled') : dim('off')} (ISNIC_KEYCHAIN=1 or {"keychain":true})`);
    console.log(`password:   ${pw ? green('stored') : dim('not stored')}  (service "${KEYCHAIN_SERVICE}")`);
    console.log(`api key:    ${key ? green('stored') : dim('not stored')}  (service "${KEYCHAIN_SERVICE_KEY}")`);
    return;
  }
  fail('usage: isnic keychain <add|remove|status> [--api-key]', 2);
}

/* -------------------------------------------------------------------- main */

function parseArgs(argv) {
  const opts = { handle: null, password: null, apiKey: null, json: false, noColor: false };
  const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--no-color') opts.noColor = true;
    else if (a === '--handle') opts.handle = argv[++i];
    else if (a === '--password') opts.password = argv[++i];
    else if (a === '--api-key') opts.apiKey = argv[++i];
    else if (a === '-h' || a === '--help') { console.log(HELP); process.exit(0); }
    else if (a.startsWith('-')) fail(`unknown option: ${a}\n\n${HELP}`, 2);
    else args.push(a);
  }
  return { opts, args };
}

async function main() {
  const { opts, args } = parseArgs(process.argv.slice(2));
  if (opts.noColor) process.env.NO_COLOR = '1';
  if (args.length === 0) { console.log(HELP); process.exit(0); }
  const cmd = args.shift();
  const env = getConfig();
  if (opts.handle) env.handle = opts.handle;
  if (opts.password) env.password = opts.password;
  if (opts.apiKey) env.apiKey = opts.apiKey;

  switch (cmd) {
    case 'list': return cmdList({ env, json: opts.json });
    case 'info': return cmdInfo({ env, json: opts.json }, args);
    case 'check': return cmdCheck({ env, json: opts.json }, args);
    case 'whois': return cmdWhois({ env, json: opts.json }, args);
    case 'ispstat': return cmdIspstat({ env, json: opts.json });
    case 'config': return cmdConfig({ env });
    case 'keychain': return cmdKeychain({ env }, args);
    default: fail(`unknown command: ${cmd}\n\n${HELP}`, 2);
  }
}

main().catch((e) => fail(e.message));
