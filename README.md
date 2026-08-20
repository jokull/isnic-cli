# isnic-cli

Read-only CLI for the **ISNIC .is registry** built on their public **RDAP** API.
No external dependencies — plain Node.js ≥ 18.

```sh
isnic list                       # your domains + statuses + expiry (auth required)
isnic check example.is [...]     # .is availability (rdap dac)
isnic info example.is            # full RDAP record for one domain
isnic whois JSA5-IS              # entity / handle lookup
isnic whois sue.ns.cloudflare.com  # nameserver lookup (auto-routed)
isnic ispstat                    # DNS-provider domain list (often denied for non-providers)
isnic config                     # show credential status
```

Output is aligned tables (colors when TTY; `--no-color` or `NO_COLOR=1` to disable).
Every command also supports `--json` for machine-readable output.

## Install

```sh
npm link          # from this repo — exposes `isnic` on PATH
# or just run:   node bin/isnic.mjs <command>
```

## Auth

Only `list` and `ispstat` require credentials (the RDAP lists endpoints).
`check`, `info` and `whois` work anonymously; if credentials are set they are
also sent, which exempts lookups of your own domains from the 50/30-min rate
limit.

Credentials — HTTP Basic with your NIC handle as user and your **password**
(or an RDAP/RPP **API key**) as password. Precedence:

1. Flags: `--handle <h> --password <p>` (or `--api-key <k>`)
2. Env: `ISNIC_HANDLE`, `ISNIC_PASSWORD` / `ISNIC_API_KEY`
3. **macOS Keychain** — best option on a Mac, no plaintext on disk:
4. Config file `~/.config/isnic/config.json` (plaintext; `chmod 600` it)

### macOS Keychain

First run (prompts for handle if unset, then the password):

```sh
isnic keychain add            # prompts: NIC handle + password (hidden input, upsert)
isnic keychain add --api-key  # stores an RDAP/RPP API key instead (needed if 2FA is on)
isnic keychain status         # what's stored / enabled
isnic keychain remove         # delete the entry
```

`isnic keychain add` also writes your handle and `"keychain": true` to
`~/.config/isnic/config.json` (0600 — the handle isn't a secret, the secret
stays in the Keychain), so after that **`isnic list` works with no
environment variables at all**:

```sh
isnic list
```

Scripted / piped input is supported (`printf 'JSA5-IS\nsecret\n' | isnic keychain add`).
Keychain lookup is otherwise opt-in (`ISNIC_KEYCHAIN=1`, or `{"keychain": true}`
in the config) so anonymous commands like `check` never trigger a Keychain
access prompt. Items are stored under services `isnic-cli` (password) and
`isnic-cli-api` (API key), keyed by your NIC handle.

> ⚠️ If TOTP 2FA is enabled on the account, password auth is **rejected** by
> the registry — create an RDAP/RPP API key in the account web UI
> (Mín síða → API → *Aðgangslyklar fyrir RDAP og RPP*) and store it with
> `isnic keychain add --api-key`. The key is only ever shown once when
> created; store it somewhere safe.

## API surface (confirmed live)

| Endpoint | Auth | Rate limit | Used by |
|---|---|---|---|
| `GET /rdap/lists/my_domains` | Basic | not documented | `list` |
| `GET /rdap/lists/ispstat` | Basic | not documented | `ispstat` (403 unless DNS provider) |
| `GET /rdap/dac/{domain}` | public | 7200 req / 30 min | `check` (404 = available) |
| `GET /rdap/domain/{domain}` | public | 50 req / 30 min (own domains exempt when authed) | `info`, `whois` |
| `GET /rdap/entity/{handle}` | public | 50 req / 30 min | `whois` |
| `GET /rdap/nameserver/{ns}` | public | 1500 req / hour | `whois` |

Base URL `https://rdap.isnic.is`. Full spec: <https://www.isnic.is/en/api/rdap>.

## Roadmap — write operations

Registration, renewal, auto-renew, contact/nameserver/DNSSEC changes and
transfers are **not** implemented and are intentionally excluded here
(read-only only). ISNIC offers two protocols for that:

- **EPP** — XML provisioning (RFC 5730) at `epp.isnic.is:700`
  (sandbox `epp.sandbox.isnic.is:700`). Requires applying for access, IP
  whitelisting and passing sandbox competency checks. Handbook:
  <https://www.isnic.is/en/api/epp>
- **RPP** — *Restful Provisioning Protocol*, ISNIC's REST API (an IETF
  standardization effort, <https://datatracker.ietf.org/doc/html/draft-ietf-rpp-json-00>).
  Keys are created in the account UI (same place as RDAP keys). The endpoint
  host and full spec are not public yet — this CLI will gain a `renew` /
  `autocharge` / `delegate` set of commands once the RPP surface is confirmed.

## Notes

- **Do not** hammer the API: respect the documented rate limits, especially
  anonymous `domain`/`entity` lookups (50/30 min). `check` is cheap
  (7200/30 min).
- The registry runs bot protection on `www.isnic.is` (a "robot jail" that
  blocks an IP for ~30 min after bursts of requests). `rdap.isnic.is` was not
  affected during testing.
- IDN names are converted to punycode automatically (`örflæði.is` →
  `xn--rfli-xoa4dub.is`).
