# node-icq-server — agent guidance

Compact reference for working in this repo. Every line answers: "Would an agent likely miss this without help?"

## Entry points & commands

- Start: `npm start` (= `node server.js`). Opens AUTH `5190`, BOS `5191`, WEB `8080`, HTTPS `443`.
- DB CLI: `npm run db <command>` (= `node database.js <command>`).
  - `add <UIN> <PASS> [NICK] [FIRST] [LAST] [EMAIL]`
  - `auto <PASS> [NICK] [EMAIL]` — allocate free UIN
  - `passwd <UIN> <PASS>` — change password
  - `list | search <q> | del <UIN> | nextuin | migrate | schema`
- `npm run db:migrate` — idempotent: converts legacy plaintext passwords to PBKDF2-SHA256 + AES-GCM. Run once before first production start if `icq.db` existed before this rewrite.

## Configuration

- `config.js` reads all settings from `ICQ_*` env vars; `validateConfig()` runs on startup and **exits with errors** for bad ports, `UIN_MIN > UIN_MAX`, or `BOS_ADDRESS = 0.0.0.0`.
- `BOS_ADDRESS` must be a **real client-reachable IP** (clients connect to it). `0.0.0.0` is rejected at startup. Leave unset → auto-detected from LAN interfaces.
- `HOST` default is `192.168.0.20` (this machine's LAN IP). Change if deploying elsewhere.
- `ADMIN_PASS` default is `changethispassword` — the server warns at every start. Change via `ICQ_ADMIN_PASS` or `config.js` before publishing.
- `DEBUG_PACKETS` logs every byte of traffic — never enable on a public server.
- `LEGACY_AUTH_ENABLED: true` stores passwords both as PBKDF2 hash (web login) and AES-256-GCM ciphertext (OSCAR XOR/MD5/HTTP API need the plain password). Set `false` to store only the hash; XOR/MD5/HTTP API will then break until passwords are reset.
- Master key for AES-GCM is auto-generated into `.authkey` (mode 600, gitignored). Losing `.authkey` breaks XOR/MD5/HTTP API logins until passwords are reset.

## Database

- SQLite at `./icq.db` (configurable via `ICQ_DB_PATH`). Do not edit directly — use `node database.js`.
- Tables: `users`, `ssi`, `offline`. Schema created idempotently on `db.init()`.
- Columns `profile`, `awayMsg`, `city`, `phone`, `homepage`, `about`, `password_secure` are added by migration if missing.

## Architecture (not obvious from filenames)

- `server.js` — TCP servers + `Session` class + rate limiting (token buckets per connection for packets and bytes) + graceful shutdown on `SIGINT`/`SIGTERM`.
- `auth.js` — XOR Roasting + BUCP/MD5 auth, registration via SNAC(17,04) and FLAP Channel 1, cookie issuance.
- `bos.js` — OSCAR family handlers: `0x01` Generic, `0x02` Locate, `0x03` Buddy, `0x04` ICBM messages, `0x09` Privacy, `0x13` SSI, `0x15` ICQ Meta (profiles, search).
- `web.js` — HTTP panel at `:8080/admin`, public registration at `/api/register`, ICQ HTTP API (`/auth/getChallenge`, `/auth/clientLogin`, `/aim/startOSCARSession`). XML bodies used by real ICQ clients are parsed.
- `security.js` — PBKDF2, AES-256-GCM, master key, constant-time comparison.
- `ratelimit.js` — token buckets keyed by IP / IP+UIN; `startJanitor()` prunes stale entries every 60s.
- `oscar.js` — `OscarBuilder`, `parseTLVs`, `makeSNAC`, `makeFLAP`.
- `utils.js` — `hexDump` (gated by `DEBUG_PACKETS`).

## Gotchas

- `handlers.js` was **deleted** — it duplicated `auth.js`/`bos.js` and referenced non-existent `config.FAMILIES`. Do not recreate it.
- `icq.db`, `*.pem`, `.authkey`, `*.bak-*`, `node_modules/` are gitignored.
- No test suite, no CI, no lint. Verify changes by running `npm start` and reading startup warnings; protocol behavior is checked by connecting a test OSCAR client.
- Sessions live in memory only — restarting drops all online sessions; offline messages survive in SQLite.
- One UIN = one active session; a new login disconnects the old one.

## Environment

- Node.js >= 18 (tested on v24). Modern features used: WHATWG `URL` (not `url.parse()`), `crypto.timingSafeEqual`, `crypto.scryptSync`.
- Dependencies: `iconv-lite` (CP1251 decode), `sqlite3`. `npm install` after clone.