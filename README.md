# node-icq
A standalone ICQ server written in pure JavaScript. It implements the OSCAR protocol (FLAP/SNAC/TLV), authentication, SSI contact list, message exchange, and White Pages profiles.

## Features

### Protocol core
- **Double authentication** — MD5 (BUCP) and XOR Roasting
- **FLAP/SNAC/TLV** — full binary implementation
- **Connection protection** — token buckets for packets and bytes, frame length check
 before memory allocation, inactivity timeout, login attempt limit per pair (IP + UIN)

### Message exchange
- **Channel 1** — text messages (ASCII, UTF-8, UTF-16, CP1251)
- **Channel 2** — Rendezvous / Extended
- **Channel 4** — old ICQ format
- **ACK messages** — delivery confirmation
- **Offline messages** — with a queue limit (default: 200 per recipient) and a lifespan of 30 days

### Contacts and presence
- **SSI (Server-Side Information)** — full contact list management
  - adding / modifying / deleting contacts and groups
  - storage in SQLite
  - SSI Activate processing
  - SSI Check with “no changes” optimization
- **Contact statuses** — real-time online/offline notifications
- **Standard statuses** — Online, Away, DND, NA, Occupied, Free for Chat, Invisible
- **X-Status** — Angry, Depression, At Home, At Work and others
- **Extended statuses** — mood and notes via BART (TLV 0x001D)
- **Capabilities** — end‑to‑end TLV transmission for compatibility with clients
- **Search by profiles** — by UIN and by White Pages (QIP 2005, QIP Infium)

### Web Panel
- Public registration (HTML + JSON API)
- Admin panel: online sessions, account list, kick, system mailing
- ICQ HTTP API (`/auth/getChallenge`, `/auth/clientLogin`, `/aim/startOSCARSession`)
  for ICQ 7/8 and mobile clients

## Client Compatibility

| Client | Version | Authentication Method | Status |
|--------|---------|---------------------|--------|
| **QIP 2005** | Build 8095+ | XOR (Roasted) | ✅ Full |
| **QIP Infium** | 9040+ | MD5 (BUCP) | ✅ almost |
| **Pidgin** | any | MD5 | ✅ Full |
| **Jimm** | any | XOR | ✅ Full |
| **QIP 2012** | any | MD5 | ✅ Full |
| **D[i]chat** | any | MD5 | ✅ Complete |
| **QIP PDA** | any | XOR | ✅ Complete |

## Installation

> [!CAUTION]
> Before the first launch, configure `config.js`.

```bash
git clone https://github.com/Artemchik-Development/node-icq-server.git
cd node-icq-server
npm install
node server.```

Node.js 18 or later is required. Dependencies: `sqlite3` and `iconv-lite`.

## Account Management

Via the CLI:

```bash
node database.js add 100000 password              # UIN + password
node database.js add 100000 pwd Alice Smith mail  # with details
node database.js auto password                    # issue a free UIN
node database.js passwd 100000 newpass           # change password
node database.js list                             # list of accounts
node database.js search Alice                     # search
node database.js del 100000                       # delete
node database.js nextuin                          # next free UIN
node database.js migrate                          # convert old passwords to hashes
node database.js schema                           # table structure
```

Or via the built-in web interface at `http://<address>:8080/`.

## How passwords are stored

Two-layer scheme:

- `users.password` — **PBKDF2-SHA256** hash (210,000 iterations). This is the main password verifier.
- `users.password_secure` — **AES-256-GCM** ciphertext of the same password.

The second layer is needed because the OSCAR protocol itself requires a password, not its hash:

| Mechanism | What it requires |
|---|---|
| XOR Roasting | direct password comparison |
| BUCP / MD5 | `md5(password)` inside the hash |
| ICQ HTTP API | `HMAC-SHA256(password, challenge)` |

The encryption key is taken from `ICQ_MASTER_KEY`; if the variable is not set, the key is generated once and stored in the `.authkey` file (permissions 600, added to `.gitignore`).

What this provides: leaking only the database file does not reveal passwords. A complete server leak (including `.authkey`) — this cannot be avoided without abandoning XOR/MD5/HTTP API.

To disable the escort layer and store only an irreversible hash, set `LEGACY_AUTH_ENABLED: false`. Please note: this will disable login via XOR Roasting, BUCP/MD5, and ICQ HTTP API — only web registration will remain.

### Migration from the old database

On the first run, passwords saved in plain text are automatically converted to PBKDF2 + ciphertext. The values are deleted permanently, so **make a backup of `icq.db` before the first run**.

## Configuration

All values are stored in `config.js` and can be overridden by environment variables with the `ICQ_` prefix (convenient for systemd/Docker).

Key parameters:

| Parameter | By default | Variable | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | `ICQ_HOST` | TCP listening address |
| `AUTH_PORT` | `5190` | `ICQ_AUTH_PORT` | Authentication server port |
| `BOS_PORT` | `5191` | `ICQ_BOS_PORT` | BOS port |
| `BOS_ADDRESS` | auto-detection | `ICQ_BOS_ADDRESS` | The address that the client is given to connect to the BOS |
| `WEB_PORT` | `8080` | `ICQ_WEB_PORT` | Web panel port |
| `HTTPS_PORT` | `443` | `ICQ_HTTPS_PORT` | HTTPS port |
| `ADMIN_USER` | `admin` | `ICQ_ADMIN_USER` | Admin login |
| `ADMIN_PASS` | `changethispassword` | `ICQ_ADMIN_PASS` | Admin password (**change it!**) |
| `REGISTRATION_ENABLED` | `true` | `ICQ_REGISTRATION_ENABLED` | Registration via OSCAR and web |
| `PBKDF2_ITERATIONS` | `210000` | `ICQ_PBKDF2_ITERATIONS` | Hashing cost |
| `LEGACY_AUTH_ENABLED` | `true` | `ICQ_LEGACY_AUTH_ENABLED` | Whether to store reversible password ciphertext |
| `SESSION_IDLE_TIMEOUT_MS` | `900000` | `ICQ_SESSION_IDLE_TIMEOUT_MS` | Idle session timeout |
| `MAX_OFFLINE_MESSAGES` | `200` | `ICQ_MAX_OFFLINE_MESSAGES` | Size of the offline message queue |
| `CORS_ALLOW_ORIGIN` | `null` | `ICQ_CORS_ALLOW_ORIGIN` | By default, CORS is disabled |

`BOS_ADDRESS` cannot be `0.0.0.0`: this is a listening address, and you cannot connect to it. If you leave the field empty, the server will determine the IP of the network interface itself.

The configuration is checked at startup: errors (occupied ports, disabled UIN range, too few PBKDF2_ITERATIONS) stop the startup with a clear message; warnings are output to the console.

## Ports

| Port | Purpose |
|---|---|
| 5190/tcp | Authentication (OSCAR) |
| 5191/tcp | BOS — main server |
| 8080/tcp | Web panel and HTTP API |
| 443/tcp | HTTPS (requires `cert.pem` and `key.pem`, port permissions required) |

## Security when publishing to the internet

- Change `ADMIN_PASS` or set `ICQ_ADMIN_PASS`.
- Do not keep `DEBUG_PACKETS: true` — every byte of traffic gets into the log.
- Restrict access to port 8080 (admin panel) by firewall.
- Regularly copy `icq.db` **along with `.authkey`** — losing the key means
  the inability to log in via XOR/MD5 before changing passwords.

## Project structure

| File | Purpose |
|---|---|
| `server.js` | OSCAR TCP servers, session class, connection protection, shutdown |
| `auth.js` | Authentication (XOR/BUCP), registration, cookie issuance |
| `bos.js` | BOS logic: SSI, messages, statuses, questionnaires, search |
| `database.js` | SQLite, password hashing, CLI |
| `web.js` | Web panel, admin interface, ICQ HTTP API |
| `oscar.js` | Assembly and parsing of FLAP/SNAC/TLV |
| `security.js` | PBKDF2, AES-256-GCM, master key, constant-time comparison |
| `ratelimit.js` | Token buckets for load limiting |
| `utils.js` | Debug hex dump of packets |

## What still needs to be done

- Full support for user personal data (partially: the main fields are available)
- File sharing (ICQ File Transfer)
- Video and audio calls
- Cluster mode — sessions live in process memory
