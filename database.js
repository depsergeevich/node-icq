'use strict';


const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const config = require('./config');
const security = require('./security');

const dbPath = path.isAbsolute(config.DB_PATH) ? config.DB_PATH : path.join(__dirname, config.DB_PATH);
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err); else resolve(this);
        });
    });
}

function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err); else resolve(row);
        });
    });
}

function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err); else resolve(rows);
        });
    });
}

function close() {
    return new Promise((resolve) => db.close(() => resolve()));
}


function sanitizeText(value, maxLength = 255) {
    if (value === undefined || value === null) return '';
    
    const cleaned = String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
    return cleaned.slice(0, maxLength);
}





async function init({ migrate = true } = {}) {
    await run(`CREATE TABLE IF NOT EXISTS users (
        uin           TEXT PRIMARY KEY,
        password      TEXT,
        nickname      TEXT DEFAULT '',
        firstname     TEXT DEFAULT '',
        lastname      TEXT DEFAULT '',
        email         TEXT DEFAULT '',
        gender        INTEGER DEFAULT 0,
        age           INTEGER DEFAULT 0
    )`);

    
    
    const extraCols = ['profile', 'awayMsg', 'city', 'phone', 'homepage', 'about', 'password_secure', 'state', 'country', 'birth_year', 'birth_month', 'birth_day'];
    for (const col of extraCols) {
        try { await run(`ALTER TABLE users ADD COLUMN ${col} TEXT`); } catch (e) {  }
    }

    await run(`CREATE TABLE IF NOT EXISTS ssi (
        uin  TEXT,
        name TEXT,
        gid  INTEGER,
        iid  INTEGER,
        type INTEGER,
        tlv  BLOB,
        PRIMARY KEY (uin, gid, iid)
    )`);

    await run(`CREATE TABLE IF NOT EXISTS offline (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        sender    TEXT,
        recipient TEXT,
        message   TEXT,
        ts        REAL
    )`);

    await run('CREATE INDEX IF NOT EXISTS idx_ssi_uin ON ssi (uin)');
    await run('CREATE INDEX IF NOT EXISTS idx_ssi_name ON ssi (name, type)');
    await run('CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline (recipient, ts)');

    if (migrate) await migrateLegacyPasswords();
}


async function migrateLegacyPasswords() {
    const rows = await all("SELECT uin, password, password_secure FROM users WHERE password IS NOT NULL AND password <> ''");

    let converted = 0;
    let withoutEscort = 0;

    for (const row of rows) {
        if (security.isHashedPassword(row.password)) {
            
            
            
            if (config.LEGACY_AUTH_ENABLED && !row.password_secure) withoutEscort++;
            continue;
        }

        const plain = String(row.password);
        const { hash, secret } = buildPasswordRecord(plain);

        await run('UPDATE users SET password = ?, password_secure = ? WHERE uin = ?', [hash, secret, row.uin]);
        converted++;
    }

    if (converted > 0) {
        console.log(`\x1b[33m[DB]\x1b[0m Миграция паролей: переведено с открытого текста ${converted}`);
        console.log(`\x1b[33m[DB]\x1b[0m Старые значения удалены безвозвратно — резервная копия БД остаётся вашей страховкой.`);
    }
    if (withoutEscort > 0) {
        console.log(`\x1b[33m[DB]\x1b[0m У ${withoutEscort} аккаунт(ов) уже хеш без эскорт-слоя: вход через XOR/BUCP/HTTP API для них недоступен, задайте пароль через "node database.js passwd <UIN> <PASS>".`);
    }

    return { converted, withoutEscort };
}






function buildPasswordRecord(plain) {
    const hash = security.hashPassword(plain, config.PBKDF2_ITERATIONS);
    const secret = config.LEGACY_AUTH_ENABLED
        ? security.encryptSecret(plain, security.getMasterKey(config.AUTH_MASTER_KEY).key)
        : null;
    return { hash, secret };
}


async function verifyUserPassword(uin, plain) {
    const user = await get('SELECT password FROM users WHERE uin = ?', [uin]);
    if (!user || !user.password) return false;
    return security.verifyPassword(plain, user.password);
}


async function getProtocolSecret(uin) {
    if (!config.LEGACY_AUTH_ENABLED) return null;

    const user = await get('SELECT password_secure FROM users WHERE uin = ?', [uin]);
    if (!user || !user.password_secure) return null;

    return security.decryptSecret(user.password_secure, security.getMasterKey(config.AUTH_MASTER_KEY).key);
}

async function changePassword(uin, plain) {
    const user = await get('SELECT uin FROM users WHERE uin = ?', [uin]);
    if (!user) return { error: 'User not found' };

    const { hash, secret } = buildPasswordRecord(plain);
    await run('UPDATE users SET password = ?, password_secure = ? WHERE uin = ?', [hash, secret, uin]);
    return { uin, success: true };
}


async function ensureProtocolSecret(uin, plain) {
    if (!config.LEGACY_AUTH_ENABLED) return;
    const user = await get('SELECT password_secure FROM users WHERE uin = ?', [uin]);
    if (user && user.password_secure) {
        if (security.decryptSecret(user.password_secure, security.getMasterKey(config.AUTH_MASTER_KEY).key) !== null) return;
    }
    const secret = security.encryptSecret(plain, security.getMasterKey(config.AUTH_MASTER_KEY).key);
    await run('UPDATE users SET password_secure = ? WHERE uin = ?', [secret, uin]);
}





async function getSSI(uin) {
    return all('SELECT * FROM ssi WHERE uin = ?', [uin]);
}

async function addSSI(uin, name, gid, iid, type, tlvBuf) {
    await run(
        'INSERT OR REPLACE INTO ssi (uin, name, gid, iid, type, tlv) VALUES (?,?,?,?,?,?)',
        [uin, name, gid, iid, type, tlvBuf]
    );
}

async function deleteSSI(uin, gid, iid) {
    await run('DELETE FROM ssi WHERE uin = ? AND gid = ? AND iid = ?', [uin, gid, iid]);
}

async function getSSIBuddies(uin) {
    return all('SELECT name FROM ssi WHERE uin = ? AND type = 0 AND name <> \'\'', [uin]);
}





async function searchByUIN(targetUin) {
    return get('SELECT uin, nickname, firstname, lastname, email, gender, age, city, phone, homepage, about, state, country, birth_year, birth_month, birth_day FROM users WHERE uin = ?', [targetUin]);
}

function buildSearchQuery({ nickname, firstname, lastname, email, city, state, country, birth_year, gender, age, ageMin, ageMax } = {}) {
    const conditions = [];
    const params = [];

    const like = (column, value) => { conditions.push(`LOWER(${column}) LIKE LOWER(?)`); params.push(`%${value}%`); };

    if (nickname) like('nickname', nickname);
    if (firstname) like('firstname', firstname);
    if (lastname) like('lastname', lastname);
    if (email) like('email', email);
    if (city) like('city', city);
    if (state) like('state', state);
    if (country) like('country', country);
    if (birth_year) like('birth_year', birth_year);

    if (gender !== undefined && gender !== null && gender !== 0) {
        conditions.push('CAST(gender AS INTEGER) = ?');
        params.push(gender);
    }
    if (age !== undefined && age !== null && age > 0) {
        conditions.push('CAST(age AS INTEGER) = ?');
        params.push(age);
    }
    if (ageMin !== undefined && ageMin !== null && ageMin > 0) {
        conditions.push('CAST(age AS INTEGER) >= ?');
        params.push(ageMin);
    }
    if (ageMax !== undefined && ageMax !== null && ageMax > 0 && ageMax < 65535) {
        conditions.push('CAST(age AS INTEGER) <= ?');
        params.push(ageMax);
    }

    return { conditions, params };
}

const PUBLIC_FIELDS = 'uin, nickname, firstname, lastname, email, gender, age, city, phone, homepage, about, state, country, birth_year, birth_month, birth_day';

async function searchByDetails(criteria = {}) {
    const { conditions, params } = buildSearchQuery(criteria);
    if (conditions.length === 0) return [];
    return all(`SELECT ${PUBLIC_FIELDS} FROM users WHERE ${conditions.join(' AND ')} LIMIT 40`, params);
}


async function searchByKeyword(keyword) {
    if (!keyword) return [];
    const q = `%${keyword}%`;
    return all(
        `SELECT ${PUBLIC_FIELDS} FROM users WHERE
            LOWER(nickname) LIKE LOWER(?) OR
            LOWER(firstname) LIKE LOWER(?) OR
            LOWER(lastname) LIKE LOWER(?) OR
            LOWER(email) LIKE LOWER(?) OR
            LOWER(city) LIKE LOWER(?)
         LIMIT 40`,
        [q, q, q, q, q]
    );
}





async function storeOffline(sender, recipient, message) {
    const text = sanitizeText(message, 4096);
    if (!text) return;

    await run('INSERT INTO offline (sender, recipient, message, ts) VALUES (?,?,?,?)',
        [sanitizeText(sender, 32), sanitizeText(recipient, 32), text, Date.now() / 1000]);

    
    
    await run(`DELETE FROM offline WHERE recipient = ? AND id NOT IN (
                    SELECT id FROM offline WHERE recipient = ? ORDER BY ts DESC LIMIT ?)`,
        [recipient, recipient, config.MAX_OFFLINE_MESSAGES]);

    if (config.MAX_OFFLINE_AGE_DAYS > 0) {
        await run('DELETE FROM offline WHERE recipient = ? AND ts < ?',
            [recipient, Date.now() / 1000 - config.MAX_OFFLINE_AGE_DAYS * 86400]);
    }
}

async function getOffline(recipient) {
    const rows = await all('SELECT * FROM offline WHERE recipient = ? ORDER BY ts', [recipient]);
    if (rows.length === 0) return rows;

    
    const chunkSize = 200;
    for (let i = 0; i < rows.length; i += chunkSize) {
        const ids = rows.slice(i, i + chunkSize).map(r => r.id).join(',');
        await run(`DELETE FROM offline WHERE id IN (${ids})`);
    }
    return rows;
}





async function getNextUIN() {
    const row = await get(
        'SELECT MAX(CAST(uin AS INTEGER)) as maxuin FROM users WHERE CAST(uin AS INTEGER) BETWEEN ? AND ?',
        [config.UIN_MIN, config.UIN_MAX]
    );

    if (row && row.maxuin) {
        const next = row.maxuin + 1;
        if (next <= config.UIN_MAX) return next.toString();
    }

    for (let uin = config.UIN_MIN; uin <= config.UIN_MAX; uin++) {
        const exists = await get('SELECT 1 FROM users WHERE uin = ?', [uin.toString()]);
        if (!exists) return uin.toString();
    }

    return null; 
}


async function registerUser(password, opts = {}) {
    if (typeof password !== 'string' || password.length < config.MIN_PASSWORD_LENGTH) {
        return { error: `Password must be at least ${config.MIN_PASSWORD_LENGTH} characters` };
    }
    if (password.length > config.MAX_PASSWORD_LENGTH) {
        return { error: `Password must be at most ${config.MAX_PASSWORD_LENGTH} characters` };
    }

    let uin = opts.uin ? String(opts.uin) : null;

    if (uin && !/^\d+$/.test(uin)) {
        return { error: 'UIN must contain digits only' };
    }
    if (uin && parseInt(uin, 10) < config.UIN_MIN) {
        return { error: `UIN must be at least ${config.UIN_MIN}` };
    }
    if (uin && parseInt(uin, 10) > config.UIN_MAX) {
        return { error: `UIN must be at most ${config.UIN_MAX}` };
    }
    if (!uin) {
        uin = await getNextUIN();
        if (!uin) return { error: 'No free UINs available' };
    }

    const exists = await get('SELECT 1 FROM users WHERE uin = ?', [uin]);
    if (exists) return { error: 'UIN already taken' };

    const nickname = sanitizeText(opts.nickname, 64);
    const { hash, secret } = buildPasswordRecord(password);

    try {
        
        await run(
            `INSERT INTO users (uin, password, password_secure, nickname, firstname, lastname, email)
             VALUES (?,?,?,?,?,?,?)`,
            [
                uin, hash, secret,
                nickname || uin,
                sanitizeText(opts.firstname, 64),
                sanitizeText(opts.lastname, 64),
                sanitizeText(opts.email, 128),
            ]
        );
        return { uin, success: true };
    } catch (e) {
        return { error: e.message };
    }
}

async function deleteUser(uin) {
    const target = String(uin);
    await run('DELETE FROM users WHERE uin = ?', [target]);
    await run('DELETE FROM ssi WHERE uin = ?', [target]);
    await run('DELETE FROM offline WHERE recipient = ? OR sender = ?', [target, target]);
}





const USAGE = `
ICQ Database Manager
  node database.js add     <UIN> <PASS> [NICK] [FIRST] [LAST] [EMAIL]
  node database.js auto    <PASS> [NICK] [EMAIL]      — выдать свободный UIN
  node database.js passwd  <UIN> <PASS>               — сменить пароль
  node database.js list
  node database.js search  <query>
  node database.js del     <UIN>
  node database.js nextuin
  node database.js migrate                            — перевести пароли в хеши
  node database.js schema                            — показать структуру таблиц
`;

async function runCli(argv) {
    await init();
    const args = argv.slice(2);
    const cmd = args[0];

    if (cmd === 'add') {
        const [, uin, pass, nick, first, last, email] = args;
        if (!uin || !pass) { console.log(USAGE); process.exitCode = 1; return; }
        const result = await registerUser(pass, { uin, nickname: nick, firstname: first, lastname: last, email });
        if (result.success) console.log(`\x1b[32m[OK]\x1b[0m User ${result.uin} registered.`);
        else { console.error(`\x1b[31m[ERR]\x1b[0m ${result.error}`); process.exitCode = 1; }
        return;
    }

    if (cmd === 'auto') {
        const [, pass, nick, email] = args;
        if (!pass) { console.log(USAGE); process.exitCode = 1; return; }
        const result = await registerUser(pass, { nickname: nick, email });
        if (result.success) console.log(`\x1b[32m[OK]\x1b[0m User ${result.uin} registered.`);
        else { console.error(`\x1b[31m[ERR]\x1b[0m ${result.error}`); process.exitCode = 1; }
        return;
    }

    if (cmd === 'passwd') {
        const [, uin, pass] = args;
        if (!uin || !pass) { console.log(USAGE); process.exitCode = 1; return; }
        const result = await changePassword(uin, pass);
        if (result.success) console.log(`\x1b[32m[OK]\x1b[0m Password for ${uin} updated.`);
        else { console.error(`\x1b[31m[ERR]\x1b[0m ${result.error}`); process.exitCode = 1; }
        return;
    }

    if (cmd === 'list') {
        const users = await all('SELECT uin, nickname, firstname, lastname, email FROM users ORDER BY CAST(uin AS INTEGER)');
        console.log('\n  UIN         Nick        Name              Email');
        console.log('  ' + '-'.repeat(60));
        if (users.length === 0) console.log('  (empty)');
        users.forEach(u => {
            const name = [u.firstname, u.lastname].filter(Boolean).join(' ') || '-';
            console.log(`  ${String(u.uin).padEnd(12)}${(u.nickname || '-').padEnd(12)}${name.padEnd(18)}${u.email || '-'}`);
        });
        console.log(`\n  Total: ${users.length} users\n`);
        return;
    }

    if (cmd === 'del') {
        if (!args[1]) { console.log(USAGE); process.exitCode = 1; return; }
        await deleteUser(args[1]);
        console.log(`User ${args[1]} deleted (аккаунт, контакты и офлайн-сообщения).`);
        return;
    }

    if (cmd === 'search') {
        const q = args[1];
        if (!q) { console.log(USAGE); process.exitCode = 1; return; }
        const rows = await all(
            'SELECT uin, nickname, firstname, lastname FROM users WHERE uin LIKE ? OR nickname LIKE ? OR firstname LIKE ? OR lastname LIKE ?',
            [`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`]
        );
        rows.forEach(r => console.log(`  UIN: ${r.uin}  Nick: ${r.nickname}  Name: ${r.firstname} ${r.lastname}`));
        if (!rows.length) console.log('  No results.');
        return;
    }

    if (cmd === 'nextuin') {
        const uin = await getNextUIN();
        console.log(`Next available UIN: ${uin || 'NONE'}`);
        return;
    }

    if (cmd === 'migrate') {
        const result = await migrateLegacyPasswords();
        console.log(`Converted: ${result.converted}, encrypted: ${result.encrypted}`);
        return;
    }

    if (cmd === 'schema') {
        for (const table of ['users', 'ssi', 'offline']) {
            const rows = await all(`PRAGMA table_info(${table})`);
            console.log(`\n${table}:`);
            rows.forEach(r => console.log(`  ${r.name.padEnd(18)} ${r.type}`));
        }
        console.log('');
        return;
    }

    console.log(USAGE);
}

if (require.main === module) {
    runCli(process.argv)
        .catch(e => { console.error('\x1b[31m[ERR]\x1b[0m', e.stack || e); process.exitCode = 1; })
        .finally(() => close());
}

module.exports = {
    init, run, get, all, close, sanitizeText,

    
    verifyUserPassword, getProtocolSecret, changePassword, ensureProtocolSecret,

    
    getSSI, addSSI, deleteSSI, getSSIBuddies,

    
    searchByUIN, searchByDetails, searchByKeyword,

    
    storeOffline, getOffline,

    
    getNextUIN, registerUser, deleteUser, PUBLIC_FIELDS,

    
    migrateLegacyPasswords,
};