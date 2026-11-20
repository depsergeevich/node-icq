'use strict';
/**
 * Криптографические утилиты.
 *
 * Хранение паролей в проекте двухслойное:
 *   1) users.password        — PBKDF2-SHA256 хеш. Это основной верификатор:
 *                              через него проверяется пароль там, где клиент
 *                              присылает его открытым текстом (веб-регистрация,
 *                              ICQ HTTP API в части "пароль = хеш", CLI).
 *   2) users.password_secure — AES-256-GCM шифротекст того же пароля.
 *                              Нужен потому, что протокол OSCAR требует сам
 *                              пароль: XOR Roasting сравнивает его напрямую, а
 *                              BUCP/MD5 считает md5(пароль), HTTP API считает
 *                              HMAC-SHA256(пароль, challenge). Хранить только
 *                              необратимый хеш и сохранить эти три механизма
 *                              невозможно.
 *
 * Мастер-ключ берётся из ICQ_MASTER_KEY / config.AUTH_MASTER_KEY, иначе
 * генерируется один раз и кладётся в .authkey (в .gitignore).
 * Утечка одного лишь файла БД больше не раскрывает пароли.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PBKDF2_ALGO = 'sha256';
const CIPHER = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const HASH_PREFIX = 'pbkdf2';
const SEC_PREFIX = 'gcm';

function toBuffer(value) {
    return Buffer.isBuffer(value) ? value : Buffer.from(String(value == null ? '' : value), 'utf8');
}

// ───────────────────────────────────────────
//  Пароли: PBKDF2-SHA256
// ───────────────────────────────────────────

function hashPassword(plain, iterations) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(toBuffer(plain), salt, iterations, KEY_BYTES, PBKDF2_ALGO);
    return [HASH_PREFIX, PBKDF2_ALGO, iterations, salt.toString('base64'), hash.toString('base64')].join('$');
}

function isHashedPassword(value) {
    return typeof value === 'string' && value.startsWith(`${HASH_PREFIX}$`) && value.split('$').length === 5;
}

function verifyPassword(plain, stored) {
    if (!isHashedPassword(stored)) return false;

    const [, algo, iterText, saltB64, hashB64] = stored.split('$');
    const iterations = Number.parseInt(iterText, 10);
    if (!Number.isInteger(iterations) || iterations <= 0) return false;

    let salt, expected;
    try {
        salt = Buffer.from(saltB64, 'base64');
        expected = Buffer.from(hashB64, 'base64');
    } catch { return false; }
    if (salt.length === 0 || expected.length === 0) return false;

    let actual;
    try {
        actual = crypto.pbkdf2Sync(toBuffer(plain), salt, iterations, expected.length, algo);
    } catch { return false; }

    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function passwordNeedsRehash(stored, iterations) {
    if (!isHashedPassword(stored)) return true;
    return Number.parseInt(stored.split('$')[2], 10) < iterations;
}

// ───────────────────────────────────────────
//  Обратимое шифрование (эскорт-слой для OSCAR)
// ───────────────────────────────────────────

function deriveKey(secret) {
    return crypto.scryptSync(toBuffer(secret), 'node-icq-server/master-key', KEY_BYTES);
}

function encryptSecret(plain, key) {
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(CIPHER, key, iv);
    const body = Buffer.concat([cipher.update(toBuffer(plain)), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [SEC_PREFIX, iv.toString('base64'), tag.toString('base64'), body.toString('base64')].join('$');
}

/** Возвращает null, если данных нет, формат неверный или ключ не тот. */
function decryptSecret(stored, key) {
    if (typeof stored !== 'string' || !stored) return null;

    const parts = stored.split('$');
    if (parts.length !== 4 || parts[0] !== SEC_PREFIX) return null;

    let iv, tag, body;
    try {
        iv = Buffer.from(parts[1], 'base64');
        tag = Buffer.from(parts[2], 'base64');
        body = Buffer.from(parts[3], 'base64');
    } catch { return null; }
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES || body.length === 0) return null;

    try {
        const decipher = crypto.createDecipheriv(CIPHER, key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
    } catch {
        return null; // битый шифротекст или сменился мастер-ключ
    }
}

function isEncryptedSecret(value) {
    return typeof value === 'string' && value.startsWith(`${SEC_PREFIX}$`) && value.split('$').length === 4;
}

// ───────────────────────────────────────────
//  Мастер-ключ
// ───────────────────────────────────────────

let masterKeyCache = null;

function loadOrCreateKeyFile(file) {
    try {
        const saved = fs.readFileSync(file, 'utf8').trim();
        if (saved.length >= 32) return { secret: saved, source: file };
    } catch { /* файла нет — создадим ниже */ }

    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(file, generated, { mode: 0o600 });
    try { fs.chmodSync(file, 0o600); } catch { /* Windows: права не меняются */ }
    return { secret: generated, source: `${file} (создан автоматически)` };
}

/** Ленивая инициализация: файл .authkey создаётся только когда реально понадобился. */
function getMasterKey(explicitSecret, keyFile) {
    if (masterKeyCache) return masterKeyCache;

    let secret, source;
    if (explicitSecret && String(explicitSecret).trim()) {
        secret = String(explicitSecret).trim();
        source = 'ICQ_MASTER_KEY / config.AUTH_MASTER_KEY';
    } else {
        const loaded = loadOrCreateKeyFile(keyFile || path.join(__dirname, '.authkey'));
        secret = loaded.secret;
        source = loaded.source;
    }

    masterKeyCache = { key: deriveKey(secret), source, generated: !explicitSecret };
    return masterKeyCache;
}

function resetMasterKeyCache() {
    masterKeyCache = null;
}

// ───────────────────────────────────────────
//  Сравнение и генерация токенов
// ───────────────────────────────────────────

/** Сравнение строк за постоянное время (устойчиво к разной длине). */
function safeEqual(a, b) {
    const da = crypto.createHash('sha256').update(toBuffer(a)).digest();
    const db = crypto.createHash('sha256').update(toBuffer(b)).digest();
    return crypto.timingSafeEqual(da, db);
}

function randomToken(bytes = 32) {
    return crypto.randomBytes(bytes);
}

function randomId(bytes = 16) {
    return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
    hashPassword,
    verifyPassword,
    isHashedPassword,
    passwordNeedsRehash,

    encryptSecret,
    decryptSecret,
    isEncryptedSecret,
    getMasterKey,
    resetMasterKeyCache,

    safeEqual,
    randomToken,
    randomId,

    PBKDF2_ALGO,
    KEY_BYTES,
};