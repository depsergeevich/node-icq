'use strict';
/**
 * Конфигурация сервера.
 *
 * Любое значение можно переопределить переменной окружения (удобно для
 * systemd/Docker), явное значение ниже — это значение по умолчанию.
 * Валидация выполняется в validateConfig() на старте: лучше упасть сразу с
 * понятным сообщением, чем работать наполовину.
 */

const os = require('os');

// ───────────────────────────────────────────
//  Чтение переменных окружения
// ───────────────────────────────────────────

function envString(name, fallback) {
    const raw = process.env[name];
    return raw === undefined || raw.trim() === '' ? fallback : raw.trim();
}

function envInt(name, fallback) {
    const raw = envString(name, null);
    if (raw === null) return fallback;
    const value = Number.parseInt(raw, 10);
    if (!Number.isInteger(value)) {
        throw new Error(`Переменная окружения ${name} должна быть целым числом, получено: "${raw}"`);
    }
    return value;
}

function envBool(name, fallback) {
    const raw = envString(name, null);
    if (raw === null) return fallback;
    return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

function isWildcardHost(host) {
    if (typeof host !== 'string' || host === '') return false;
    const value = host.trim().toLowerCase();
    if (value === '::' || value === '::0' || value === '[::]') return true;
    // 0.0.0.0 в любой записи октетов: 0, 00, 0x0 — это всё тот же wildcard.
    return /^0+(\.0+){3}$/.test(value);
}

// ───────────────────────────────────────────
//  Автоопределение адреса, который клиентам
//  нужно использовать для подключения к BOS.
//  0.0.0.0 — адрес прослушивания, подключиться к нему нельзя.
// ───────────────────────────────────────────

function detectLanAddress() {
    const interfaces = os.networkInterfaces();
    const candidates = [];

    for (const entries of Object.values(interfaces)) {
        for (const entry of entries || []) {
            if (entry.family !== 'IPv4' || entry.internal) continue;
            candidates.push({ address: entry.address, private: /^10\./.test(entry.address) || /^192\.168\./.test(entry.address) || /^172\.(1[6-9]|2\d|3[01])\./.test(entry.address) });
        }
    }

    if (candidates.length === 0) return '127.0.0.1';
    candidates.sort((a, b) => Number(b.private) - Number(a.private));
    return candidates[0].address;
}

const HOST = envString('ICQ_HOST', '192.168.0.20');
const BOS_ADDRESS = envString('ICQ_BOS_ADDRESS', isWildcardHost(HOST) ? detectLanAddress() : HOST);

const DEBUG_PACKETS = envBool('ICQ_DEBUG_PACKETS', false);

const config = {
    // ── Сеть ──────────────────────────────────────────────
    HOST,
    AUTH_PORT: envInt('ICQ_AUTH_PORT', 5190),
    BOS_PORT: envInt('ICQ_BOS_PORT', 5191),
    // Адрес, который сервер сообщает клиенту для подключения к BOS.
    BOS_ADDRESS,

    // ── Веб-панель и HTTP(S) API ──────────────────────────
    WEB_ENABLED: envBool('ICQ_WEB_ENABLED', true),
    WEB_HOST: envString('ICQ_WEB_HOST', HOST),
    WEB_PORT: envInt('ICQ_WEB_PORT', 8080),
    HTTPS_ENABLED: envBool('ICQ_HTTPS_ENABLED', true),
    HTTPS_PORT: envInt('ICQ_HTTPS_PORT', 443),
    CERT_FILE: envString('ICQ_CERT_FILE', './cert.pem'),
    KEY_FILE: envString('ICQ_KEY_FILE', './key.pem'),
    // По умолчанию CORS выключен: браузерный клиент работает с той же origin,
    // что отдал страницу. '*' больше не выставляется по умолчанию.
    CORS_ALLOW_ORIGIN: envString('ICQ_CORS_ALLOW_ORIGIN', null),
    MAX_REQUEST_BODY: envInt('ICQ_MAX_REQUEST_BODY', 16 * 1024),

    // ── Хранилище ─────────────────────────────────────────
    DB_PATH: envString('ICQ_DB_PATH', './icq.db'),

    // ── Регистрация и UIN ─────────────────────────────────
    REGISTRATION_ENABLED: envBool('ICQ_REGISTRATION_ENABLED', true),
    MIN_PASSWORD_LENGTH: envInt('ICQ_MIN_PASSWORD_LENGTH', 4),
    MAX_PASSWORD_LENGTH: envInt('ICQ_MAX_PASSWORD_LENGTH', 64),
    UIN_MIN: envInt('ICQ_UIN_MIN', 100),
    UIN_MAX: envInt('ICQ_UIN_MAX', 999999),
    MAX_OFFLINE_MESSAGES: envInt('ICQ_MAX_OFFLINE_MESSAGES', 200),
    MAX_OFFLINE_AGE_DAYS: envInt('ICQ_MAX_OFFLINE_AGE_DAYS', 30),

    // ── Пароли ────────────────────────────────────────────
    PBKDF2_ITERATIONS: envInt('ICQ_PBKDF2_ITERATIONS', 210000),
    // Обратимое шифрование пароля нужно протоколу OSCAR: XOR Roasting
    // сравнивает пароль напрямую, BUCP/MD5 и ICQ HTTP API считают от него
    // хеш. При выключении флага остаётся только PBKDF2-хеш, и эти три
    // способа входа перестают работать.
    LEGACY_AUTH_ENABLED: envBool('ICQ_LEGACY_AUTH_ENABLED', true),
    // Пусто → мастер-ключ генерируется и хранится в .authkey (в .gitignore).
    AUTH_MASTER_KEY: envString('ICQ_MASTER_KEY', ''),

    // ── Админ-панель ──────────────────────────────────────
    // Значение по умолчанию — заведомо временное, сервер предупредит в лог.
    ADMIN_USER: envString('ICQ_ADMIN_USER', 'admin'),
    ADMIN_PASS: envString('ICQ_ADMIN_PASS', 'testserver'),
    ADMIN_PANEL_ENABLED: envBool('ICQ_ADMIN_PANEL_ENABLED', true),

    // ── Таймауты и лимиты соединений ──────────────────────
    SESSION_IDLE_TIMEOUT_MS: envInt('ICQ_SESSION_IDLE_TIMEOUT_MS', 15 * 60 * 1000),
    AUTH_TIMEOUT_MS: envInt('ICQ_AUTH_TIMEOUT_MS', 60 * 1000),
    MAX_FRAMED_BYTES: envInt('ICQ_MAX_FRAMED_BYTES', 64 * 1024),
    MAX_BUFFERED_BYTES: envInt('ICQ_MAX_BUFFERED_BYTES', 256 * 1024),
    COOKIE_TTL_MS: envInt('ICQ_COOKIE_TTL_MS', 2 * 60 * 1000),

    // ── Ограничение нагрузки ─────────────────────────────
    // Пакетный лимит на одно TCP-соединение (пакетов/сек, с запасом на
    // burst). Срабатывает только на реальном флуде.
    FLAP_RATE: {
        capacity: envInt('ICQ_FLAP_BURST', 400),
        refillPerSecond: envInt('ICQ_FLAP_REFILL', 120),
    },
    // Байтовый лимит на одно TCP-соединение (байт/сек).
    FLAP_BYTE_RATE: {
        capacity: envInt('ICQ_FLAP_BYTE_BURST', 4 * 1024 * 1024),
        refillPerSecond: envInt('ICQ_FLAP_BYTE_REFILL', 1024 * 1024),
    },
    // Неудачные попытки входа на пару (IP + UIN).
    AUTH_RATE: {
        capacity: envInt('ICQ_AUTH_BURST', 10),
        refillPerSecond: envInt('ICQ_AUTH_REFILL', 0.2),
    },
    // HTTP-запросы на IP.
    HTTP_RATE: {
        capacity: envInt('ICQ_HTTP_BURST', 120),
        refillPerSecond: envInt('ICQ_HTTP_REFILL', 30),
    },

    // ── Отладка ───────────────────────────────────────────
    DEBUG_PACKETS,
};

const PLACEHOLDER_ADMIN_PASS = 'changethispassword';

/**
 * Проверки, которые должны упасть до открытия портов.
 * Возвращает массив предупреждений (не критичных проблем).
 */
function validateConfig() {
    const errors = [];
    const warnings = [];

    const port = (name, value) => {
        if (!Number.isInteger(value) || value < 1 || value > 65535) {
            errors.push(`${name}: порт "${value}" вне диапазона 1-65535`);
        }
    };

    port('AUTH_PORT', config.AUTH_PORT);
    port('BOS_PORT', config.BOS_PORT);
    port('WEB_PORT', config.WEB_PORT);
    port('HTTPS_PORT', config.HTTPS_PORT);

    const taken = new Map();
    const claim = (name, value, enabled = true) => {
        if (!enabled) return;
        if (taken.has(value)) errors.push(`${name} и ${taken.get(value)} используют один порт ${value}`);
        taken.set(value, name);
    };
    claim('AUTH_PORT', config.AUTH_PORT);
    claim('BOS_PORT', config.BOS_PORT);
    claim('WEB_PORT', config.WEB_PORT, config.WEB_ENABLED);
    claim('HTTPS_PORT', config.HTTPS_PORT, config.HTTPS_ENABLED && config.WEB_ENABLED);

    if (config.UIN_MIN > config.UIN_MAX) {
        errors.push(`UIN_MIN (${config.UIN_MIN}) больше UIN_MAX (${config.UIN_MAX})`);
    }
    if (config.MIN_PASSWORD_LENGTH < 1) {
        errors.push(`MIN_PASSWORD_LENGTH должен быть >= 1, получено ${config.MIN_PASSWORD_LENGTH}`);
    }
    if (config.MAX_PASSWORD_LENGTH < config.MIN_PASSWORD_LENGTH) {
        errors.push(`MAX_PASSWORD_LENGTH (${config.MAX_PASSWORD_LENGTH}) меньше MIN_PASSWORD_LENGTH (${config.MIN_PASSWORD_LENGTH})`);
    }
    if (config.PBKDF2_ITERATIONS < 10000) {
        errors.push(`PBKDF2_ITERATIONS (${config.PBKDF2_ITERATIONS}) слишком мало, минимум 10000`);
    }
    if (config.MAX_BUFFERED_BYTES < config.MAX_FRAMED_BYTES) {
        errors.push('MAX_BUFFERED_BYTES должен быть не меньше MAX_FRAMED_BYTES');
    }

    if (isWildcardHost(config.BOS_ADDRESS)) {
        errors.push(
            `BOS_ADDRESS = "${config.BOS_ADDRESS}" — это адрес прослушивания, а не адрес для подключения. ` +
            `Клиент получит его в ответе на вход и не сможет подключиться. ` +
            `Укажите реальный IP этой машины (например 192.168.1.10) или оставьте поле пустым, ` +
            `тогда адрес определится автоматически по сетевым интерфейсам.`
        );
    }
    if (config.CORS_ALLOW_ORIGIN === '*') {
        warnings.push('CORS_ALLOW_ORIGIN = "*" открывает HTTP API любому сайту. Оставьте пустым, если веб-клиент работает с той же origin.');
    }
    if (config.ADMIN_PANEL_ENABLED && config.ADMIN_PASS === PLACEHOLDER_ADMIN_PASS) {
        warnings.push('ADMIN_PASS всё ещё является значением по умолчанию из config.js. Смените его в config.js или через ICQ_ADMIN_PASS.');
    }
    if (config.LEGACY_AUTH_ENABLED) {
        warnings.push('LEGACY_AUTH_ENABLED = true: пароли дополнительно хранятся в виде AES-256-GCM шифротекста, потому что протокол OSCAR требует сам пароль (XOR/BUCP/HTTP API). Утечка БД без .authkey пароли не раскрывает, утечка сервера целиком — раскрывает.');
    }
    if (config.DEBUG_PACKETS) {
        warnings.push('DEBUG_PACKETS включён: каждый байт трафика печатается в консоль и попадает в логи. Не используйте на публичном сервере.');
    }

    return { errors, warnings };
}

module.exports = { ...config, detectLanAddress, isWildcardHost, validateConfig, PLACEHOLDER_ADMIN_PASS };