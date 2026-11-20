'use strict';
/**
 * Точка входа: TCP-серверы OSCAR (AUTH + BOS) и запуск веб-панели.
 *
 * Здесь же живёт защита соединения на транспортном уровне:
 *   - ведро токенов на пакеты и на байты (антифлуд);
 *   - проверка длины кадра до выделения буфера;
 *   - таймаут неактивности сессии и таймаут AUTH-соединения;
 *   - аккуратное завершение по SIGINT/SIGTERM.
 */

const net = require('net');
const crypto = require('crypto');
const config = require('./config');
const db = require('./database');
const { hexDump } = require('./utils');
const Auth = require('./auth');
const BOS = require('./bos');
const { TokenBucket, KeyedRateLimiter } = require('./ratelimit');
const { makeFLAP, makeSNAC, parseTLVs, OscarBuilder, FLAP_MAGIC, HEADER_SIZE } = require('./oscar');

const sessions = new Map();

// Перебор пароля считаем по паре (IP + UIN): один UIN с разных IP тоже
// упирается в лимит на каждый адрес отдельно.
const authAttempts = new KeyedRateLimiter(config.AUTH_RATE);

class Session {
    constructor(socket, type) {
        this.socket = socket;
        this.type = type;
        this.buffer = Buffer.alloc(0);
        this.seq = 0;
        this.uin = null;
        this.status = 0;
        this.signonTime = 0;
        this.profile = '';
        this.awayMsg = '';
        this.watching = new Set();
        this.userTLVs = new Map();

        this.remoteAddress = socket.remoteAddress || '?';
        this.lastActivity = Date.now();
        this.createdAt = this.lastActivity;

        // Лимиты транспорта — свои для каждого соединения.
        this.packetBucket = new TokenBucket(config.FLAP_RATE);
        this.byteBucket = new TokenBucket(config.FLAP_BYTE_RATE);
        this.closed = false;
        this.floodWarned = false;
    }

    initDefaults() {
        this.userTLVs.set(0x0001, Buffer.from([0x00, 0x40]));
        this.userTLVs.set(0x0006, Buffer.from([0x00, 0x00, 0x00, 0x00]));
        const tBuf = Buffer.alloc(4);
        tBuf.writeUInt32BE(this.signonTime);
        this.userTLVs.set(0x0003, tBuf);
        this.userTLVs.set(0x000D, Buffer.concat([
            Buffer.from('094613494C7F11D18222444553540000', 'hex'),
            Buffer.from('0946134E4C7F11D18222444553540000', 'hex'),
        ]));
        const dc = Buffer.alloc(37);
        dc.writeUInt32BE(0x7F000001, 0);
        dc.writeUInt8(0x04, 8);
        dc.writeUInt16BE(0x000A, 9);
        this.userTLVs.set(0x000C, dc);
    }

    sendFLAP(channel, data) {
        if (this.closed) return;
        this.seq = (this.seq + 1) & 0xFFFF;
        const packet = makeFLAP(channel, this.seq, data || Buffer.alloc(0));
        hexDump(packet, `→ OUT [${this.type}] ${this.uin || ''}`);
        try { this.socket.write(packet); } catch (e) { /* сокет уже мёртв */ }
    }

    sendSNAC(fam, sub, flags, reqId, data) {
        this.sendFLAP(0x02, makeSNAC(fam, sub, flags, reqId, data || Buffer.alloc(0)));
    }

    /** Мягкое закрытие: сначала FLAP «разъезд», затем FIN. */
    disconnect() {
        if (this.closed) return;
        this.closed = true;
        try { this.sendFLAP(0x04, Buffer.alloc(0)); } catch (e) { /* игнорируем */ }
        try { this.socket.end(); } catch (e) { /* игнорируем */ }
    }

    /** Жёсткое закрытие без прощания — админ-панель, таймауты, флуд. */
    destroy() {
        this.closed = true;
        try { this.socket.destroy(); } catch (e) { /* игнорируем */ }
    }

    get isIdle() {
        return Date.now() - this.lastActivity > this.idleTimeout;
    }

    get idleTimeout() {
        return this.type === 'BOS' ? config.SESSION_IDLE_TIMEOUT_MS : config.AUTH_TIMEOUT_MS;
    }
}

// ═══════════════════════════════════════════
//  FLAP обработка
// ═══════════════════════════════════════════

async function handleFLAP(session, channel, data) {

    if (channel === 0x01) {

        // ──── AUTH ────
        if (session.type === 'AUTH') {
            if (data.length <= 4) {
                console.log('\x1b[33m[AUTH]\x1b[0m BUCP handshake');
                return;
            }

            const tlvs = parseTLVs(data.subarray(4));
            const uinTlv = tlvs[0x0001];
            const hasPass = tlvs[0x0002] || tlvs[0x0025];

            if (uinTlv && hasPass) {
                const uin = uinTlv.toString().trim();

                // Пустой UIN в Channel 1 = запрос регистрации (старый клиент)
                if (!uin) {
                    console.log('\x1b[35m[AUTH]\x1b[0m Пустой UIN в Channel 1 → регистрация');
                    const handled = await Auth.handleChannel1Registration(session, tlvs);
                    if (handled) return;
                }

                if (uin) {
                    const limitKey = `${session.remoteAddress}|${uin}`;
                    if (!authAttempts.allow(limitKey)) {
                        console.log(`\x1b[31m[AUTH]\x1b[0m Превышен лимит попыток для ${uin} с ${session.remoteAddress}`);
                        session.destroy();
                        return;
                    }

                    console.log(`\x1b[33m[AUTH]\x1b[0m Старый клиент, UIN: ${uin}`);
                    const valid = await Auth.checkCredentials(uin, tlvs);

                    if (valid) {
                        authAttempts.reset(limitKey);
                        console.log(`\x1b[32m[AUTH OK]\x1b[0m ${uin} → BOS`);
                        const cookie = Auth.issueCookie(uin);

                        session.sendFLAP(0x04, new OscarBuilder()
                            .tlv(0x0001, uin)
                            .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                            .tlv(0x0006, cookie)
                            .build());
                        session.socket.end();
                    } else {
                        console.log(`\x1b[31m[AUTH FAIL]\x1b[0m ${uin}`);
                        Auth.sendChannel1Error(session, uin, 0x0005);
                        session.socket.end();
                    }
                    return;
                }
            }

            if (uinTlv) console.log(`\x1b[33m[AUTH]\x1b[0m BUCP-клиент ${uinTlv.toString()}`);
            return;
        }

        // ──── BOS ────
        if (session.type === 'BOS') {
            if (data.length <= 4) return;
            const tlvs = parseTLVs(data.subarray(4));
            const cookieTlv = tlvs[0x0006];
            if (!cookieTlv) { session.disconnect(); return; }

            const uin = Auth.consumeCookie(cookieTlv.toString('hex'));
            if (!uin) {
                console.log('\x1b[31m[BOS]\x1b[0m Недействительный или истёкший cookie');
                session.disconnect();
                return;
            }

            // Один UIN — одна сессия: старую закрываем.
            const old = sessions.get(uin);
            if (old) {
                console.log(`\x1b[33m[BOS]\x1b[0m UIN ${uin} переподключается, старая сессия закрывается`);
                old.destroy();
                sessions.delete(uin);
            }

            session.uin = uin;
            session.signonTime = Math.floor(Date.now() / 1000);
            session.initDefaults();
            sessions.set(uin, session);

            const ssiBuddies = await db.getSSIBuddies(uin);
            for (const b of ssiBuddies) session.watching.add(b.name);

            console.log(`\x1b[32m[BOS]\x1b[0m ${uin} ONLINE (${sessions.size} в сети, следит за ${session.watching.size})`);

            const fam = new OscarBuilder();
            [0x0001, 0x0002, 0x0003, 0x0004, 0x0009, 0x0013, 0x0015].forEach(f => fam.u16(f));
            session.sendSNAC(0x0001, 0x0003, 0, 0, fam.build());

            session.sendSNAC(0x0001, 0x0013, 0, 0,
                new OscarBuilder().u16(1).tlv(0x000B, 'Welcome!').build());
        }
    }

    else if (channel === 0x02) {
        if (data.length < 10) return;
        const snac = {
            family:  data.readUInt16BE(0),
            subtype: data.readUInt16BE(2),
            flags:   data.readUInt16BE(4),
            reqId:   data.readUInt32BE(6),
            data:    data.subarray(10)
        };
        if (session.type === 'AUTH') await Auth.handlePacket(session, snac);
        else if (session.type === 'BOS' && session.uin) await BOS.handlePacket(session, snac, { sessions });
    }
}

// ═══════════════════════════════════════════
//  TCP серверы
// ═══════════════════════════════════════════

const servers = [];

function createServer(type, port) {
    const server = net.createServer(socket => {
        const session = new Session(socket, type);
        const addr = `${session.remoteAddress}:${socket.remotePort}`;
        console.log(`[${type}] Подключение с ${addr}`);

        socket.setNoDelay(true);
        session.sendFLAP(0x01, Buffer.from([0x00, 0x00, 0x00, 0x01]));

        socket.on('data', async chunk => {
            session.lastActivity = Date.now();
            hexDump(chunk, `← IN[${type}] ${session.uin || addr}`);

            // ── Антифлуд: пакеты и байты по отдельному ведру ──
            const packetsOk = session.packetBucket.tryRemove(1);
            const bytesOk = session.byteBucket.tryRemove(chunk.length);

            if (!packetsOk || !bytesOk) {
                if (!session.floodWarned) {
                    session.floodWarned = true;
                    console.log(`\x1b[31m[FLOOD]\x1b[0m Превышен лимит трафика на соединении ${addr} (${type}), разрываем`);
                }
                session.destroy();
                return;
            }

            session.buffer = Buffer.concat([session.buffer, chunk]);

            // Защита от «половинного» кадра, раздувающего буфер.
            if (session.buffer.length > config.MAX_BUFFERED_BYTES) {
                console.log(`\x1b[31m[FLOOD]\x1b[0m Буфер неполного кадра > ${config.MAX_BUFFERED_BYTES} байт у ${addr}, разрываем`);
                session.destroy();
                return;
            }

            try {
                while (session.buffer.length >= HEADER_SIZE) {
                    if (session.buffer[0] !== FLAP_MAGIC) {
                        console.log(`\x1b[31m[PROTO]\x1b[0m Неверный FLAP-магic от ${addr}, разрываем`);
                        session.destroy();
                        return;
                    }

                    const dataLen = session.buffer.readUInt16BE(4);

                    // Длина кадра проверяется ДО выделения памяти и разбора.
                    if (dataLen > config.MAX_FRAMED_BYTES) {
                        console.log(`\x1b[31m[PROTO]\x1b[0m Заявленная длина кадра ${dataLen} > ${config.MAX_FRAMED_BYTES} от ${addr}, разрываем`);
                        session.destroy();
                        return;
                    }

                    const totalLen = HEADER_SIZE + dataLen;
                    if (session.buffer.length < totalLen) break;

                    const chan = session.buffer[1];
                    const frameData = Buffer.from(session.buffer.subarray(HEADER_SIZE, totalLen));
                    session.buffer = session.buffer.subarray(totalLen);

                    await handleFLAP(session, chan, frameData);
                    if (session.closed) return;
                }
            } catch (e) {
                console.error('\x1b[31m[ERROR]\x1b[0m', e.stack || e);
            }
        });

        socket.on('error', err => {
            console.log(`\x1b[90m[${type}]\x1b[0m Ошибка сокета ${addr}: ${err.code || err.message}`);
        });

        socket.on('close', async () => {
            if (session.uin && sessions.get(session.uin) === session) {
                sessions.delete(session.uin);
                console.log(`\x1b[31m[OFFLINE]\x1b[0m ${session.uin} (${sessions.size} в сети)`);
                try { await BOS.notifyWatchers(session, sessions, false); } catch (e) { /* не критично */ }
            }
        });
    });

    server.on('error', err => {
        console.error(`\x1b[31m[${type}]\x1b[0m Ошибка сервера на порту ${port}: ${err.code || err.message}`);
        if (err.code === 'EADDRINUSE') process.exitCode = 1;
    });

    server.listen(port, config.HOST, () => {
        console.log(`\x1b[1m${type}\x1b[0m сервер слушает ${config.HOST}:${port}`);
    });

    servers.push(server);
    return server;
}

// ── Сборка ICBM-пакета для системной рассылки ──
function makeBroadcast(sessionsMap) {
    return function broadcastMessage(text) {
        const sender = 'System';
        const textBuf = Buffer.from(text, 'utf8');

        // Fragment 1: возможности/фичи сообщения.
        const frag1 = Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01]);

        // Fragment 2: сам текст с заголовками charset и language.
        const frag2 = Buffer.alloc(8 + textBuf.length);
        frag2.writeUInt16BE(0x0101, 0);              // fragment id (текст)
        frag2.writeUInt16BE(textBuf.length + 4, 2);  // длина фрагмента
        frag2.writeUInt16BE(0x0000, 4);              // charset: US-ASCII/UTF-8
        frag2.writeUInt16BE(0x0000, 6);              // language: English
        textBuf.copy(frag2, 8);

        const tlv02 = Buffer.concat([frag1, frag2]);
        let sent = 0;

        for (const session of sessionsMap.values()) {
            if (session.type !== 'BOS' || !session.uin) continue;

            const b = new OscarBuilder()
                .raw(crypto.randomBytes(8))          // cookie
                .u16(1)                              // channel 1
                .u8(sender.length).string(sender)
                .u16(0).u16(2)                       // warning level, TLV count
                .tlv(0x0001, Buffer.from([0x00, 0x40]))
                .tlv(0x0006, Buffer.from([0, 0, 0, 0]))
                .tlv(0x0002, tlv02);

            session.sendSNAC(0x0004, 0x0007, 0, 0, b.build());
            sent++;
        }
        return sent;
    };
}

// ── Периодическая уборка: таймауты сессий и истёкшие cookie ──
const janitor = setInterval(() => {
    for (const [uin, session] of sessions) {
        if (session.isIdle) {
            console.log(`\x1b[33m[IDLE]\x1b[0m ${uin} отключён по таймауту неактивности`);
            session.destroy();
            sessions.delete(uin);
            BOS.notifyWatchers(session, sessions, false).catch(() => {});
        }
    }
    Auth.sweepCookies();
}, 30000);
if (janitor.unref) janitor.unref();

// ═══════════════════════════════════════════
//  Запуск и корректное завершение
// ═══════════════════════════════════════════

async function main() {
    const { errors, warnings } = config.validateConfig();

    for (const warning of warnings) console.log(`\x1b[33m[WARN]\x1b[0m ${warning}`);
    if (errors.length > 0) {
        console.error('\n\x1b[31mОшибки конфигурации:\x1b[0m');
        for (const err of errors) console.error(`  • ${err}`);
        console.error('\nИсправьте config.js (или переменные окружения) и запустите снова.\n');
        process.exit(1);
    }

    await db.init();

    createServer('AUTH', config.AUTH_PORT);
    createServer('BOS', config.BOS_PORT);

    if (config.WEB_ENABLED) {
        try {
            const { startWeb } = require('./web');
            await startWeb({ sessions, broadcast: makeBroadcast(sessions) });
        } catch (e) {
            console.error(`\x1b[31m[WEB]\x1b[0m Веб-сервер не запущен: ${e.stack || e.message}`);
        }
    } else {
        console.log('\x1b[90m[WEB]\x1b[0m Веб-сервер отключён (WEB_ENABLED = false)');
    }

    console.log(`\nРегистрация через OSCAR: ${config.REGISTRATION_ENABLED ? '\x1b[32mвключена\x1b[0m' : '\x1b[31mотключена\x1b[0m'}`);
    console.log(`Диапазон UIN: ${config.UIN_MIN} — ${config.UIN_MAX}`);
    console.log(`BOS-адрес для клиентов: ${config.BOS_ADDRESS}:${config.BOS_PORT}`);
    console.log(`Админка: ${config.ADMIN_PANEL_ENABLED ? `${config.ADMIN_USER}@http://${config.WEB_HOST}:${config.WEB_PORT}/admin` : 'отключена'}`);
    console.log('\nВсе серверы готовы.\n');
}

let shuttingDown = false;
async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n\x1b[33m[SHUTDOWN]\x1b[0m Получен ${signal}, закрываем соединения...`);

    for (const [uin, session] of sessions) {
        console.log(`  ${uin}`);
        session.disconnect();
    }
    sessions.clear();

    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    console.log('\x1b[32m[SHUTDOWN]\x1b[0m Порты закрыты.');

    try { await require('./web').stopWeb(); } catch (e) { /* веб мог не стартовать */ }

    try { await db.close(); console.log('\x1b[32m[SHUTDOWN]\x1b[0m БД закрыта.'); } catch (e) { /* уже закрыта */ }

    process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', reason => {
    console.error('\x1b[31m[UNHANDLED]\x1b[0m', reason);
});

main().catch(err => {
    console.error('\x1b[31m[FATAL]\x1b[0m', err.stack || err);
    process.exit(1);
});