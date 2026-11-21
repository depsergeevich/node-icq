'use strict';


const crypto = require('crypto');
const db = require('./database');
const security = require('./security');
const { OscarBuilder, parseTLVs } = require('./oscar');
const config = require('./config');





const ROAST = Buffer.from([
    0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
    0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
]);

function xorDecode(buf) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        out[i] = buf[i] ^ ROAST[i % ROAST.length];
    }
    let end = out.length;
    while (end > 0 && out[end - 1] === 0) end--;
    return out.subarray(0, end).toString('utf8');
}

function md5(data) {
    return crypto.createHash('md5').update(data).digest();
}


function maskSecret(value) {
    if (typeof value !== 'string' || value.length === 0) return '(empty)';
    return `${'*'.repeat(Math.min(8, value.length))} (${value.length} chars)`;
}

const Auth = {
    keys: new Map(),           
    pendingCookies: new Map(), 

    issueCookie(uin, bytes = 256) {
        const cookie = security.randomToken(bytes);
        this.pendingCookies.set(cookie.toString('hex'), {
            uin,
            expiresAt: Date.now() + config.COOKIE_TTL_MS,
        });
        return cookie;
    },

    consumeCookie(hex) {
        const entry = this.pendingCookies.get(hex);
        if (!entry) return null;
        this.pendingCookies.delete(hex);
        if (entry.expiresAt < Date.now()) return null;
        return entry.uin;
    },

    
    sweepCookies() {
        const now = Date.now();
        let removed = 0;
        for (const [key, entry] of this.pendingCookies) {
            if (entry.expiresAt < now) { this.pendingCookies.delete(key); removed++; }
        }
        return removed;
    },

    
    async checkCredentials(uin, tlvs) {
        const md5Hash = tlvs[0x0025];
        const roasted = tlvs[0x0002];

        if (!md5Hash && !roasted) return false;

        const user = await db.get('SELECT uin FROM users WHERE uin = ?', [uin]);
        if (!user) {
            console.log(`\x1b[31m[AUTH]\x1b[0m UIN ${uin} не найден`);
            return false;
        }

        const plain = await db.getProtocolSecret(uin);
        if (plain === null) {
            console.log(`\x1b[31m[AUTH]\x1b[0m Для UIN ${uin} нет эскорт-слоя пароля (LEGACY_AUTH_ENABLED или сменился мастер-ключ). Протокольный вход недоступен — задайте пароль через "node database.js passwd ${uin} <PASS>".`);
            return false;
        }

        let ok = false;
        let method = '';

        if (md5Hash) {
            const authKey = this.keys.get(uin) || '';
            const material = Buffer.concat([
                Buffer.from(authKey),
                md5(plain),
                Buffer.from('AOL Instant Messenger (SM)')
            ]);
            ok = security.safeEqual(md5(material), md5Hash);
            method = 'MD5/BUCP';
        } else if (roasted) {
            const decoded = xorDecode(roasted);
            ok = security.safeEqual(decoded, plain);
            method = 'XOR';
        }

        this.keys.delete(uin);
        console.log(`\x1b[33m[AUTH]\x1b[0m ${method} для ${uin}: ${ok ? '\x1b[32mOK' : '\x1b[31mFAIL'}\x1b[0m`);

        if (ok) {
            
            try { await db.ensureProtocolSecret(uin, plain); } catch (e) {  }
        }
        return ok;
    },

    
    async handlePacket(session, snac) {
        if (snac.subtype === 0x0004) {
            await this.handleRegistration(session, snac);
            return;
        }

        
        if (snac.subtype === 0x0006) {
            let uin = '';
            const tlvs = parseTLVs(snac.data);
            if (tlvs[0x0001]) {
                uin = tlvs[0x0001].toString();
            } else if (snac.data.length >= 4) {
                const len = snac.data.readUInt16BE(0);
                if (len > 0 && len < snac.data.length - 2) {
                    uin = snac.data.subarray(2, 2 + len).toString();
                }
            }

            console.log(`\x1b[33m[AUTH]\x1b[0m Запрос ключа для UIN: ${uin}`);

            const key = security.randomToken(16).toString('hex');
            if (uin) this.keys.set(uin, key);

            const keyBuf = Buffer.from(key);
            session.sendSNAC(0x0017, 0x0007, 0, snac.reqId,
                new OscarBuilder().u16(keyBuf.length).raw(keyBuf).build());
        }

        
        if (snac.subtype === 0x0002) {
            const tlvs = parseTLVs(snac.data);
            const uinTlv = tlvs[0x0001];
            if (!uinTlv) return;

            const uin = uinTlv.toString().trim();
            console.log(`\x1b[33m[AUTH]\x1b[0m BUCP-вход: ${uin}`);

            const valid = await this.checkCredentials(uin, tlvs);

            if (valid) {
                console.log(`\x1b[32m[AUTH OK]\x1b[0m ${uin} → BOS`);
                const cookie = this.issueCookie(uin);

                session.sendSNAC(0x0017, 0x0003, 0, snac.reqId,
                    new OscarBuilder()
                        .tlv(0x0001, uin)
                        .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                        .tlv(0x0006, cookie)
                        .build());

                session.disconnect();
            } else {
                console.log(`\x1b[31m[AUTH FAIL]\x1b[0m ${uin}`);
                this.sendAuthError(session, snac.reqId, uin, 0x0005);
            }
        }
    },

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    async handleRegistration(session, snac) {
        console.log('\x1b[35m[REGISTER]\x1b[0m Получен запрос регистрации');

        if (!config.REGISTRATION_ENABLED) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Регистрация отключена в конфиге');
            this.sendRegError(session, snac.reqId, 0x0006, 'Registration is disabled');
            return;
        }

        const tlvs = parseTLVs(snac.data);

        let password = '';
        if (tlvs[0x0002]) {
            password = xorDecode(tlvs[0x0002]);
        } else if (tlvs[0x0025]) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Клиент прислал MD5-хеш — для регистрации нужен открытый пароль');
            this.sendRegError(session, snac.reqId, 0x0006, 'Cannot register with MD5 auth');
            return;
        }

        if (password.length < config.MIN_PASSWORD_LENGTH) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Слишком короткий пароль (минимум ${config.MIN_PASSWORD_LENGTH})');
            this.sendRegError(session, snac.reqId, 0x0006, 'Password too short');
            return;
        }
        if (password.length > config.MAX_PASSWORD_LENGTH) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Слишком длинный пароль (максимум ${config.MAX_PASSWORD_LENGTH})');
            this.sendRegError(session, snac.reqId, 0x0006, 'Password too long');
            return;
        }

        let desiredUin = '';
        if (tlvs[0x0001]) desiredUin = tlvs[0x0001].toString().trim();

        const email = tlvs[0x000E] ? tlvs[0x000E].toString() : '';
        const clientInfo = tlvs[0x0003] ? tlvs[0x0003].toString() : '';

        console.log(`\x1b[35m[REGISTER]\x1b[0m Желаемый UIN: "${desiredUin || 'auto'}", пароль: ${maskSecret(password)}, клиент: "${clientInfo}"`);

        const opts = { nickname: desiredUin || undefined, email };
        if (desiredUin && /^\d+$/.test(desiredUin)) opts.uin = desiredUin;

        const result = await db.registerUser(password, opts);

        if (result.error) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Отказано: ${result.error}`);

            if (result.error.includes('already taken') || result.error.includes('No free UINs')) {
                this.sendRegError(session, snac.reqId, 0x0014, result.error);
            } else {
                this.sendRegError(session, snac.reqId, 0x0006, result.error);
            }
            return;
        }

        const newUin = result.uin;
        console.log(`\x1b[32m[REGISTER]\x1b[0m ★ Новый аккаунт: UIN ${newUin}`);

        const cookie = this.issueCookie(newUin);

        session.sendSNAC(0x0017, 0x0005, 0, snac.reqId,
            new OscarBuilder()
                .tlv(0x0001, newUin)
                .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                .tlv(0x0006, cookie)
                .build());

        console.log(`\x1b[32m[REGISTER]\x1b[0m UIN ${newUin} передан клиенту, cookie готов для BOS`);

        
        
    },

    
    
    
    
    
    
    

    async handleChannel1Registration(session, tlvs) {
        if (!config.REGISTRATION_ENABLED) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Регистрация отключена в конфиге (channel 1)');
            return false;
        }

        const uinTlv = tlvs[0x0001];
        const passTlv = tlvs[0x0002];

        if (!passTlv) return false;

        const uin = uinTlv ? uinTlv.toString().trim() : '';
        if (uin && uin.length > 0) return false; 

        const password = xorDecode(passTlv);
        if (password.length < config.MIN_PASSWORD_LENGTH) {
            console.log('\x1b[31m[REGISTER]\x1b[0m Слишком короткий пароль (channel 1)');
            return false;
        }

        console.log('\x1b[35m[REGISTER]\x1b[0m Регистрация через Channel 1');

        const result = await db.registerUser(password, {});

        if (result.error) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Отказано: ${result.error}`);

            const errBuf = Buffer.alloc(2);
            errBuf.writeUInt16BE(result.error.includes('already taken') || result.error.includes('No free UINs') ? 0x0014 : 0x0006);

            session.sendFLAP(0x04, new OscarBuilder()
                .tlv(0x0004, 'http://icq.com/')
                .tlv(0x0008, errBuf)
                .build());
            session.socket.end();
            return true;
        }

        const newUin = result.uin;
        console.log(`\x1b[32m[REGISTER]\x1b[0m ★ Новый аккаунт (ch1): UIN ${newUin}`);

        const cookie = this.issueCookie(newUin);

        session.sendFLAP(0x04, new OscarBuilder()
            .tlv(0x0001, newUin)
            .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
            .tlv(0x0006, cookie)
            .build());

        session.socket.end();
        return true;
    },

    
    
    sendChannel1Error(session, uin, errorCode) {
        const errBuf = Buffer.alloc(2);
        errBuf.writeUInt16BE(errorCode);
        session.sendFLAP(0x04, new OscarBuilder()
            .tlv(0x0001, uin)
            .tlv(0x0004, 'http://icq.com/')
            .tlv(0x0008, errBuf)
            .build());
    },

    sendAuthError(session, reqId, uin, errorCode) {
        const errBuf = Buffer.alloc(2);
        errBuf.writeUInt16BE(errorCode);
        session.sendSNAC(0x0017, 0x0003, 0, reqId,
            new OscarBuilder()
                .tlv(0x0001, uin)
                .tlv(0x0004, 'http://icq.com/')
                .tlv(0x0008, errBuf)
                .build());
    },

    sendRegError(session, reqId, errorCode, errorText) {
        const errBuf = Buffer.alloc(2);
        errBuf.writeUInt16BE(errorCode);
        session.sendSNAC(0x0017, 0x0001, 0, reqId,
            new OscarBuilder()
                .tlv(0x0008, errBuf)
                .tlv(0x0004, errorText || 'http://icq.com/')
                .build());
    },
};

module.exports = Auth;
module.exports.xorDecode = xorDecode;