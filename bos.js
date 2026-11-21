const iconv = require('iconv-lite');
const { OscarBuilder, parseTLVs } = require('./oscar');
const db = require('./database');





function packUserInfoOnline(session) {
    const uinBuf = Buffer.from(session.uin, 'utf8');
    const b = new OscarBuilder();
    b.u8(uinBuf.length).raw(uinBuf);
    b.u16(0);
    const tlvMap = session.userTLVs;
    b.u16(tlvMap.size);
    for (const [type, value] of tlvMap) b.tlv(type, value);
    return b.build();
}

function packUserInfoOffline(uin) {
    const uinBuf = Buffer.from(uin, 'utf8');
    return new OscarBuilder().u8(uinBuf.length).raw(uinBuf).u16(0).u16(0).build();
}

function parseSSIItems(data) {
    const items =[];
    let pos = 0;
    while (pos + 10 <= data.length) {
        const nameLen = data.readUInt16BE(pos); pos += 2;
        if (pos + nameLen + 8 > data.length) break;
        const name = data.subarray(pos, pos + nameLen).toString('utf8'); pos += nameLen;
        const gid = data.readUInt16BE(pos); pos += 2;
        const iid = data.readUInt16BE(pos); pos += 2;
        const type = data.readUInt16BE(pos); pos += 2;
        const tlvLen = data.readUInt16BE(pos); pos += 2;
        let tlvData = null;
        if (tlvLen > 0) {
            if (pos + tlvLen > data.length) break;
            tlvData = Buffer.from(data.subarray(pos, pos + tlvLen));
            pos += tlvLen;
        }
        items.push({ name, gid, iid, type, tlvData });
    }
    return items;
}

function writeLNTS(str) {
    const data = Buffer.from((str || '') + '\0', 'utf8');
    const len = Buffer.alloc(2);
    len.writeUInt16LE(data.length);
    return Buffer.concat([len, data]);
}

function writeLTLV(type, buf) {
    const head = Buffer.alloc(4);
    head.writeUInt16LE(type, 0);
    head.writeUInt16LE(buf.length, 2);
    return Buffer.concat([head, buf]);
}








const ICQ_FIELD = {
    UIN: 310,          
    FIRSTNAME: 320,    
    LASTNAME: 330,     
    NICKNAME: 340,     
    EMAIL: 350,        
    AGE_RANGE: 360,    
    AGE: 370,          
    GENDER: 380,       
    CITY: 400,         
    STATE: 410,        
    COUNTRY: 420,      
    BIRTH_YEAR: 372,   
    BIRTH_MONTH: 374,  
    BIRTH_DAY: 376,    
    HOMEPAGE_CAT: 530, 
    HOMEPAGE_URL: 531, 
    KEYWORD: 550,      
    ONLINE_ONLY: 560,  
    ABOUT: 600,        
    PHONE: 630,        
};



function parseICQMetaTLVs(buf) {
    const map = {};
    let pos = 0;
    while (pos + 4 <= buf.length) {
        const type = buf.readUInt16LE(pos);
        const len = buf.readUInt16LE(pos + 2);
        pos += 4;
        if (len < 0 || pos + len > buf.length) break;
        map[type] = buf.subarray(pos, pos + len);
        pos += len;
    }
    return map;
}





























const INFIUM_FIELD = {
    UIN: 0x0032, EMAIL: 0x0050, FIRSTNAME: 0x0064, LASTNAME: 0x006E,
    NICKNAME: 0x0078, GENDER: 0x0082, LANGUAGE: 0x00FA, CITY: 0x00A0,
    COUNTRY: 0x00BE, AGE_RANGE: 0x0154, ONLINE_ONLY: 0x0136,
};

function skipInfiumHeader(buf) {
    let pos = 0;
    const need = (n) => pos + n <= buf.length;
    if (!need(6)) return null;
    pos += 2;                                    
    pos += 2;                                    
    const type2 = buf.readUInt16LE(pos); pos += 2;
    if (!need(12)) return null;
    pos += 12;                                   
    if (type2 !== 0x0FD2) { if (!need(2)) return null; pos += 2; }
    if (!need(2)) return null;
    pos += 2;                                    
    if (type2 !== 0x0FD2) { if (!need(2)) return null; pos += 2; }
    if (!need(4)) return null;
    pos += 4;                                    
    return pos;
}

function readInfiumString(valueBuf) {
    if (!valueBuf || valueBuf.length === 0) return '';
    
    
    
    try {
        const s = valueBuf.toString('utf16le').replace(/\0+$/, '').trim();
        if (s && /^[\x20-\x7Eа-яА-ЯёЁ]*$/.test(s)) return s;
    } catch (e) {  }
    return valueBuf.toString('utf8').replace(/\0+$/, '').trim();
}





function parseInfiumBody(buf) {
    
    if (buf.length >= 2) {
        const count = buf.readUInt16BE(0);
        if (count > 0 && count < 200) {
            let pos = 2, ok = true;
            const found = [];
            for (let i = 0; i < count && ok; i++) {
                if (pos + 2 > buf.length) { ok = false; break; }
                const recLen = buf.readUInt16BE(pos); pos += 2;
                if (pos + recLen > buf.length) { ok = false; break; }
                const rec = buf.subarray(pos, pos + recLen); pos += recLen;
                let ipos = 0;
                while (ipos + 4 <= rec.length) {
                    const itype = rec.readUInt16BE(ipos);
                    const ilen = rec.readUInt16BE(ipos + 2);
                    ipos += 4;
                    if (ipos + ilen > rec.length) { ok = false; break; }
                    if (itype === INFIUM_FIELD.UIN) {
                        const s = rec.subarray(ipos, ipos + ilen).toString('ascii');
                        if (/^\d+$/.test(s)) found.push(s);
                    }
                    ipos += ilen;
                }
            }
            if (ok && pos === buf.length && found.length > 0) return { kind: 'uins', uins: found };
        }
    }

    
    
    
    if (buf.length >= 4) {
        let pos = 0, ok = true;
        const fields = {};
        while (pos + 4 <= buf.length) {
            const type = buf.readUInt16BE(pos);
            const len = buf.readUInt16BE(pos + 2);
            pos += 4;
            if (pos + len > buf.length) { ok = false; break; }
            fields[type] = buf.subarray(pos, pos + len);
            pos += len;
        }
        if (ok && pos === buf.length && Object.keys(fields).length > 0) {
            const nonUinKeys = Object.keys(fields).map(Number).filter(t => t !== INFIUM_FIELD.UIN);
            if (nonUinKeys.length === 0) {
                
                const uins = [];
                const v = fields[INFIUM_FIELD.UIN];
                const s = v.toString('ascii');
                if (/^\d+$/.test(s)) uins.push(s);
                if (uins.length > 0) return { kind: 'uins', uins };
            } else {
                
                const criteria = {};
                if (fields[INFIUM_FIELD.NICKNAME]) criteria.nickname = readInfiumString(fields[INFIUM_FIELD.NICKNAME]);
                if (fields[INFIUM_FIELD.FIRSTNAME]) criteria.firstname = readInfiumString(fields[INFIUM_FIELD.FIRSTNAME]);
                if (fields[INFIUM_FIELD.LASTNAME]) criteria.lastname = readInfiumString(fields[INFIUM_FIELD.LASTNAME]);
                if (fields[INFIUM_FIELD.EMAIL]) criteria.email = readInfiumString(fields[INFIUM_FIELD.EMAIL]);
                if (fields[INFIUM_FIELD.CITY]) criteria.city = readInfiumString(fields[INFIUM_FIELD.CITY]);
                if (fields[INFIUM_FIELD.GENDER] && fields[INFIUM_FIELD.GENDER].length >= 1) {
                    criteria.gender = fields[INFIUM_FIELD.GENDER].readUInt8(0);
                }
                if (fields[INFIUM_FIELD.AGE_RANGE] && fields[INFIUM_FIELD.AGE_RANGE].length >= 4) {
                    criteria.ageMin = fields[INFIUM_FIELD.AGE_RANGE].readUInt16BE(0);
                    criteria.ageMax = fields[INFIUM_FIELD.AGE_RANGE].readUInt16BE(2);
                }
                if (Object.keys(criteria).length > 0) return { kind: 'criteria', criteria };
            }
        }
    }

    return { kind: 'unknown' };
}



function readSString(valueBuf) {
    if (!valueBuf || valueBuf.length < 2) return '';
    const strLen = valueBuf.readUInt16LE(0);
    if (2 + strLen > valueBuf.length) return '';
    return valueBuf.subarray(2, 2 + strLen).toString('utf8').replace(/\0+$/, '');
}

function writeSString(str) {
    const data = Buffer.from((str || '') + '\0', 'utf8');
    const len = Buffer.alloc(2);
    len.writeUInt16LE(data.length);
    return Buffer.concat([len, data]);
}







const META_SUCCESS = 0x0A;
const META_FAIL = 0x14;
const META_EMPTY = 0x32; 

const META_REQ = {
    HOMEINFO: 0x04D0,   
    SHORTINFO: 0x04BA,  
    FULLINFO: 0x04B2,   
    WP_UIN: 0x051F,     
};

const META_RESP = {
    SHORT: 0x0104,
    HOME: 0x00C8,
    MORE: 0x00DC,
    EMAIL: 0x00EB,
    HPAGE: 0x010E,
    WORK: 0x00D2,
    ABOUT: 0x00E6,
    INTERESTS: 0x00F0,
    AFFILATIONS: 0x00FA,
};

const META_SET_REQ = {
    HOMEINFO: 0x03EA,
    MOREINFO: 0x03FD,
    NOTESINFO: 0x0406,
};

const META_SET_ACK = {
    HOMEINFO: 0x0064,
    MOREINFO: 0x0078,
    NOTESINFO: 0x0082,
};



function makeSeqReader(buf) {
    let pos = 0;
    return {
        lnts() {
            if (pos + 2 > buf.length) return '';
            const len = buf.readUInt16LE(pos); pos += 2;
            const end = Math.min(pos + len, buf.length);
            const s = buf.subarray(pos, end).toString('utf8').replace(/\0+$/, '');
            pos = end;
            return s;
        },
        u8() { const v = pos < buf.length ? buf.readUInt8(pos) : 0; pos += 1; return v; },
        u16() { const v = pos + 2 <= buf.length ? buf.readUInt16LE(pos) : 0; pos += 2; return v; },
    };
}

function buildICBMParams() {
    return new OscarBuilder().u16(0x0000).u32(0x0000000B).u16(8000).u16(999).u16(999).u32(0).u16(0).build();
}

function mergeTLVs(session, rawTlvs) {
    for (const key of Object.keys(rawTlvs)) session.userTLVs.set(Number(key), rawTlvs[Number(key)]);
}





const BOS = {
    async handlePacket(session, snac, context) {
        const { family, subtype } = snac;
        try {
            if (family === 0x0001) return await this.handleGeneric(session, snac, context);
            if (family === 0x0002) return await this.handleLocate(session, snac, context);
            if (family === 0x0003) return await this.handleBuddy(session, snac, context);
            if (family === 0x0004) return await this.handleICBM(session, snac, context);
            if (family === 0x0009) return this.handlePrivacy(session, snac);
            if (family === 0x0013) return await this.handleSSI(session, snac, context);
            if (family === 0x0015) return await this.handleICQ(session, snac, context);
        } catch (e) {
            console.error(`\x1b[31m[BOS ERR]\x1b[0m`, e);
        }
    },

    async handleGeneric(session, snac, ctx) {
        const { subtype, reqId } = snac;
        if (subtype === 0x0002) {
            console.log(`\x1b[32m[READY]\x1b[0m ${session.uin}`);
            
            try {
                const me = await db.searchByUIN(session.uin);
                if (me) { session.profile = me.about || ''; session.awayMsg = me.awayMsg || ''; }
            } catch(e) {}

            session.sendSNAC(0x0001, 0x000F, 0, 0, packUserInfoOnline(session));
            const offline = await db.getOffline(session.uin);
            for (const msg of offline) session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
        }
        if (subtype === 0x0006) session.sendSNAC(0x0001, 0x0007, 0, reqId, this.buildRateResponse());
        if (subtype === 0x0008) session.sendSNAC(0x0001, 0x0013, 0, 0, new OscarBuilder().u16(0x0004).tlv(0x000B, 'Welcome!').build());
        if (subtype === 0x000E) {
            const rawTlvs = parseTLVs(snac.data); mergeTLVs(session, rawTlvs);
            if (rawTlvs[0x0006] && rawTlvs[0x0006].length >= 4) session.status = rawTlvs[0x0006].readUInt16BE(2);
            await this.notifyWatchers(session, ctx.sessions, true);
        }
        if (subtype === 0x0011) {
            if (snac.data.length >= 4) {
                const idle = snac.data.readUInt32BE(0);
                if (idle > 0) { const buf = Buffer.alloc(4); buf.writeUInt32BE(idle); session.userTLVs.set(0x0004, buf); } 
                else session.userTLVs.delete(0x0004);
            }
        }
        if (subtype === 0x0017) {
            const b = new OscarBuilder();
            [[0x0001, 0x0004],[0x0002, 0x0001],[0x0003, 0x0001],[0x0004, 0x0001],[0x0009, 0x0001],[0x0013, 0x0005],[0x0015, 0x0001]].forEach(([f, v]) => b.u16(f).u16(v));
            session.sendSNAC(0x0001, 0x0018, 0, reqId, b.build());
        }
        if (subtype === 0x001E) { mergeTLVs(session, parseTLVs(snac.data)); await this.notifyWatchers(session, ctx.sessions, true); }
        if (subtype === 0x0004) session.sendSNAC(0x0001, 0x0001, 0, reqId, new OscarBuilder().u16(0x0005).build());
    },

    buildRateResponse() {
        const b = new OscarBuilder();
        b.u16(1).u16(0x0001).u32(80).u32(2500).u32(2000).u32(1500).u32(1000).u32(2500).u32(6000).u32(0).u8(0);
        const pairs =[];
        const families = {
            0x0001:[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0E,0x0F,0x11,0x13,0x17,0x18,0x1E],
            0x0002:[0x01,0x02,0x03,0x04,0x05,0x06], 0x0003:[0x01,0x02,0x03,0x04,0x05,0x0B,0x0C],
            0x0004:[0x01,0x02,0x04,0x05,0x06,0x07,0x0C], 0x0009:[0x01,0x02,0x03],
            0x0013:[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0E,0x0F,0x11,0x12],
            0x0015:[0x01,0x02,0x03],
        };
        for (const [fam, subs] of Object.entries(families)) for (const sub of subs) pairs.push([parseInt(fam), sub]);
        b.u16(0x0001).u16(pairs.length); pairs.forEach(([f, s]) => b.u16(f).u16(s));
        return b.build();
    },

    async notifyWatchers(session, sessions, online) {
        const targetUin = session.uin;
        for (const [uin, ws] of sessions) {
            if (uin === targetUin || !ws.watching.has(targetUin)) continue;
            ws.sendSNAC(0x0003, online ? 0x000B : 0x000C, 0, 0, online ? packUserInfoOnline(session) : packUserInfoOffline(targetUin));
        }
        const ssiWatchers = await db.all("SELECT DISTINCT uin FROM ssi WHERE name = ? AND type = 0",[targetUin]);
        for (const row of ssiWatchers) {
            const ws = sessions.get(row.uin);
            if (ws && !ws.watching.has(targetUin)) {
                ws.watching.add(targetUin);
                ws.sendSNAC(0x0003, online ? 0x000B : 0x000C, 0, 0, online ? packUserInfoOnline(session) : packUserInfoOffline(targetUin));
            }
        }
    },

    async sendBuddyStatuses(session, sessions) {
        for (const buddyUin of session.watching) {
            const bs = sessions.get(buddyUin);
            if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
        }
    },

    async handleLocate(session, snac, ctx) {
        const { subtype, reqId } = snac;
        if (subtype === 0x0002) session.sendSNAC(0x0002, 0x0003, 0, reqId, new OscarBuilder().tlv(0x0001, 0x0400).tlv(0x0002, 0x0010).tlv(0x0005, 0x000A).build());
        
        if (subtype === 0x0004) {
            const tlvs = parseTLVs(snac.data);
            if (tlvs[0x0002]) { 
                session.profile = tlvs[0x0002].toString('utf8'); 
                try { await db.run("UPDATE users SET about = ? WHERE uin = ?",[session.profile, session.uin]); } catch(e){}
            }
            if (tlvs[0x0004]) { 
                session.awayMsg = tlvs[0x0004].toString('utf8'); 
                try { await db.run("UPDATE users SET awayMsg = ? WHERE uin = ?", [session.awayMsg, session.uin]); } catch(e){}
            }
            if (tlvs[0x0005]) { session.userTLVs.set(0x000D, tlvs[0x0005]); await this.notifyWatchers(session, ctx.sessions, true); }
        }
        
        if (subtype === 0x0005 && snac.data.length >= 3) {
            const flags = snac.data.readUInt16BE(0); const targetUin = snac.data.subarray(3, 3 + snac.data[2]).toString();
            const ts = ctx.sessions.get(targetUin);
            const userDb = await db.searchByUIN(targetUin); 

            const b = new OscarBuilder(); const tb = Buffer.from(targetUin); b.u8(tb.length).raw(tb).u16(0);
            
            const infoPairs =[]; 
            if (ts) {
                for (const[type, value] of ts.userTLVs) infoPairs.push([type, value]);
                infoPairs.push([0x0002, Buffer.from(ts.profile || (userDb ? userDb.about : '') || `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from(ts.awayMsg || '')]);
            } else {
                infoPairs.push([0x0001, Buffer.from([0x00, 0x40])]);
                infoPairs.push([0x0002, Buffer.from(userDb ? (userDb.about || '') : `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from('')]);
            }
            b.u16(infoPairs.length); infoPairs.forEach(([t, v]) => b.tlv(t, v));
            session.sendSNAC(0x0002, 0x0006, 0, reqId, b.build());
        }
    },

    async handleBuddy(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0003, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 1000).tlv(0x0002, 200).tlv(0x0003, 200).build());
        if (snac.subtype === 0x0004 || snac.subtype === 0x0005) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1; if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                if (snac.subtype === 0x0004) { session.watching.add(buddyUin); const bs = ctx.sessions.get(buddyUin); if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs)); }
                else session.watching.delete(buddyUin);
            }
        }
    },

    async handleICBM(session, snac, ctx) {
        if (snac.subtype === 0x0004 || snac.subtype === 0x0002) return session.sendSNAC(0x0004, 0x0005, 0, snac.reqId, buildICBMParams());
        if (snac.subtype === 0x0006) {
            const d = snac.data; if (d.length < 11) return;
            const cookie = d.subarray(0, 8); const channel = d.readUInt16BE(8); const uinLen = d[10];
            const recipient = d.subarray(11, 11 + uinLen).toString('utf8'); const tlvs = parseTLVs(d.subarray(11 + uinLen));
            const target = ctx.sessions.get(recipient);

            if (channel === 2) {
                if (target) {
                    const b = new OscarBuilder().raw(cookie).u16(channel).u8(Buffer.byteLength(session.uin)).string(session.uin)
                             .u16(0).u16(3).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, session.userTLVs.get(0x0006) || Buffer.from([0,0,0,0])).tlv(0x03, session.userTLVs.get(0x0003) || Buffer.alloc(4));
                    if (tlvs[0x05]) b.tlv(0x05, tlvs[0x05]);
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
                return;
            }

            let msgText = '';
            if (channel === 1 && tlvs[0x0002]) {
                const frag = tlvs[0x0002]; let pos = 0;
                while (pos + 4 <= frag.length) {
                    const fId = frag[pos]; const fLen = frag.readUInt16BE(pos + 2); const fData = frag.subarray(pos + 4, pos + 4 + fLen); pos += 4 + fLen;
                    if (fId === 0x01 && fData.length >= 4) { const cs = fData.readUInt16BE(0); const raw = fData.subarray(4); msgText = (cs === 0x0003) ? iconv.decode(raw, 'win1251') : raw.toString('utf8'); }
                }
            } else if (channel === 4 && tlvs[0x0005] && tlvs[0x0005].length >= 8) {
                msgText = tlvs[0x0005].subarray(8, 8 + tlvs[0x0005].readUInt16LE(6)).toString('utf8').replace(/\0/g, '');
            }

            
            
            msgText = db.sanitizeText(msgText, 4096);

            console.log(`\x1b[32m[MSG]\x1b[0m ${session.uin} → ${recipient} : ${msgText}`);

            if (target) {
                let tlv02 = tlvs[0x0002];
                if (channel === 1 && msgText) {
                    const textBuf = Buffer.from(msgText, 'utf8');
                    const msgBody = Buffer.concat([Buffer.alloc(4), textBuf]);
                    const msgHeader = Buffer.alloc(4); msgHeader[0] = 0x01; msgHeader[1] = 0x01; msgHeader.writeUInt16BE(msgBody.length, 2);
                    tlv02 = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]), msgHeader, msgBody]);
                }
                const b = new OscarBuilder().raw(cookie).u16(channel).u8(Buffer.byteLength(session.uin)).string(session.uin)
                         .u16(0).u16(3).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, session.userTLVs.get(0x0006) || Buffer.from([0,0,0,0])).tlv(0x03, session.userTLVs.get(0x0003) || Buffer.alloc(4));
                if (tlv02) b.tlv(0x02, tlv02); if (tlvs[0x0005]) b.tlv(0x0005, tlvs[0x0005]);
                target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                if (tlvs[0x0003]) session.sendSNAC(0x0004, 0x000C, 0, snac.reqId, new OscarBuilder().raw(cookie).u16(channel).u8(Buffer.byteLength(recipient)).string(recipient).build());
            } else if (msgText) {
                await db.storeOffline(session.uin, recipient, msgText);
            }
        }
    },

    buildIncomingMsg(senderUin, text, ts) {
        const cookie = Buffer.alloc(8); cookie.writeUInt32BE(Math.floor(Math.random() * 0xFFFFFFFF), 0); cookie.writeUInt32BE(Math.floor(ts || Date.now() / 1000), 4);
        const msgBody = Buffer.concat([Buffer.alloc(4), Buffer.from(text, 'utf8')]);
        const msgHeader = Buffer.alloc(4); msgHeader[0] = 0x01; msgHeader[1] = 0x01; msgHeader.writeUInt16BE(msgBody.length, 2);
        const signonTime = Buffer.alloc(4); signonTime.writeUInt32BE(Math.floor(Date.now() / 1000));
        return new OscarBuilder().raw(cookie).u16(1).u8(Buffer.byteLength(senderUin)).string(senderUin).u16(0).u16(3).tlv(0x0001, Buffer.from([0x00, 0x40])).tlv(0x0006, Buffer.from([0, 0, 0, 0])).tlv(0x0003, signonTime).tlv(0x0002, Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]), msgHeader, msgBody])).build();
    },

    handlePrivacy(session, snac) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0009, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 200).tlv(0x0002, 200).build());
    },

    async handleSSI(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0013, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0004, 1000).tlv(0x0005, 100).tlv(0x0006, 200).tlv(0x0007, 200).tlv(0x0008, 200).build());
        
        if (snac.subtype === 0x0004 || snac.subtype === 0x0005) {
            const items = await db.getSSI(session.uin);
            if (snac.subtype === 0x0005 && snac.data.length >= 6) {
                const cliTs = snac.data.readUInt32BE(0); const cliCnt = snac.data.readUInt16BE(4);
                if (cliCnt === items.length && cliTs > 0) {
                    session.sendSNAC(0x0013, 0x000F, 0, snac.reqId, new OscarBuilder().u32(Math.floor(Date.now() / 1000)).u16(items.length).build());
                    for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
                    return;
                }
            }
            for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
            const b = new OscarBuilder().u8(0).u16(items.length);
            for (const i of items) { 
                const nb = Buffer.from(i.name || '', 'utf8'); 
                const tlvBuf = i.tlv ? Buffer.from(i.tlv) : Buffer.alloc(0);
                b.u16(nb.length).raw(nb).u16(i.gid).u16(i.iid).u16(i.type).u16(tlvBuf.length); 
                if(tlvBuf.length > 0) b.raw(tlvBuf); 
            }
            b.u32(Math.floor(Date.now() / 1000));
            session.sendSNAC(0x0013, 0x0006, 0, snac.reqId, b.build());
        }
        
        if (snac.subtype === 0x0007) { await this.sendBuddyStatuses(session, ctx.sessions); await this.notifyWatchers(session, ctx.sessions, true); }
        
        if (snac.subtype === 0x0008 || snac.subtype === 0x0009 || snac.subtype === 0x000A) {
            const items = parseSSIItems(snac.data); const results =[];
            
            for (const item of items) {
                const tlvBlob = item.tlvData ? Buffer.from(item.tlvData) : null;
                try {
                    if (snac.subtype === 0x0008) { 
                        await db.run("DELETE FROM ssi WHERE uin = ? AND name = ?",[session.uin, item.name]); 
                        await db.run("INSERT INTO ssi (uin, name, gid, iid, type, tlv) VALUES (?, ?, ?, ?, ?, ?)",[session.uin, item.name, item.gid, item.iid, item.type, tlvBlob]); 
                        if (item.type === 0 && item.name) { session.watching.add(item.name); const bs = ctx.sessions.get(item.name); if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs)); } 
                    }
                    if (snac.subtype === 0x0009) await db.run("UPDATE ssi SET gid = ?, type = ?, tlv = ? WHERE uin = ? AND name = ? AND iid = ?",[item.gid, item.type, tlvBlob, session.uin, item.name, item.iid]);
                    if (snac.subtype === 0x000A) { await db.run("DELETE FROM ssi WHERE uin = ? AND name = ? AND iid = ?",[session.uin, item.name, item.iid]); if (item.type === 0 && item.name) session.watching.delete(item.name); }
                    results.push(0x0000);
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2); results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, snac.reqId, ack);
        }
        if (snac.subtype === 0x0012) { const buddies = await db.getSSIBuddies(session.uin); for (const b of buddies) session.watching.add(b.name); }
    },

    
    
    

    async handleICQ(session, snac, ctx) {
        if (snac.subtype !== 0x0002) return;
        const tlvs = parseTLVs(snac.data);
        const extData = tlvs[0x0001];
        if (!extData || extData.length < 10) return;

        const ownerUin = extData.readUInt32LE(2);
        const cmdType  = extData.readUInt16LE(6);
        const seq      = extData.readUInt16LE(8);
        const subData  = extData.subarray(10);

        if (cmdType === 0x003C) {
            const offline = await db.getOffline(session.uin);
            for (const msg of offline) session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
            this.sendICQDirect(session, snac.reqId, ownerUin, 0x0042, seq, Buffer.alloc(0));
            return;
        }

        if (cmdType === 0x003E) return;

        if (cmdType === 0x07D0 && subData.length >= 2) {
            const subCmd = subData.readUInt16LE(0);
            const metaData = subData.subarray(2);

            
            if (subCmd === META_REQ.HOMEINFO) {
                const user = await db.searchByUIN(session.uin);
                this.sendHomeInfoV7(session, snac.reqId, ownerUin, seq, user);
                return;
            }

            
            if (subCmd === META_REQ.SHORTINFO) {
                let targetUin = session.uin;
                if (metaData.length >= 4) { const v = metaData.readUInt32LE(0); if (v > 0) targetUin = v.toString(); }
                const user = await db.searchByUIN(targetUin);
                this.sendShortInfoV7(session, snac.reqId, ownerUin, seq, user);
                return;
            }

            
            
            
            if (subCmd === META_REQ.FULLINFO) {
                let targetUin = session.uin;
                if (metaData.length >= 4) { const v = metaData.readUInt32LE(0); if (v > 0) targetUin = v.toString(); }
                const user = await db.searchByUIN(targetUin);
                this.sendHomeInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendMoreInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendEmailInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendHpageInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendWorkInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendAboutInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendInterestsInfoV7(session, snac.reqId, ownerUin, seq, user);
                this.sendAffilationsInfoV7(session, snac.reqId, ownerUin, seq, user);
                return;
            }

            
            
            if (subCmd === META_REQ.WP_UIN) {
                let targetUin = session.uin;
                if (metaData.length >= 4) { const v = metaData.readUInt32LE(0); if (v > 0) targetUin = v.toString(); }
                const user = await db.searchByUIN(targetUin);
                this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq, user ? [user] : [], ctx);
                return;
            }

            
            if (subCmd === 0x0C3A || subCmd === 0x0D0E) {
                let pos = 0; const updates = {};
                while(pos + 4 <= metaData.length) {
                    const tType = metaData.readUInt16LE(pos); const tLen = metaData.readUInt16LE(pos+2); pos += 4;
                    if (tLen > 0 && pos + tLen <= metaData.length) {
                        const valBuf = metaData.subarray(pos, pos+tLen);
                        const strVal = valBuf.toString('utf8').replace(/\0/g, '').trim();
                        if (tType === ICQ_FIELD.NICKNAME) updates.nickname = strVal;
                        if (tType === ICQ_FIELD.FIRSTNAME) updates.firstname = strVal;
                        if (tType === ICQ_FIELD.LASTNAME) updates.lastname = strVal;
                        if (tType === ICQ_FIELD.EMAIL) updates.email = strVal;
                        if (tType === ICQ_FIELD.CITY) updates.city = strVal;
                        if (tType === ICQ_FIELD.PHONE) updates.phone = strVal;
                        if (tType === ICQ_FIELD.AGE && tLen >= 2) updates.age = valBuf.readUInt16LE(0);
                        if (tType === ICQ_FIELD.GENDER && tLen >= 1) updates.gender = valBuf.readUInt8(0);
                        if (tType === ICQ_FIELD.HOMEPAGE_URL && tLen > 2) updates.homepage = readSString(valBuf.subarray(2));
                        if (tType === ICQ_FIELD.ABOUT) updates.about = strVal;
                        if (tType === ICQ_FIELD.STATE) updates.state = strVal;
                        if (tType === ICQ_FIELD.COUNTRY) updates.country = strVal;
                        if (tType === ICQ_FIELD.BIRTH_YEAR && tLen >= 2) updates.birth_year = valBuf.readUInt16LE(0);
                        if (tType === ICQ_FIELD.BIRTH_MONTH && tLen >= 1) updates.birth_month = valBuf.readUInt8(0);
                        if (tType === ICQ_FIELD.BIRTH_DAY && tLen >= 1) updates.birth_day = valBuf.readUInt8(0);
                    }
                    pos += tLen;
                }
                await this.applyProfileUpdates(session.uin, updates);
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x0C3F, Buffer.from([META_SUCCESS]));
                return;
            }

            
            
            
            if (subCmd === META_SET_REQ.HOMEINFO) {
                const r = makeSeqReader(metaData);
                const updates = {
                    nickname: r.lnts(), firstname: r.lnts(), lastname: r.lnts(), email: r.lnts(),
                    city: r.lnts(),
                    state: r.lnts(),
                };
                updates.phone = r.lnts();
                r.lnts(); r.lnts(); r.lnts(); r.lnts(); 
                updates.country = r.u16(); 
                
                let ok = true;
                try { await this.applyProfileUpdates(session.uin, updates); } catch (e) { ok = false; }
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, META_SET_ACK.HOMEINFO, Buffer.from([ok ? META_SUCCESS : META_FAIL]));
                return;
            }

            if (subCmd === META_SET_REQ.MOREINFO) {
                const r = makeSeqReader(metaData);
                const updates = { age: r.u16(), gender: r.u8() };
                updates.homepage = r.lnts();
                updates.birth_year = r.u16(); 
                updates.birth_month = r.u8(); 
                updates.birth_day = r.u8();   
                
                let ok = true;
                try { await this.applyProfileUpdates(session.uin, updates); } catch (e) { ok = false; }
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, META_SET_ACK.MOREINFO, Buffer.from([ok ? META_SUCCESS : META_FAIL]));
                return;
            }

            if (subCmd === META_SET_REQ.NOTESINFO) {
                const r = makeSeqReader(metaData);
                const about = r.lnts();
                let ok = true;
                try { await this.applyProfileUpdates(session.uin, { about }); } catch (e) { ok = false; }
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, META_SET_ACK.NOTESINFO, Buffer.from([ok ? META_SUCCESS : META_FAIL]));
                return;
            }

            
            
            
            
            
            if (subCmd === 0x0898) {
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x08A2, Buffer.concat([Buffer.from([META_FAIL]), writeLNTS('')]));
                return;
            }

            
            
            if (subCmd === 0x0569) {
                let results = [];
                if (metaData.length >= 8) {
                    const targetUin = metaData.readUInt32LE(4).toString();
                    console.log(`\x1b[35m[SEARCH]\x1b[0m ${session.uin} ищет по UIN: ${targetUin}`);
                    try { const u = await db.searchByUIN(targetUin); if (u) results.push(u); } catch (e) {}
                }
                this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq, results, ctx);
                return;
            }

            
            
            
            
            if (subCmd === 0x055F) {
                const tlvChain = parseICQMetaTLVs(metaData);
                const criteria = {};
                if (tlvChain[ICQ_FIELD.NICKNAME]) criteria.nickname = readSString(tlvChain[ICQ_FIELD.NICKNAME]);
                if (tlvChain[ICQ_FIELD.FIRSTNAME]) criteria.firstname = readSString(tlvChain[ICQ_FIELD.FIRSTNAME]);
                if (tlvChain[ICQ_FIELD.LASTNAME]) criteria.lastname = readSString(tlvChain[ICQ_FIELD.LASTNAME]);
                if (tlvChain[ICQ_FIELD.EMAIL]) criteria.email = readSString(tlvChain[ICQ_FIELD.EMAIL]);
                if (tlvChain[ICQ_FIELD.CITY]) criteria.city = readSString(tlvChain[ICQ_FIELD.CITY]);
                if (tlvChain[ICQ_FIELD.GENDER] && tlvChain[ICQ_FIELD.GENDER].length >= 1) {
                    criteria.gender = tlvChain[ICQ_FIELD.GENDER].readUInt8(0);
                }
                if (tlvChain[ICQ_FIELD.AGE_RANGE] && tlvChain[ICQ_FIELD.AGE_RANGE].length >= 4) {
                    criteria.ageMin = tlvChain[ICQ_FIELD.AGE_RANGE].readUInt16LE(0);
                    criteria.ageMax = tlvChain[ICQ_FIELD.AGE_RANGE].readUInt16LE(2);
                }
                const keyword = tlvChain[ICQ_FIELD.KEYWORD] ? readSString(tlvChain[ICQ_FIELD.KEYWORD]) : '';
                const onlineOnly = !!(tlvChain[ICQ_FIELD.ONLINE_ONLY] && tlvChain[ICQ_FIELD.ONLINE_ONLY].readUInt8(0) === 1);

                console.log(`\x1b[35m[SEARCH]\x1b[0m ${session.uin} whitepages:`, criteria, keyword ? `keyword="${keyword}"` : '(без keyword)');

                let results = [];
                try {
                    if (Object.keys(criteria).length > 0) results = await db.searchByDetails(criteria);
                    else if (keyword) results = await db.searchByKeyword(keyword);
                } catch (e) { console.error('[SEARCH ERROR]', e); }

                if (onlineOnly && ctx && ctx.sessions) results = results.filter(u => ctx.sessions.has(u.uin));

                this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq, results, ctx);
                return;
            }

            
            
            
            
            if (subCmd === 0x0FA0) {
                let results = [];
                const bodyStart = skipInfiumHeader(metaData);
                if (bodyStart !== null) {
                    const body = metaData.subarray(bodyStart);
                    const parsed = parseInfiumBody(body);

                    if (parsed.kind === 'uins') {
                        console.log(`\x1b[35m[SEARCH]\x1b[0m ${session.uin} infium-запрос по UIN:`, parsed.uins);
                        for (const targetUin of parsed.uins) {
                            try {
                                const u = await db.searchByUIN(targetUin);
                                if (u) results.push(u);
                            } catch (e) { console.error('[INFIUM ERROR]', e); }
                        }
                    } else if (parsed.kind === 'criteria') {
                        console.log(`\x1b[35m[SEARCH]\x1b[0m ${session.uin} infium-поиск по критериям:`, parsed.criteria);
                        try {
                            results = await db.searchByDetails(parsed.criteria);
                        } catch (e) { console.error('[INFIUM SEARCH ERROR]', e); }
                    } else {
                        console.log(`\x1b[33m[SEARCH]\x1b[0m ${session.uin}: infium-запрос не распознан (ни список UIN, ни известные критерии)`);
                    }
                } else {
                    console.log(`\x1b[33m[SEARCH]\x1b[0m ${session.uin}: не удалось разобрать infium-запрос (пакет короче заголовка)`);
                }
                this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq, results, ctx);
                return;
            }
        }
    },

    
    
    
    
    sendQip2005SearchResult(session, reqId, ownerUin, seq, users, ctx) {
        if (!users || users.length === 0) {
            return this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.from([META_EMPTY]));
        }

        users.forEach((user, idx) => {
            const isLast = idx === users.length - 1;
            const online = (ctx && ctx.sessions && ctx.sessions.has(String(user.uin))) ? 1 : 0;

            
            
            
            
            const details = [];
            const uinBuf = Buffer.alloc(4); uinBuf.writeUInt32LE(parseInt(user.uin) || 0); details.push(uinBuf);
            details.push(writeLNTS(user.nickname));
            details.push(writeLNTS(user.firstname));
            details.push(writeLNTS(user.lastname));
            details.push(writeLNTS(user.email));
            details.push(Buffer.from([0x00])); 
            const onlineBuf = Buffer.alloc(2); onlineBuf.writeUInt16LE(online); details.push(onlineBuf);
            details.push(Buffer.from([user.gender ? parseInt(user.gender) : 0]));
            const ageBuf = Buffer.alloc(2); ageBuf.writeUInt16LE(user.age ? parseInt(user.age) : 0); details.push(ageBuf);

            const detailsBuf = Buffer.concat(details);
            const sizeBuf = Buffer.alloc(2); sizeBuf.writeUInt16LE(detailsBuf.length);

            const tail = [];
            if (isLast) { const leftBuf = Buffer.alloc(4); leftBuf.writeUInt32LE(0); tail.push(leftBuf); }
            
            
            
            
            tail.push(Buffer.alloc(isLast ? 8 : 12));

            const payload = Buffer.concat([Buffer.from([META_SUCCESS]), sizeBuf, detailsBuf, Buffer.concat(tail)]);
            this.sendICQMetaReply(session, reqId, ownerUin, seq, isLast ? 0x01AE : 0x01A4, payload);
        });
    },

    
    
    
    async applyProfileUpdates(uin, updates) {
        const limits = { nickname: 64, firstname: 64, lastname: 64, email: 128, city: 128, state: 64, country: 64, phone: 64, homepage: 256, about: 1024, birth_year: 4, birth_month: 2, birth_day: 2 };
        const keys = Object.keys(updates).filter(k => updates[k] !== undefined && updates[k] !== '');
        if (keys.length === 0) return;

        const setStr = keys.map(k => `${k} = ?`).join(', ');
        const values = keys.map(k => {
            const value = updates[k];
            const limit = limits[k] || 255;
            return (typeof value === 'number' || typeof value === 'boolean') ? value : db.sanitizeText(value, limit);
        });
        values.push(uin);

        await db.run(`UPDATE users SET ${setStr} WHERE uin = ?`, values);
        console.log(`\x1b[35m[ПРОФИЛЬ]\x1b[0m ${uin} обновил анкету:`, keys);
    },

    
    
    
    
    
    
    
    

    sendShortInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.SHORT, Buffer.from([META_FAIL]));
        const bufs = [Buffer.from([META_SUCCESS])];
        bufs.push(writeLNTS(user.nickname));
        bufs.push(writeLNTS(user.firstname));
        bufs.push(writeLNTS(user.lastname));
        bufs.push(writeLNTS(user.email));
        bufs.push(Buffer.from([0x00]));                             
        bufs.push(Buffer.from([0x00]));                             
        bufs.push(Buffer.from([user.gender ? parseInt(user.gender) : 0]));
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.SHORT, Buffer.concat(bufs));
    },

    sendHomeInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.HOME, Buffer.from([META_FAIL]));
        const bufs = [Buffer.from([META_SUCCESS])];
        bufs.push(writeLNTS(user.nickname));
        bufs.push(writeLNTS(user.firstname));
        bufs.push(writeLNTS(user.lastname));
        bufs.push(writeLNTS(user.email));
        bufs.push(writeLNTS(user.city));
        bufs.push(writeLNTS(user.state));
        bufs.push(writeLNTS(user.phone));
        bufs.push(writeLNTS('')); bufs.push(writeLNTS('')); bufs.push(writeLNTS('')); 
        bufs.push(writeLNTS('')); 
        bufs.push(Buffer.from([(parseInt(user.country) || 0) & 0xFF, (parseInt(user.country) || 0) >> 8])); 
        bufs.push(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00])); 
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.HOME, Buffer.concat(bufs));
    },

    sendMoreInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.MORE, Buffer.from([META_FAIL]));
        
        
        
        
        
        
        
        
        
        const bufs = [Buffer.from([META_SUCCESS])];
        const ageBuf = Buffer.alloc(2); ageBuf.writeUInt16LE(user.age ? parseInt(user.age) : 0); bufs.push(ageBuf);
        bufs.push(Buffer.from([user.gender ? parseInt(user.gender) : 0]));
        bufs.push(writeLNTS(user.homepage));
        const by = parseInt(user.birth_year) || 0;
        const bm = parseInt(user.birth_month) || 0;
        const bd = parseInt(user.birth_day) || 0;
        bufs.push(Buffer.from([by & 0xFF, by >> 8]));                 
        bufs.push(Buffer.from([bm, bd]));        
        bufs.push(Buffer.from([0x00, 0x00, 0x00]));  
        
        
        bufs.push(Buffer.from([0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]));
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.MORE, Buffer.concat(bufs));
    },

    sendEmailInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.EMAIL, Buffer.from([META_FAIL]));
        
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.EMAIL, Buffer.from([META_SUCCESS, 0x00]));
    },

    sendHpageInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.HPAGE, Buffer.from([META_FAIL]));
        const bufs = [Buffer.from([META_SUCCESS, 0x00])]; 
        bufs.push(Buffer.alloc(2)); 
        bufs.push(writeLNTS(user.homepage));
        bufs.push(Buffer.from([0x00]));
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.HPAGE, Buffer.concat(bufs));
    },

    sendWorkInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.WORK, Buffer.from([META_FAIL]));
        
        const bufs = [Buffer.from([META_SUCCESS])];
        for (let i = 0; i < 6; i++) bufs.push(writeLNTS('')); 
        bufs.push(Buffer.alloc(2)); 
        for (let i = 0; i < 3; i++) bufs.push(writeLNTS('')); 
        bufs.push(Buffer.alloc(2)); 
        bufs.push(writeLNTS('')); 
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.WORK, Buffer.concat(bufs));
    },

    sendAboutInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.ABOUT, Buffer.from([META_FAIL]));
        const bufs = [Buffer.from([META_SUCCESS])];
        bufs.push(writeLNTS(user.about));
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.ABOUT, Buffer.concat(bufs));
    },

    sendInterestsInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.INTERESTS, Buffer.from([META_FAIL]));
        
        
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.INTERESTS, Buffer.from([META_SUCCESS, 0x00]));
    },

    sendAffilationsInfoV7(session, reqId, ownerUin, seq, user) {
        if (!user) return this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.AFFILATIONS, Buffer.from([META_FAIL]));
        
        
        
        
        
        this.sendICQMetaReply(session, reqId, ownerUin, seq, META_RESP.AFFILATIONS,
            Buffer.from([META_SUCCESS, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]));
    },

    sendICQDirect(session, snacReqId, ownerUin, cmdType, seq, payload) {
        const inner = Buffer.alloc(8); inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(cmdType, 4); inner.writeUInt16LE(seq, 6);
        const innerFull = payload.length > 0 ? Buffer.concat([inner, payload]) : inner;
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    },

    sendICQMetaReply(session, snacReqId, ownerUin, seq, subType, payload) {
        const inner = Buffer.alloc(10); inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(0x07DA, 4); inner.writeUInt16LE(seq, 6); inner.writeUInt16LE(subType, 8);
        const innerFull = Buffer.concat([inner, payload]);
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    }
};

module.exports = BOS;