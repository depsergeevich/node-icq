'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const db = require('./database');
const config = require('./config');
const security = require('./security');
const Auth = require('./auth');
const { KeyedRateLimiter } = require('./ratelimit');

let serverRef = null;
let httpServer = null;
let httpsServer = null;

const HTTP_CHALLENGES = new Map();
const HTTP_TOKENS = new Map();
const HTTP_RATE = new KeyedRateLimiter(config.HTTP_RATE);

const CHALLENGE_TTL_MS = 60 * 1000;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function escapeHtml(value) {
    if (value === undefined || value === null) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const CSS = `
    body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    h1, h2 { color: #38bdf8; font-weight: 300; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; color: #94a3b8; font-size: 12px; text-transform: uppercase; padding: 10px; border-bottom: 1px solid #334155; }
    td { padding: 10px; border-bottom: 1px solid #334155; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .online { background: #064e3b; color: #34d399; }
    .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; color: white; display: inline-block; text-decoration: none; font-weight: bold;}
    .btn-danger { background: #ef4444; }
    .btn-primary { background: #3b82f6; }
    .btn-primary:hover { background: #2563eb; }
    input[type=text], input[type=password], textarea { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: white; border-radius: 4px; margin-top: 5px; box-sizing: border-box; }
    .nav { display: flex; gap: 10px; margin-bottom: 20px; }
    .nav a { color: #94a3b8; text-decoration: none; padding: 5px 10px; border-radius: 4px; }
    .nav a.active { background: #334155; color: white; }
    label { color: #94a3b8; font-size: 12px; font-weight: bold; text-transform: uppercase; }
`;

function layout(title, content) {
    return `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"><style>${CSS}</style></head><body>
    <div class="container">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h1>ICQ Server</h1>
            <div>
                <a href="/" class="btn btn-primary" style="margin-right:10px;">Регистрация</a>
                ${config.ADMIN_PANEL_ENABLED ? '<a href="/admin" class="btn btn-danger">Admin Panel</a>' : ''}
            </div>
        </div>
        ${content}
    </div></body></html>`;
}

function publicRegistration() {
    return `
        <div class="card" style="max-width: 400px; margin: 40px auto;">
            <h2 style="text-align: center; margin-top: 0;">Получить UIN</h2>
            <form id="regForm">
                <div style="margin-bottom: 15px;">
                    <label>Никнейм (необязательно)</label>
                    <input type="text" id="regNick" maxlength="64" placeholder="Например: Artem">
                </div>
                <div style="margin-bottom: 20px;">
                    <label>Пароль (минимум ${config.MIN_PASSWORD_LENGTH} символов)</label>
                    <input type="password" id="regPass" required minlength="${config.MIN_PASSWORD_LENGTH}" maxlength="${config.MAX_PASSWORD_LENGTH}" placeholder="Придумайте пароль">
                </div>
                <button type="submit" id="regBtn" class="btn btn-primary" style="width: 100%; font-size: 16px;">Зарегистрироваться</button>
            </form>
            <div id="regResult" style="margin-top: 20px; text-align: center; display: none;"></div>
        </div>
        <script>
            document.getElementById('regForm').addEventListener('submit', async function (e) {
                e.preventDefault();
                const btn = document.getElementById('regBtn');
                const resBox = document.getElementById('regResult');
                btn.disabled = true; btn.innerText = "Секундочку...";
                try {
                    const response = await fetch('/api/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            nickname: document.getElementById('regNick').value,
                            password: document.getElementById('regPass').value
                        })
                    });
                    const data = await response.json();
                    if (data.success) {
                        resBox.style.display = 'block';
                        resBox.innerHTML = '<span style="color:#94a3b8; font-size:14px;">Ваш новый UIN:</span><br>' +
                            '<strong style="font-size:36px; color:#34d399; letter-spacing: 2px;">' + escapeHtml(data.uin) + '</strong>' +
                            '<br><br><span style="color:#e2e8f0; font-size:12px;">Запомните UIN и пароль — они больше не показываются.</span>';
                        document.getElementById('regForm').style.display = 'none';
                    } else {
                        resBox.style.display = 'block';
                        resBox.innerHTML = '<span style="color:#ef4444;">Ошибка: ' + escapeHtml(data.error) + '</span>';
                        btn.disabled = false; btn.innerText = "Зарегистрироваться";
                    }
                } catch (err) {
                    resBox.style.display = 'block';
                    resBox.innerHTML = '<span style="color:#ef4444;">Ошибка соединения с сервером.</span>';
                    btn.disabled = false; btn.innerText = "Зарегистрироваться";
                }
            });

            function escapeHtml(s) {
                return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
                    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
            }
        </script>
    `;
}

async function adminDashboard() {
    const onlineCount = serverRef ? serverRef.sessions.size : 0;
    const [{ c: totalUsers }] = await db.all('SELECT count(*) as c FROM users');

    let sessionRows = '';
    if (serverRef) {
        for (const [uin, session] of serverRef.sessions) {
            sessionRows += `<tr><td><strong>${escapeHtml(uin)}</strong></td>
                <td>${escapeHtml(session.remoteAddress || session.socket.remoteAddress)}</td>
                <td>${escapeHtml(new Date(session.lastActivity).toISOString().replace('T', ' ').slice(0, 19))}</td>
                <td><span class="badge online">ONLINE</span></td>
                <td><form method="POST" action="/admin/kick" style="display:inline">
                    <input type="hidden" name="uin" value="${escapeHtml(uin)}"><button class="btn btn-danger">KICK</button></form></td></tr>`;
        }
    }
    if (!sessionRows) sessionRows = '<tr><td colspan="5" style="text-align:center;color:#64748b;">Нет пользователей в сети</td></tr>';

    return `
        <div class="nav"><a href="/admin" class="active">Dashboard</a><a href="/admin/users">All Users</a></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
            <div class="card" style="text-align:center;"><h2 style="font-size:36px;color:#34d399;margin:0;">${onlineCount}</h2><span style="color:#94a3b8;">Online Users</span></div>
            <div class="card" style="text-align:center;"><h2 style="font-size:36px;color:#38bdf8;margin:0;">${totalUsers}</h2><span style="color:#94a3b8;">Registered Accounts</span></div>
        </div>
        <div class="card"><h2>📢 System Broadcast</h2>
            <form method="POST" action="/admin/broadcast">
            <textarea name="message" rows="3" maxlength="1000" placeholder="Введите сообщение..."></textarea>
            <div style="margin-top:10px;text-align:right;"><button class="btn btn-primary">SEND</button></div></form></div>
        <div class="card"><h2>🟢 Active Sessions</h2>
            <table><thead><tr><th>UIN</th><th>IP</th><th>Активность</th><th>Статус</th><th>Действие</th></tr></thead>
            <tbody>${sessionRows}</tbody></table></div>
    `;
}

async function adminUsers() {
    const users = await db.all(`SELECT uin, nickname, email, lastname FROM users ORDER BY CAST(uin AS INTEGER)`);
    const rows = users.map(u => `<tr><td>${escapeHtml(u.uin)}</td>
        <td>${escapeHtml(u.nickname || '-')}</td>
        <td>${escapeHtml(u.email || '-')}</td>
        <td><form method="POST" action="/admin/delete_user" style="display:inline">
            <input type="hidden" name="uin" value="${escapeHtml(u.uin)}"><button class="btn btn-danger">DEL</button></form></td></tr>`).join('');

    return `<div class="nav"><a href="/admin">Dashboard</a><a href="/admin/users" class="active">All Users</a></div>
        <div class="card"><h2>👥 User Database</h2>
        <table><thead><tr><th>UIN</th><th>Nickname</th><th>Email</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4">Аккаунтов нет</td></tr>'}</tbody></table></div>`;
}

function checkAdminAuth(req) {
    if (!config.ADMIN_PANEL_ENABLED) return false;

    const header = req.headers['authorization'] || '';
    const match = /^Basic\s+(.+)$/i.exec(header.trim());
    if (!match) return false;

    let creds;
    try { creds = Buffer.from(match[1], 'base64').toString('utf8'); } catch { return false; }

    const separator = creds.indexOf(':');
    if (separator < 0) return false;

    const user = creds.slice(0, separator);
    const pass = creds.slice(separator + 1);

    const userOk = security.safeEqual(user, config.ADMIN_USER);
    const passOk = security.safeEqual(pass, config.ADMIN_PASS);
    return userOk && passOk;
}

function requestAuth(res) {
    res.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="ICQ Admin Panel", charset="UTF-8"',
        'Content-Type': 'text/plain; charset=utf-8'
    });
    res.end('Access denied');
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let aborted = false;

        req.on('data', chunk => {
            if (aborted) return;
            size += chunk.length;
            if (size > config.MAX_REQUEST_BODY) {
                aborted = true;
                reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });

        req.on('end', () => {
            if (aborted) return;
            resolve(Buffer.concat(chunks).toString('utf8'));
        });

        req.on('error', reject);
    });
}

function parseXmlFields(raw) {
    const fields = {};
    const tag = /<([A-Za-z0-9_:-]+)>([^<]*)<\/\1>/g;
    let match;
    while ((match = tag.exec(raw)) !== null) {
        fields[match[1]] = match[2].trim();
    }
    return fields;
}

async function parseBody(req) {
    const raw = await readBody(req);
    if (!raw) return {};

    const contentType = req.headers['content-type'] || '';

    if (contentType.includes('application/json')) {
        try { return JSON.parse(raw); } catch (e) { return {}; }
    }

    if (contentType.includes('xml') || raw.trimStart().startsWith('<')) {
        return parseXmlFields(raw);
    }

    const params = {};
    for (const pair of raw.split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        const key = eq < 0 ? pair : pair.slice(0, eq);
        const value = eq < 0 ? '' : pair.slice(eq + 1);
        try {
            params[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(value.replace(/\+/g, ' '));
        } catch {  }
    }
    return params;
}

function sendXml(res, statusCode, xml) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/xml; charset=utf-8',
        'Cache-Control': 'no-store'
    });
    res.end(xml);
}

function sendJson(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
}

function apiError(statusCode, code, text) {
    return `<response xmlns="https://api.login.aol.com"><statuscode>${statusCode}</statuscode><statustext>${escapeHtml(text)}</statustext></response>`;
}

function sweepHttpState() {
    const now = Date.now();
    for (const [key, entry] of HTTP_CHALLENGES) {
        if (entry.expiresAt < now) HTTP_CHALLENGES.delete(key);
    }
    for (const [key, entry] of HTTP_TOKENS) {
        if (entry.expiresAt < now) HTTP_TOKENS.delete(key);
    }
}

async function handleRoutes(req, res, parsedUrl) {
    const rawPath = parsedUrl.pathname || '';
    const path = rawPath.replace(/\/+$/, '');
    const query = parsedUrl.searchParams;
    const method = req.method;

    if (method === 'GET' && (path === '' || path === '/' || path === '/register')) {
        if (!config.REGISTRATION_ENABLED) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end(layout('Регистрация', '<div class="card"><h2>Регистрация отключена</h2><p>Обратитесь к администратору.</p></div>'));
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(layout('Регистрация', publicRegistration()));
    }

    if (path === '/api/register') {
        if (method !== 'POST') return sendJson(res, 405, { success: false, error: 'Method not allowed' });

        if (!config.REGISTRATION_ENABLED) {
            return sendJson(res, 403, { success: false, error: 'Registration is disabled' });
        }

        const data = await parseBody(req);
        const password = typeof data.password === 'string' ? data.password : '';

        if (password.length < config.MIN_PASSWORD_LENGTH) {
            return sendJson(res, 400, { success: false, error: `Password must be at least ${config.MIN_PASSWORD_LENGTH} characters` });
        }
        if (password.length > config.MAX_PASSWORD_LENGTH) {
            return sendJson(res, 400, { success: false, error: `Password must be at most ${config.MAX_PASSWORD_LENGTH} characters` });
        }

        const result = await db.registerUser(password, {
            nickname: data.nickname,
            email: data.email
        });

        if (result.error) {
            return sendJson(res, 409, { success: false, error: result.error });
        }

        console.log(`\x1b[32m[WEB API]\x1b[0m Зарегистрирован новый UIN: ${result.uin}`);
        return sendJson(res, 200, { success: true, uin: result.uin });
    }

    if (path === '/auth/getChallenge') {
        if (method !== 'POST') return sendXml(res, 405, apiError(405, 'Method not allowed'));

        const tid = security.randomId(8);
        const challengeword = security.randomId(8);

        HTTP_CHALLENGES.set(tid, { challenge: challengeword, uin: null, expiresAt: Date.now() + CHALLENGE_TTL_MS });

        return sendXml(res, 200, `<response xmlns="https://api.login.aol.com"><statuscode>200</statuscode><statustext>OK</statustext>` +
            `<data><tid>${tid}</tid><normalize>false</normalize><truncate>true</truncate>` +
            `<realm>AOL Instant Messenger (SM)</realm><challengeword>${challengeword}</challengeword></data></response>`);
    }

    if (path === '/auth/clientLogin') {
        if (method !== 'POST') return sendXml(res, 405, apiError(405, 'Method not allowed'));

        const data = await parseBody(req);
        const uin = String(data.s ?? data.uin ?? '').trim();
        const clientHash = data.pwd ?? data.password;
        const tid = data.tid ? String(data.tid) : null;

        const plain = uin ? await db.getProtocolSecret(uin) : null;

        let success = false;
        let matchedTid = null;

        if (plain !== null && typeof clientHash === 'string' && clientHash.length > 0) {
            const candidates = tid && HTTP_CHALLENGES.has(tid)
                ? [[tid, HTTP_CHALLENGES.get(tid)]]
                : [...HTTP_CHALLENGES.entries()];

            for (const [key, entry] of candidates) {

                if (entry.uin && entry.uin !== uin) continue;

                const expected = crypto.createHmac('sha256', plain).update(entry.challenge).digest('base64');
                if (security.safeEqual(expected, clientHash)) {
                    success = true;
                    matchedTid = key;
                    break;
                }
            }
        }

        if (!success) {
            console.log(`\x1b[31m[HTTP AUTH FAIL]\x1b[0m Неудачный вход UIN: ${uin || '(пусто)'}`);
            return sendXml(res, 401, apiError(401, 'Invalid login'));
        }

        HTTP_CHALLENGES.delete(matchedTid);

        const token = security.randomToken(32).toString('base64');
        HTTP_TOKENS.set(token, { uin, expiresAt: Date.now() + TOKEN_TTL_MS });

        console.log(`\x1b[32m[HTTP AUTH]\x1b[0m Успешный вход: ${uin}`);
        return sendXml(res, 200, `<response xmlns="https://api.login.aol.com"><statuscode>200</statuscode><statustext>OK</statustext>` +
            `<data><token><expiresin>${Math.floor(TOKEN_TTL_MS / 1000)}</expiresin><a>${token}</a></token>` +
            `<sessionsecret>${security.randomId(8)}</sessionsecret>` +
            `<hosttime>${Math.floor(Date.now() / 1000)}</hosttime><loginid>${escapeHtml(uin)}</loginid></data></response>`);
    }

    if (path === '/aim/startOSCARSession') {
        const token = query.get('a') || query.get('token');
        const entry = token ? HTTP_TOKENS.get(token) : null;

        if (!entry || entry.expiresAt < Date.now()) {
            return sendXml(res, 401, `<response xmlns="https://api.oscar.aol.com"><statuscode>401</statuscode><statustext>Unauthorized</statustext></response>`);
        }

        HTTP_TOKENS.delete(token);

        const cookie = Auth.issueCookie(entry.uin, 32);
        const bosHost = `${config.BOS_ADDRESS}:${config.BOS_PORT}`;

        return sendXml(res, 200, `<response xmlns="https://api.oscar.aol.com"><statuscode>200</statuscode><statustext>OK</statustext>` +
            `<data><host>${escapeHtml(bosHost)}</host><cookie>${cookie.toString('base64')}</cookie></data></response>`);
    }

    if (path === '/admin' || path.startsWith('/admin/')) {
        if (!checkAdminAuth(req)) return requestAuth(res);

        if (method === 'GET') {
            const content = path === '/admin/users' ? await adminUsers() : await adminDashboard();
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
            return res.end(layout('Admin Panel', content));
        }

        if (method === 'POST') {
            const data = await parseBody(req);

            if (path === '/admin/kick') {
                const uin = String(data.uin || '');
                const session = serverRef && serverRef.sessions.get(uin);
                if (session) {
                    session.destroy();                       // 'close' уберёт UIN из sessions
                    serverRef.sessions.delete(uin);
                    console.log(`\x1b[33m[ADMIN]\x1b[0m ${uin} отключён администратором`);
                }
            }

            if (path === '/admin/broadcast' && serverRef && data.message) {
                const text = db.sanitizeText(data.message, 1000);
                const sent = serverRef.broadcast(text);
                console.log(`\x1b[33m[ADMIN]\x1b[0m Рассылка (${sent} получателей): ${text}`);
            }

            if (path === '/admin/delete_user') {
                const uin = String(data.uin || '');
                if (!/^\d+$/.test(uin)) {
                    return sendJson(res, 400, { success: false, error: 'Invalid UIN' });
                }
                const session = serverRef && serverRef.sessions.get(uin);
                if (session) { session.destroy(); serverRef.sessions.delete(uin); }
                await db.deleteUser(uin);
                console.log(`\x1b[33m[ADMIN]\x1b[0m Аккаунт ${uin} удалён`);
            }

            res.writeHead(302, { Location: '/admin' });
            return res.end();
        }

        res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Method not allowed');
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
}

async function startWeb(mainServer) {
    serverRef = mainServer;

    const requestHandler = async (req, res) => {
        let parsedUrl;
        try {

            parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
            return res.end('Bad request');
        }

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");

        if (config.CORS_ALLOW_ORIGIN) {
            res.setHeader('Access-Control-Allow-Origin', config.CORS_ALLOW_ORIGIN);
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        }

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            return res.end();
        }

        const ip = req.socket.remoteAddress || 'unknown';
        if (!HTTP_RATE.allow(ip)) {
            console.log(`\x1b[33m[WEB]\x1b[0m Превышен лимит запросов от ${ip}`);
            res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8' });
            return res.end('Too many requests');
        }

        try {
            await handleRoutes(req, res, parsedUrl);
        } catch (e) {
            const statusCode = e.statusCode || 500;
            console.error(`\x1b[31m[WEB]\x1b[0m ${req.method} ${parsedUrl.pathname}:`, e.message);
            if (!res.headersSent) {
                res.writeHead(statusCode, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end(statusCode === 413 ? 'Payload too large' : 'Internal error');
            }
        }
    };

    httpServer = http.createServer(requestHandler);
    httpServer.on('error', err => {
        console.error(`\x1b[31m[WEB]\x1b[0m HTTP-сервер: ${err.code || err.message}`);
        if (err.code === 'EACCES' || err.code === 'EADDRINUSE') process.exitCode = 1;
    });

    await new Promise((resolve, reject) => {
        httpServer.once('error', reject);
        httpServer.listen(config.WEB_PORT, config.WEB_HOST, resolve);
    }).catch(err => {
        console.error(`\x1b[31m[WEB]\x1b[0m HTTP не поднялся на ${config.WEB_HOST}:${config.WEB_PORT} — ${err.code || err.message}`);
        process.exitCode = 1;
    });

    console.log(`\x1b[1mWEB\x1b[0m HTTP слушает ${config.WEB_HOST}:${config.WEB_PORT}`);

    if (config.HTTPS_ENABLED) {
        const certPath = path.isAbsolute(config.CERT_FILE) ? config.CERT_FILE : path.join(__dirname, config.CERT_FILE);
        const keyPath = path.isAbsolute(config.KEY_FILE) ? config.KEY_FILE : path.join(__dirname, config.KEY_FILE);

        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            try {
                httpsServer = https.createServer({
                    key: fs.readFileSync(keyPath),
                    cert: fs.readFileSync(certPath)
                }, requestHandler);

                httpsServer.on('error', err => {
                    if (err.code === 'EACCES') {
                        console.log(`\x1b[33m[WEB]\x1b[0m Нет прав на порт ${config.HTTPS_PORT} (нужны права администратора) — HTTPS отключён`);
                    } else {
                        console.error(`\x1b[31m[WEB]\x1b[0m HTTPS-сервер: ${err.code || err.message}`);
                    }
                });

                await new Promise(resolve => {
                    httpsServer.listen(config.HTTPS_PORT, config.WEB_HOST, resolve);
                    httpsServer.once('error', resolve); // не роняем весь процесс
                });

                console.log(`\x1b[1mWEB\x1b[0m HTTPS слушает ${config.WEB_HOST}:${config.HTTPS_PORT}`);
            } catch (e) {
                console.log(`\x1b[33m[WEB]\x1b[0m HTTPS не запущен: ${e.message}`);
            }
        } else {
            console.log(`\x1b[33m[WEB]\x1b[0m Не найдены ${certPath} и/или ${keyPath} — HTTPS отключён.`);
        }
    }

    sweepTimer.unref();
}

const sweepTimer = setInterval(sweepHttpState, 30000);

async function stopWeb() {
    sweepTimer.clear();
    for (const server of [httpServer, httpsServer]) {
        if (!server) continue;
        await new Promise(resolve => server.close(resolve));
    }
    httpServer = null;
    httpsServer = null;
}

module.exports = { startWeb, stopWeb, escapeHtml };