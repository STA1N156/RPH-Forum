const express = require('express');
const path = require('path');
const { performance } = require('perf_hooks');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const zlib = require('zlib');
let sharp = null;
try {
    sharp = require('sharp');
} catch (err) {
    console.warn('[Server] sharp unavailable, image compression disabled:', err.message);
}
const { db, DB_PATH, initDatabase, cleanupLoginAttempts, cleanupOldLogs } = require('./database');
const { SqliteReadPool } = require('./sqlite-read-pool');

const app = express();
let sqliteReadPool = null;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT) || 9191;
const HOST = process.env.HOST || '0.0.0.0';
const SERVER_DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const TRUST_PROXY_SETTING = process.env.TRUST_PROXY === 'false'
    ? false
    : (process.env.TRUST_PROXY === 'true' || !process.env.TRUST_PROXY ? true : process.env.TRUST_PROXY);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (IS_PRODUCTION ? '' : '123456');
const EXPLICIT_JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const DERIVED_JWT_SECRET = process.env.ADMIN_PASSWORD
    ? crypto.createHash('sha256').update(`rp-forum:${process.env.ADMIN_PASSWORD}`).digest('hex')
    : '';
const JWT_SECRET = EXPLICIT_JWT_SECRET || DERIVED_JWT_SECRET || (IS_PRODUCTION ? '' : crypto.randomBytes(32).toString('hex'));
const RESEND_API_KEY = (process.env.RESEND_API_KEY || '').trim();
const RESEND_FROM = (process.env.RESEND_FROM || process.env.EMAIL_FROM || '').trim();
const RESEND_EMAIL_ENDPOINT = 'https://api.resend.com/emails';
const TURNSTILE_SITE_KEY = (process.env.TURNSTILE_SITE_KEY || '').trim();
const TURNSTILE_SECRET_KEY = (process.env.TURNSTILE_SECRET_KEY || '').trim();
const TURNSTILE_VERIFY_ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const ADMIN_NOTIFICATION_EMAILS = (process.env.ADMIN_NOTIFICATION_EMAILS || process.env.ADMIN_EMAILS || '').trim();
const NEWAPI_BASE_URL = (process.env.NEWAPI_BASE_URL || '').trim();
const NEWAPI_ADMIN_TOKEN = (process.env.NEWAPI_ADMIN_TOKEN || process.env.NEWAPI_ACCESS_TOKEN || '').trim();
const NEWAPI_ADMIN_USER_ID = (process.env.NEWAPI_ADMIN_USER_ID || process.env.NEWAPI_USER_ID || '').trim();
const AI_REVIEW_DEFAULT_BASE_URL = 'https://cdn.sta1n.cn/v1';
const AI_REVIEW_DEFAULT_VISION_MODEL = '[AN]gemini-3.5-flash-thinking';
const AI_REVIEW_API_KEY = (process.env.AI_REVIEW_API_KEY || '').trim();
const AI_REVIEW_MODEL = (process.env.AI_REVIEW_MODEL || '').trim();
const AI_REVIEW_VISION_MODEL = (process.env.AI_REVIEW_VISION_MODEL || '').trim();
const AI_REVIEW_TIMEOUT_MS = Math.max(5000, parseInt(process.env.AI_REVIEW_TIMEOUT_MS || '30000', 10) || 30000);
const AI_REVIEW_MAX_TEXT_LENGTH = 36000;
const AI_REVIEW_LEGACY_DEFAULT_PROMPT = [
    '你是角色卡的宽松内容审核器，只审核角色卡名称、简介和开场白。',
    '只有在内容明确包含以下任一情况时才拒绝：',
    '1. 明确的政治敏感内容；',
    '2. 以虐杀、肢解、酷刑等为核心且描写非常露骨的极端暴力内容。',
    '普通战斗、犯罪、战争背景、轻微血腥、虚构冲突、黑暗题材均应放行。',
    '如果语境不足、疑似、影射、不确定或无法确认，一律放行。'
].join('\n');
const AI_REVIEW_PREVIOUS_DEFAULT_PROMPT = [
    '你是角色卡的内容审核器，负责审核角色卡名称、简介、描述、开场白、前 3 条世界书和封面。',
    '在内容明确包含以下任一情况时拒绝：',
    '1. 明确的政治敏感内容，尤其有关中国政治的任何内容必须拒绝；',
    '2. 含有重口、虐杀、肢解、犯罪、暴力、酷刑等的内容；',
    '3. 以逝世的公众人物取乐；',
    '4. 封面图片露点或清晰出现性器官。',
    '普通战斗、战争背景、轻微血腥、色情文本均应放行；但封面图片露点或出现性器官仍须拒绝。',
    '如果语境不足、疑似、不确定或无法确认，一律放行。'
].join('\n');
const AI_REVIEW_DEFAULT_TEXT_PROMPT = [
    '你是角色卡的内容审核器，负责审核角色卡名称、简介、描述、开场白和前 3 条世界书。',
    '在内容明确包含以下任一情况时拒绝：',
    '1. 明确的政治敏感内容，尤其有关中国政治的任何内容必须拒绝；',
    '2. 含有重口、虐杀、肢解、犯罪、暴力、酷刑等的内容；',
    '3. 以逝世的公众人物取乐。',
    '普通战斗、战争背景、轻微血腥、色情均应放行。',
    '如果语境不足、疑似、不确定或无法确认，一律放行。'
].join('\n');
const AI_REVIEW_DEFAULT_COVER_PROMPT = [
    '你是角色卡的封面审核器，只审核收到的封面图片。',
    '在封面明确包含以下任一情况时拒绝：',
    '1. 出现政治人物，或可辨认的政治人物变体、戏仿、换装及 AI 改造形象，尤其是中国政治人物；',
    '2. 以任何公众人物取乐；',
    '3. 露点或清晰出现性器官。',
    '如果人物身份、画面内容或语境不足，疑似、不确定或无法确认，一律放行。'
].join('\n');
const EMAIL_CODE_TTL_MINUTES = Math.max(1, parseInt(process.env.EMAIL_CODE_TTL_MINUTES || '10', 10));
const EMAIL_CODE_MAX_ATTEMPTS = 5;
const EMAIL_CODE_COOLDOWN_SECONDS = Math.max(1, parseInt(process.env.EMAIL_CODE_COOLDOWN_SECONDS || '30', 10));
const EMAIL_CODE_IP_WINDOW_MS = 60 * 1000;
const EMAIL_CODE_IP_MAX_PER_WINDOW = 3;
const EMAIL_SEND_TIMEOUT_MS = Math.max(5000, parseInt(process.env.EMAIL_SEND_TIMEOUT_MS || '15000', 10) || 15000);
const EMAIL_SEND_RETRIES = Math.max(0, parseInt(process.env.EMAIL_SEND_RETRIES || '1', 10) || 1);
const HEAT_EMAIL_STEP = 500;
const NEWAPI_HEAT_PER_COOKIE = Math.max(1, parseInt(process.env.NEWAPI_HEAT_PER_COOKIE || '6', 10));
const NEWAPI_QUOTA_PER_COOKIE = Math.max(1, parseInt(process.env.NEWAPI_QUOTA_PER_COOKIE || '50000', 10));
const VIEW_HEAT_WEIGHT = 1.0;
const COMMENT_HEAT_WEIGHT = 2;
const DOWNLOAD_HEAT_WEIGHT = 2.5;
const REGISTRATION_DOWNLOAD_CREDITS = 2;
const COMMENT_REWARD_CREDITS = 2;
const DAILY_CREDIT_COMMENT_LIMIT = 3;
const COMMENT_RATE_WINDOW_MS = 60 * 1000;
const COMMENT_RATE_MAX_PER_WINDOW = 3;
const VIEW_HEAT_ACCOUNT_WINDOW_HOURS = Math.max(1, parseInt(process.env.VIEW_HEAT_ACCOUNT_WINDOW_HOURS || '24', 10) || 24);
const VIEW_HEAT_ACCOUNT_MAX_PER_ITEM = Math.max(1, parseInt(process.env.VIEW_HEAT_ACCOUNT_MAX_PER_ITEM || '1', 10) || 1);
const NEWAPI_USER_STATUS_ENABLED = 1;
const DEFAULT_COMMENT_EMAIL_BLOCK_WORDS = ['已严肃', '严肃', '12345'];
const PERF_LOG_ALL_API = process.env.PERF_LOG_ALL_API !== 'false';
const PERF_SLOW_REQUEST_MS = Math.max(50, parseInt(process.env.PERF_SLOW_REQUEST_MS || '300', 10) || 300);
const DB_HEALTH_QUICK_CHECK = process.env.DB_HEALTH_QUICK_CHECK === 'true';
const CARD_UI_SUMMARY_BACKFILL = process.env.CARD_UI_SUMMARY_BACKFILL !== 'false';
const CARD_DETAIL_PREVIEW_BACKFILL = process.env.CARD_DETAIL_PREVIEW_BACKFILL !== 'false';
const CARD_DATA_AVATAR_CLEANUP = process.env.CARD_DATA_AVATAR_CLEANUP !== 'false';

if (!JWT_SECRET) {
    throw new Error('[FATAL] JWT_SECRET must be set in production');
}

if (IS_PRODUCTION && !EXPLICIT_JWT_SECRET) {
    console.warn('[Security] JWT_SECRET is not set. Falling back to a derived secret from ADMIN_PASSWORD. Set JWT_SECRET explicitly for independent secret rotation.');
}

app.set('trust proxy', TRUST_PROXY_SETTING);

// ============== Brute Force Config ==============
const LOGIN_WINDOW_MINUTES = 1;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 1;
const USER_LOGIN_RATE_WINDOW_MS = Math.max(10 * 1000, parseInt(process.env.USER_LOGIN_RATE_WINDOW_MS || String(60 * 1000), 10) || 60 * 1000);
const USER_LOGIN_RATE_MAX_PER_IP = Math.max(3, parseInt(process.env.USER_LOGIN_RATE_MAX_PER_IP || '20', 10) || 20);
const USER_LOGIN_RATE_MAX_PER_NAME = Math.max(3, parseInt(process.env.USER_LOGIN_RATE_MAX_PER_NAME || '6', 10) || 6);
const userLoginRateMap = new Map();

// ============== Admin Export Downloads ==============
const adminExportDownloads = new Map(); // token -> prepared backup download
const ADMIN_EXPORT_DOWNLOAD_TTL_MS = 5 * 60 * 1000;
const ADMIN_AUTH_COOKIE = 'rph_admin_token';
const ADMIN_AUTH_COOKIE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// ============== Upload Rate Limiting ==============
const MAX_UPLOAD_SIZE_BYTES = 30 * 1024 * 1024; // 30 MB
const MAX_UI_TEMPLATE_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2 MB text template
const UPLOAD_RATE_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_UPLOADS_PER_WINDOW = 2;
const uploadRateMap = new Map(); // key (userId or ip) -> [timestamp, ...]

function checkUploadRate(key) {
    const now = Date.now();
    let timestamps = uploadRateMap.get(key) || [];
    timestamps = timestamps.filter(t => now - t < UPLOAD_RATE_WINDOW_MS);
    uploadRateMap.set(key, timestamps);
    if (timestamps.length >= MAX_UPLOADS_PER_WINDOW) {
        return false;
    }
    return true;
}

function recordUpload(key) {
    const now = Date.now();
    let timestamps = uploadRateMap.get(key) || [];
    timestamps = timestamps.filter(t => now - t < UPLOAD_RATE_WINDOW_MS);
    timestamps.push(now);
    uploadRateMap.set(key, timestamps);
}

// Periodic cleanup of stale upload rate entries
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of uploadRateMap) {
        const active = timestamps.filter(t => now - t < UPLOAD_RATE_WINDOW_MS);
        if (active.length === 0) uploadRateMap.delete(key);
        else uploadRateMap.set(key, active);
    }
}, 5 * 60 * 1000);

function cleanupAdminExportDownload(token) {
    const record = adminExportDownloads.get(token);
    if (!record) return;
    adminExportDownloads.delete(token);
    if (record.path) {
        fs.unlink(record.path, (err) => {
            if (err && err.code !== 'ENOENT') {
                console.warn('[Backup] temp cleanup failed:', err.message);
            }
        });
    }
}

setInterval(() => {
    const now = Date.now();
    for (const [token, record] of adminExportDownloads) {
        if (!record || record.expiresAt <= now) cleanupAdminExportDownload(token);
    }
}, 60 * 1000);

// ============== Middleware ==============
app.use(helmet({
    contentSecurityPolicy: false, // Allow CDN scripts in frontend
    crossOriginEmbedderPolicy: false,
    frameguard: false // Allow embedding in iframe from other sites
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use('/api', (req, res, next) => {
    if (!req.cookies?.[ADMIN_AUTH_COOKIE] || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    const expectedOrigin = `${req.protocol}://${req.get('host')}`;
    if (String(req.get('origin') || '') !== expectedOrigin) {
        return res.status(403).json({ error: '请求来源无效' });
    }
    next();
});

function formatDuration(ms) {
    return `${Number(ms || 0).toFixed(1)}ms`;
}

function formatPerfExtra(extra) {
    if (!extra || typeof extra !== 'object') return '';
    const safe = {};
    Object.entries(extra).forEach(([key, value]) => {
        if (value === undefined) return;
        if (typeof value === 'string' && value.length > 120) safe[key] = `${value.slice(0, 120)}...`;
        else safe[key] = value;
    });
    try {
        return ` ${JSON.stringify(safe)}`;
    } catch {
        return '';
    }
}

function markPerf(req, step, extra) {
    if (!req.perf) return;
    const now = performance.now();
    req.perf.marks.push({
        step,
        total: now - req.perf.start,
        delta: now - req.perf.last,
        extra
    });
    req.perf.last = now;
}

app.use((req, res, next) => {
    const start = performance.now();
    req.perf = { start, last: start, marks: [] };
    req.markPerf = (step, extra) => markPerf(req, step, extra);

    res.on('finish', () => {
        const total = performance.now() - start;
        const pathName = req.path || '';
        const shouldLog = res.statusCode >= 500
            || total >= PERF_SLOW_REQUEST_MS
            || (PERF_LOG_ALL_API && pathName.startsWith('/api/'));
        if (!shouldLog) return;

        const viewer = req.admin
            ? `admin:${req.admin.id}`
            : (req.user ? `user:${req.user.id}` : 'guest');
        const renderedMarks = req.perf.marks.map((mark) => `${mark.step}+${formatDuration(mark.delta)}@${formatDuration(mark.total)}${formatPerfExtra(mark.extra)}`);
        const responseFinishGap = total - req.perf.last;
        if (responseFinishGap >= 50) {
            renderedMarks.push(`response-finish+${formatDuration(responseFinishGap)}@${formatDuration(total)}`);
        }
        const marks = renderedMarks.length ? ` marks=${renderedMarks.join(' | ')}` : '';
        console.info(`[Perf] ${req.method} ${req.originalUrl} status=${res.statusCode} total=${formatDuration(total)} viewer=${viewer} ip=${req.realIp || '-'}${marks}`);
    });
    next();
});

// ============== Real IP & Ban Helpers ==============
function normalizeIp(value) {
    if (!value) return '';
    let ip = String(value).split(',')[0].trim();
    if (!ip) return '';
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    if (ip.startsWith('[')) {
        const end = ip.indexOf(']');
        if (end > 0) ip = ip.slice(1, end);
    }
    const ipv4WithPort = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
    if (ipv4WithPort) ip = ipv4WithPort[1];
    return net.isIP(ip) ? ip : '';
}

function getRequestIp(req) {
    return normalizeIp(req.realIp)
        || normalizeIp(req.headers['cf-connecting-ip'])
        || normalizeIp(req.headers['true-client-ip'])
        || normalizeIp(req.headers['x-real-ip'])
        || normalizeIp(req.headers['x-forwarded-for'])
        || normalizeIp(req.ip)
        || normalizeIp(req.socket?.remoteAddress)
        || 'unknown';
}

function ipv4ToInt(ip) {
    const parts = ip.split('.').map(part => Number(part));
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return parts.reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
}

function ipMatchesPattern(ip, pattern) {
    const normalizedIp = normalizeIp(ip);
    const normalizedPattern = String(pattern || '').trim();
    if (!normalizedIp || !normalizedPattern) return false;
    if (!normalizedPattern.includes('/')) return normalizedIp === normalizeIp(normalizedPattern);

    const [base, bitsRaw] = normalizedPattern.split('/');
    const bits = Number(bitsRaw);
    const baseIp = normalizeIp(base);
    if (net.isIP(normalizedIp) !== 4 || net.isIP(baseIp) !== 4 || !Number.isInteger(bits) || bits < 0 || bits > 32) {
        return false;
    }
    const ipInt = ipv4ToInt(normalizedIp);
    const baseInt = ipv4ToInt(baseIp);
    if (ipInt === null || baseInt === null) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
}

function findActiveIpBan(ip) {
    try {
        const bans = db.prepare(
            `SELECT * FROM ip_bans
             WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
             ORDER BY created_at DESC`
        ).all();
        return bans.find(ban => ipMatchesPattern(ip, ban.ip_pattern)) || null;
    } catch (err) {
        console.error('IP ban check error:', err);
        return null;
    }
}

app.use((req, res, next) => {
    req.realIp = getRequestIp(req);
    const ban = findActiveIpBan(req.realIp);
    markPerf(req, 'ip-ban-check', { banned: Boolean(ban) });
    if (ban) {
        return res.status(403).json({ error: '当前 IP 已被封禁', reason: ban.reason || '' });
    }
    next();
});

const htmlAssetCache = new Map();
const publicAssetCache = new Map();
const CACHED_PUBLIC_ASSETS = new Set(['app.css', 'vue.global.js', 'marked.min.js', 'purify.min.js']);

function getCachedHtmlAsset(fileName) {
    const filePath = path.join(PUBLIC_DIR, fileName);
    const stat = fs.statSync(filePath);
    const cached = htmlAssetCache.get(fileName);
    if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) return cached;

    const body = fs.readFileSync(filePath);
    const gzip = zlib.gzipSync(body, { level: 6 });
    const etag = `"html-${crypto.createHash('sha1').update(body).digest('hex').slice(0, 16)}"`;
    const nextCache = {
        body,
        gzip,
        etag,
        lastModified: stat.mtime.toUTCString(),
        size: stat.size,
        mtimeMs: stat.mtimeMs
    };
    htmlAssetCache.set(fileName, nextCache);
    return nextCache;
}

function sendCachedHtml(req, res, fileName) {
    try {
        const asset = getCachedHtmlAsset(fileName);
        res.set('Content-Type', 'text/html; charset=utf-8');
        res.set('Cache-Control', 'no-cache, max-age=0, must-revalidate');
        res.set('ETag', asset.etag);
        res.set('Last-Modified', asset.lastModified);
        res.set('Vary', 'Accept-Encoding');
        markPerf(req, 'html-cache-ready', { fileName, bytes: asset.body.length, gzipBytes: asset.gzip.length });

        if (String(req.headers['if-none-match'] || '').split(',').map(value => value.trim()).includes(asset.etag)) {
            markPerf(req, 'html-cache-not-modified');
            return res.status(304).end();
        }

        const acceptsGzip = /\bgzip\b/i.test(String(req.headers['accept-encoding'] || ''));
        if (acceptsGzip) {
            res.set('Content-Encoding', 'gzip');
            res.set('Content-Length', asset.gzip.length);
            return res.end(asset.gzip);
        }
        res.set('Content-Length', asset.body.length);
        return res.end(asset.body);
    } catch (err) {
        console.error('Send cached HTML error:', err);
        return res.status(500).send('Failed to load page');
    }
}

function getCachedPublicAsset(fileName) {
    if (!CACHED_PUBLIC_ASSETS.has(fileName)) return null;
    const filePath = path.join(PUBLIC_DIR, fileName);
    const stat = fs.statSync(filePath);
    const cached = publicAssetCache.get(fileName);
    if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) return cached;

    const body = fs.readFileSync(filePath);
    const gzip = zlib.gzipSync(body, { level: 6 });
    const etag = `"asset-${crypto.createHash('sha1').update(body).digest('hex').slice(0, 16)}"`;
    const nextCache = {
        body,
        gzip,
        etag,
        lastModified: stat.mtime.toUTCString(),
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        contentType: fileName.endsWith('.css') ? 'text/css; charset=utf-8' : 'application/javascript; charset=utf-8'
    };
    publicAssetCache.set(fileName, nextCache);
    return nextCache;
}

function sendCachedPublicAsset(req, res, fileName) {
    try {
        const asset = getCachedPublicAsset(fileName);
        if (!asset) return res.status(404).end();
        res.set('Content-Type', asset.contentType);
        res.set('Cache-Control', 'public, max-age=604800');
        res.set('ETag', asset.etag);
        res.set('Last-Modified', asset.lastModified);
        res.set('Vary', 'Accept-Encoding');
        markPerf(req, 'public-asset-cache-ready', { fileName, bytes: asset.body.length, gzipBytes: asset.gzip.length });

        if (String(req.headers['if-none-match'] || '').split(',').map(value => value.trim()).includes(asset.etag)) {
            markPerf(req, 'public-asset-cache-not-modified');
            return res.status(304).end();
        }

        const acceptsGzip = /\bgzip\b/i.test(String(req.headers['accept-encoding'] || ''));
        if (acceptsGzip) {
            res.set('Content-Encoding', 'gzip');
            res.set('Content-Length', asset.gzip.length);
            return res.end(asset.gzip);
        }
        res.set('Content-Length', asset.body.length);
        return res.end(asset.body);
    } catch (err) {
        console.error('Send cached public asset error:', err);
        return res.status(500).end();
    }
}

// Serve static files (no cache for HTML, allow cache for assets).
// Skip this middleware for API requests so they do not wait on filesystem stats
// when image generation/cache writes are busy.
app.get('/', (req, res) => sendCachedHtml(req, res, 'index.html'));
app.get('/index.html', (req, res) => sendCachedHtml(req, res, 'index.html'));
app.get('/admin', (req, res) => sendCachedHtml(req, res, 'admin.html'));
CACHED_PUBLIC_ASSETS.forEach(fileName => {
    app.get(`/${fileName}`, (req, res) => sendCachedPublicAsset(req, res, fileName));
});

const publicStaticMiddleware = express.static(PUBLIC_DIR, {
    index: false,
    etag: true,
    maxAge: '7d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html') || filePath.endsWith('.css')) {
            res.set('Cache-Control', 'no-cache, max-age=0, must-revalidate');
        } else {
            res.set('Cache-Control', 'public, max-age=604800');
        }
    }
});
app.use((req, res, next) => {
    if (req.path.startsWith('/api/') || req.path === '/health') return next();
    return publicStaticMiddleware(req, res, next);
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============== Auth Helpers ==============
function generateAdminToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: 'admin', token_version: user.token_version || 0 },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

function generateUserToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: 'user', token_version: user.token_version || 0 },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function getBearerToken(req) {
    const authHeader = String(req.headers.authorization || '');
    return authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
}

function getAdminAuthToken(req) {
    return String(req.cookies?.[ADMIN_AUTH_COOKIE] || '').trim();
}

function getRequestAuthToken(req) {
    return getBearerToken(req) || String(req.cookies?.[ADMIN_AUTH_COOKIE] || '').trim();
}

function isAdminCookieToken(req, token) {
    const cookieToken = getAdminAuthToken(req);
    return Boolean(cookieToken && token === cookieToken);
}

function setAdminAuthCookie(res, token) {
    res.cookie(ADMIN_AUTH_COOKIE, token, {
        httpOnly: true,
        sameSite: 'strict',
        secure: IS_PRODUCTION,
        maxAge: ADMIN_AUTH_COOKIE_MAX_AGE_MS,
        path: '/'
    });
}

function clearAdminAuthCookie(res) {
    res.clearCookie(ADMIN_AUTH_COOKIE, {
        httpOnly: true,
        sameSite: 'strict',
        secure: IS_PRODUCTION,
        path: '/'
    });
}

function validateAdminPassword(password) {
    const input = String(password || '');
    if (!ADMIN_PASSWORD || !input) return false;
    const inputBuffer = Buffer.from(input);
    const expectedBuffer = Buffer.from(ADMIN_PASSWORD);
    return inputBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(inputBuffer, expectedBuffer);
}

function validateAdminTokenPayload(decoded) {
    if (!decoded || decoded.role !== 'admin') return null;
    const admin = db.prepare('SELECT id, username, token_version FROM admin_users WHERE id = ?').get(decoded.id);
    if (!admin || admin.username !== decoded.username || Number(admin.token_version || 0) !== Number(decoded.token_version || 0)) {
        return null;
    }
    return { id: admin.id, username: admin.username, role: 'admin', token_version: admin.token_version || 0 };
}

function validateUserTokenPayload(decoded) {
    if (!decoded || decoded.role !== 'user') return null;
    const user = db.prepare('SELECT id, username, email, email_verified, download_credits, token_version, is_moderator, is_banned, ban_reason, comment_email_notifications FROM users WHERE id = ?').get(decoded.id);
    if (!user || user.username !== decoded.username || Number(user.token_version || 0) !== Number(decoded.token_version || 0)) {
        return null;
    }
    if (user.is_banned) {
        const err = new Error(user.ban_reason ? `账号已被封禁：${user.ban_reason}` : '账号已被封禁');
        err.code = 'USER_BANNED';
        throw err;
    }
    return {
        id: user.id,
        username: user.username,
        email: user.email || '',
        email_verified: Number(user.email_verified || 0),
        is_moderator: Number(user.is_moderator || 0),
        comment_email_notifications: Number(user.comment_email_notifications || 0),
        role: 'user',
        token_version: user.token_version || 0
    };
}

function isModeratorUser(user) {
    return Number(user?.is_moderator || 0) === 1;
}

function isPublicCardStatus(status) {
    return status === 'approved' || status === 'unreviewed';
}

function authenticateAdmin(req, res, next) {
    markPerf(req, 'auth-admin-start');
    const token = getAdminAuthToken(req);
    if (!token) {
        return res.status(401).json({ error: '未授权' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = validateAdminTokenPayload(decoded);
        if (!admin) return res.status(403).json({ error: '权限不足或登录状态已失效' });
        req.admin = admin;
        markPerf(req, 'auth-admin-ok', { adminId: admin.id });
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function authenticateUser(req, res, next) {
    markPerf(req, 'auth-user-start');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = validateUserTokenPayload(decoded);
        if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
        if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
        req.user = user;
        markPerf(req, 'auth-user-ok', { userId: user.id });
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function authenticateUserAllowUnbound(req, res, next) {
    markPerf(req, 'auth-user-unbound-start');
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = validateUserTokenPayload(decoded);
        if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
        req.user = user;
        markPerf(req, 'auth-user-unbound-ok', { userId: user.id });
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function optionalUserAuth(req, res, next) {
    markPerf(req, 'auth-optional-start');
    const token = getRequestAuthToken(req);
    if (!token) {
        req.user = null;
        markPerf(req, 'auth-optional-guest');
        return next();
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'user') {
            req.user = validateUserTokenPayload(decoded);
            markPerf(req, 'auth-optional-user', { userId: req.user?.id || null });
        }
        else if (decoded.role === 'admin') {
            if (!isAdminCookieToken(req, token)) {
                req.user = null;
                markPerf(req, 'auth-optional-rejected-admin-bearer');
                return next();
            }
            req.admin = validateAdminTokenPayload(decoded);
            req.user = null;
            markPerf(req, 'auth-optional-admin', { adminId: req.admin?.id || null });
        }
        else {
            req.user = null;
            markPerf(req, 'auth-optional-unknown-role');
        }
        next();
    } catch (err) {
        req.user = null;
        markPerf(req, 'auth-optional-failed');
        next();
    }
}

function requireUserOrAdmin(req, res, next) {
    markPerf(req, 'auth-user-or-admin-start');
    const token = getRequestAuthToken(req);
    if (!token) {
        return res.status(401).json({ error: '请先登录后再操作' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'user') {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            req.user = user;
            markPerf(req, 'auth-user-or-admin-user', { userId: user.id });
        } else if (decoded.role === 'admin') {
            if (!isAdminCookieToken(req, token)) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            req.admin = admin;
            markPerf(req, 'auth-user-or-admin-admin', { adminId: admin.id });
        } else {
            return res.status(403).json({ error: '权限不足' });
        }
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function requireModeration(req, res, next) {
    markPerf(req, 'auth-moderation-start');
    const token = getRequestAuthToken(req);
    if (!token) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') {
            if (!isAdminCookieToken(req, token)) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            req.admin = admin;
            markPerf(req, 'auth-moderation-admin', { adminId: admin.id });
            return next();
        }
        if (decoded.role === 'user') {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            if (!isModeratorUser(user)) return res.status(403).json({ error: '权限不足' });
            req.user = user;
            markPerf(req, 'auth-moderation-user', { userId: user.id });
            return next();
        }
        return res.status(403).json({ error: '权限不足' });
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

// ============== Operation Logging ==============
function logOperation({ userType, userId, username, action, targetType, targetId, ip, details }) {
    try {
        db.prepare(
            `INSERT INTO operation_logs (user_type, user_id, username, action, target_type, target_id, ip_address, details, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(userType || 'anonymous', userId || null, username || null, action,
              targetType || null, targetId || null, ip || null,
              details ? JSON.stringify(details) : null, new Date().toISOString());
    } catch (err) {
        console.error('Log operation error:', err);
    }
}

function getModerationActor(req) {
    if (req.admin) {
        return {
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username || 'admin',
            reviewerType: 'admin'
        };
    }
    return {
        userType: 'user',
        userId: req.user.id,
        username: req.user.username,
        reviewerType: 'moderator'
    };
}

// ============== Brute Force Protection ==============
function checkBruteForce(ip, username) {
    const cutoff = new Date(Date.now() - LOGIN_WINDOW_MINUTES * 60 * 1000).toISOString();
    const attempts = db.prepare(
        `SELECT COUNT(*) as count FROM login_attempts 
         WHERE ip_address = ? AND attempt_time > ? AND success = 0`
    ).get(ip, cutoff);

    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        return { blocked: true, reason: `IP 登录尝试过多，请 ${LOCKOUT_MINUTES} 分钟后再试` };
    }

    if (username) {
        const userAttempts = db.prepare(
            `SELECT COUNT(*) as count FROM login_attempts 
             WHERE username = ? AND attempt_time > ? AND success = 0`
        ).get(username, cutoff);
        if (userAttempts.count >= MAX_LOGIN_ATTEMPTS) {
            return { blocked: true, reason: `该账户登录尝试过多，请 ${LOCKOUT_MINUTES} 分钟后再试` };
        }
    }

    return { blocked: false };
}

function recordLoginAttempt(ip, username, success) {
    db.prepare(
        'INSERT INTO login_attempts (ip_address, username, attempt_time, success) VALUES (?, ?, ?, ?)'
    ).run(ip, username, new Date().toISOString(), success ? 1 : 0);
}

function touchUserLoginRate(key, now) {
    const timestamps = (userLoginRateMap.get(key) || [])
        .filter(time => now - time < USER_LOGIN_RATE_WINDOW_MS);
    timestamps.push(now);
    userLoginRateMap.set(key, timestamps);
    return timestamps.length;
}

function checkUserLoginRate(ip, username) {
    const now = Date.now();
    const safeIp = ip || 'unknown';
    const safeName = String(username || '').trim().toLowerCase();
    const ipKey = `ip:${safeIp}`;
    const nameKey = safeName ? `name:${safeName}` : '';
    const ipCount = touchUserLoginRate(ipKey, now);
    const nameCount = nameKey ? touchUserLoginRate(nameKey, now) : 0;
    if (ipCount > USER_LOGIN_RATE_MAX_PER_IP || nameCount > USER_LOGIN_RATE_MAX_PER_NAME) {
        return {
            blocked: true,
            retryAfter: Math.ceil(USER_LOGIN_RATE_WINDOW_MS / 1000),
            reason: '登录太频繁，请稍后再试'
        };
    }
    return { blocked: false };
}

setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of userLoginRateMap) {
        const active = timestamps.filter(time => now - time < USER_LOGIN_RATE_WINDOW_MS);
        if (active.length === 0) userLoginRateMap.delete(key);
        else userLoginRateMap.set(key, active);
    }
}, 5 * 60 * 1000);

// ============== Email Helpers ==============
function normalizeEmail(email) {
    const value = String(email || '').trim().toLowerCase();
    if (!value || value.length > 254) return '';
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? value : '';
}

function isQqEmail(email) {
    const normalized = normalizeEmail(email);
    return Boolean(normalized && normalized.endsWith('@qq.com'));
}

function validateQqEmail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) return { ok: false, email: '', error: '请输入有效邮箱' };
    if (!isQqEmail(normalized)) return { ok: false, email: normalized, error: '目前仅支持 QQ 邮箱（@qq.com）' };
    return { ok: true, email: normalized };
}

function parseEmailList(value) {
    const seen = new Set();
    const emails = [];
    String(value || '')
        .split(/[\s,;，；]+/)
        .map(item => normalizeEmail(item))
        .filter(Boolean)
        .forEach((email) => {
            if (!seen.has(email)) {
                seen.add(email);
                emails.push(email);
            }
        });
    return emails;
}

function findInvalidEmails(value) {
    return String(value || '')
        .split(/[\s,;，；]+/)
        .map(item => item.trim())
        .filter(Boolean)
        .filter(item => !normalizeEmail(item));
}

function findNonQqEmails(value) {
    return String(value || '')
        .split(/[\s,;，；]+/)
        .map(item => normalizeEmail(item))
        .filter(Boolean)
        .filter(item => !isQqEmail(item));
}

function maskEmail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) return '';
    const [name, domain] = normalized.split('@');
    const visible = name.length <= 2 ? name[0] || '*' : `${name.slice(0, 2)}***`;
    return `${visible}@${domain}`;
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function buildSiteUrl(req, pathPart = '/') {
    const dbBaseUrl = getSettingValue('public_base_url');
    const configured = (dbBaseUrl || process.env.PUBLIC_BASE_URL || process.env.SITE_URL || '').trim().replace(/\/+$/, '');
    if (configured) return `${configured}${pathPart.startsWith('/') ? pathPart : `/${pathPart}`}`;
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
    return `${protocol}://${host}${pathPart.startsWith('/') ? pathPart : `/${pathPart}`}`;
}

function getSettingValue(key) {
    try {
        return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value || '';
    } catch {
        return '';
    }
}

function getSettingValueOrNull(key) {
    try {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
        return row ? String(row.value || '') : null;
    } catch {
        return null;
    }
}

function setSettingValue(key, value) {
    db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run(key, String(value || ''), new Date().toISOString());
}

function getEmailConfig() {
    return {
        apiKey: getSettingValue('resend_api_key') || RESEND_API_KEY,
        from: getSettingValue('resend_from') || RESEND_FROM
    };
}

function getTurnstileConfig() {
    return {
        siteKey: getSettingValue('turnstile_site_key') || TURNSTILE_SITE_KEY,
        secretKey: getSettingValue('turnstile_secret_key') || TURNSTILE_SECRET_KEY
    };
}

async function verifyTurnstileToken(token, remoteIp, expectedAction = 'email_code') {
    const config = getTurnstileConfig();
    if (!config.siteKey || !config.secretKey) {
        const error = new Error('安全验证尚未配置，请联系管理员');
        error.statusCode = 503;
        throw error;
    }
    if (!token || token.length > 2048) {
        const error = new Error('请先完成安全验证');
        error.statusCode = 400;
        throw error;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
        const response = await fetch(TURNSTILE_VERIFY_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                secret: config.secretKey,
                response: token,
                remoteip: remoteIp || ''
            }),
            signal: controller.signal
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success || (data.action && data.action !== expectedAction)) {
            const error = new Error('安全验证未通过或已过期，请重试');
            error.statusCode = 400;
            throw error;
        }
        return true;
    } catch (error) {
        if (error.statusCode) throw error;
        const wrapped = new Error(error.name === 'AbortError' ? '安全验证服务响应超时，请重试' : '安全验证服务暂时不可用，请重试');
        wrapped.statusCode = 503;
        throw wrapped;
    } finally {
        clearTimeout(timeout);
    }
}

function getAdminNotificationEmails() {
    return parseEmailList(getSettingValue('admin_notification_emails') || ADMIN_NOTIFICATION_EMAILS);
}

function normalizeCommentEmailBlockText(value) {
    return String(value ?? '').normalize('NFKC').toLowerCase();
}

function normalizeDuplicateCommentText(value) {
    return String(value ?? '').normalize('NFKC').trim().replace(/\s+/g, ' ');
}

function hasDuplicateCommentContent({ table, itemColumn, itemId, userId, content }) {
    const normalizedContent = normalizeDuplicateCommentText(content);
    if (!normalizedContent) return false;
    const rows = db.prepare(`SELECT content FROM ${table} WHERE ${itemColumn} = ? AND user_id = ?`).all(itemId, userId);
    return rows.some(row => normalizeDuplicateCommentText(row.content) === normalizedContent);
}

function parseCommentEmailBlockWords(value) {
    return normalizeCommentEmailBlockText(value)
        .split(/[\n,;，；]+/)
        .map(item => item.trim())
        .filter(Boolean)
        .filter((item, index, array) => array.indexOf(item) === index)
        .slice(0, 200);
}

function getCommentEmailBlockWords() {
    const saved = getSettingValueOrNull('comment_email_block_words');
    const savedWords = saved === null ? [] : parseCommentEmailBlockWords(saved);
    return parseCommentEmailBlockWords([...DEFAULT_COMMENT_EMAIL_BLOCK_WORDS, ...savedWords].join('\n'));
}

function isCommentEmailBlocked(content) {
    const text = normalizeCommentEmailBlockText(content);
    if (!text) return false;
    return getCommentEmailBlockWords().some(word => text.includes(normalizeCommentEmailBlockText(word)));
}

function isCommentHiddenFromDisplay(content, blockWords = getCommentEmailBlockWords()) {
    const text = normalizeCommentEmailBlockText(content);
    if (!text) return false;
    const trimmedText = text.trim();
    const compactText = trimmedText.replace(/\s+/g, '');
    return /^\d+$/.test(compactText)
        || /^[a-z]+$/.test(trimmedText)
        || /^已[\p{L}\p{N}]{0,8}下载(?:成功|完成|了)?[!！。.]*$/u.test(compactText)
        || blockWords.some(word => text.includes(normalizeCommentEmailBlockText(word)));
}

db.function('comment_is_hidden', { deterministic: true }, (content, blockWordsJson) => {
    let blockWords = [];
    try { blockWords = JSON.parse(blockWordsJson || '[]'); } catch {}
    return isCommentHiddenFromDisplay(content, blockWords) ? 1 : 0;
});

function normalizeBaseUrl(value) {
    return String(value || '').trim().replace(/\/+$/, '');
}

function getNewApiConfig() {
    return {
        baseUrl: normalizeBaseUrl(getSettingValue('newapi_base_url') || NEWAPI_BASE_URL),
        adminToken: getSettingValue('newapi_admin_token') || NEWAPI_ADMIN_TOKEN,
        adminUserId: String(getSettingValue('newapi_admin_user_id') || NEWAPI_ADMIN_USER_ID || '').trim()
    };
}

function isNewApiConfigured() {
    const config = getNewApiConfig();
    return Boolean(config.baseUrl && config.adminToken && config.adminUserId);
}

function getAiReviewConfig() {
    const savedPrompt = String(getSettingValue('ai_review_prompt') || '').trim();
    const savedCoverPrompt = String(getSettingValue('ai_review_cover_prompt') || '').trim();
    const useDefaultTextPrompt = !savedPrompt
        || savedPrompt === AI_REVIEW_LEGACY_DEFAULT_PROMPT
        || savedPrompt === AI_REVIEW_PREVIOUS_DEFAULT_PROMPT;
    const textPrompt = useDefaultTextPrompt ? AI_REVIEW_DEFAULT_TEXT_PROMPT : savedPrompt;
    const coverPrompt = savedCoverPrompt || AI_REVIEW_DEFAULT_COVER_PROMPT;
    if (savedPrompt !== textPrompt) setSettingValue('ai_review_prompt', textPrompt);
    if (savedCoverPrompt !== coverPrompt) setSettingValue('ai_review_cover_prompt', coverPrompt);
    return {
        baseUrl: normalizeBaseUrl(getSettingValue('ai_review_base_url') || AI_REVIEW_DEFAULT_BASE_URL),
        apiKey: getSettingValue('ai_review_api_key') || AI_REVIEW_API_KEY,
        model: String(getSettingValue('ai_review_model') || AI_REVIEW_MODEL || '').trim(),
        visionModel: String(getSettingValue('ai_review_vision_model') || AI_REVIEW_VISION_MODEL || AI_REVIEW_DEFAULT_VISION_MODEL).trim(),
        textPrompt,
        coverPrompt
    };
}

function isAiReviewConfigured(config = getAiReviewConfig()) {
    return Boolean(config.baseUrl && config.apiKey && config.model && config.visionModel);
}

function getNewApiHeaders() {
    const config = getNewApiConfig();
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.adminToken}`
    };
    if (config.adminUserId) {
        headers['New-Api-User'] = config.adminUserId;
    }
    return headers;
}

async function requestNewApi(pathPart, options = {}) {
    const config = getNewApiConfig();
    if (!config.baseUrl || !config.adminToken) {
        throw new Error('STA1N API 未配置，请先在后台设置地址和管理员 Token');
    }
    if (!config.adminUserId) {
        throw new Error('STA1N API 未配置管理用户 ID，请先在后台填写管理用户 ID');
    }
    const response = await fetch(`${config.baseUrl}${pathPart}`, {
        ...options,
        headers: {
            ...getNewApiHeaders(),
            ...(options.headers || {})
        }
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data?.success === false) {
        throw new Error(data?.message || data?.error || `STA1N API 请求失败：HTTP ${response.status}`);
    }
    return data?.data !== undefined ? data.data : data;
}

async function getNewApiUserInfo(newApiUserId) {
    return requestNewApi(`/api/user/${encodeURIComponent(newApiUserId)}`);
}

async function manageNewApiUser(payload) {
    return requestNewApi('/api/user/manage', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
}

async function addNewApiQuota(newApiUserId, quotaToAdd) {
    const id = Number(newApiUserId);
    if (!Number.isInteger(id) || id <= 0) throw new Error('STA1N API 用户 ID 无效');
    const userInfo = await getNewApiUserInfo(newApiUserId);
    const currentQuota = Number(userInfo?.quota || 0);
    if (!Number.isFinite(currentQuota)) {
        throw new Error('STA1N API 返回的用户额度无效');
    }
    if (userInfo?.status !== undefined && Number(userInfo.status) !== NEWAPI_USER_STATUS_ENABLED) {
        throw new Error('这个 STA1N API 账号当前是禁用状态，请先让管理员启用后再提现');
    }
    const nextQuota = currentQuota + quotaToAdd;
    await manageNewApiUser({
        id,
        action: 'add_quota',
        mode: 'add',
        value: quotaToAdd
    });
    const updatedUserInfo = await getNewApiUserInfo(newApiUserId).catch(() => null);
    const updatedQuota = Number(updatedUserInfo?.quota);
    return {
        userInfo,
        updatedUserInfo,
        quotaBefore: currentQuota,
        quotaAfter: Number.isFinite(updatedQuota) ? updatedQuota : nextQuota
    };
}

function maskSecret(secret) {
    const value = String(secret || '').trim();
    if (!value) return '';
    if (value.length <= 8) return '********';
    return `${value.slice(0, 4)}...${value.slice(-6)}`;
}

function isEmailConfigured() {
    const config = getEmailConfig();
    return Boolean(config.apiKey && config.from);
}

function describeFetchFailure(err) {
    if (!err) return '未知网络错误';
    const parts = [];
    if (err.name === 'AbortError') parts.push(`请求超时（${EMAIL_SEND_TIMEOUT_MS}ms）`);
    if (err.message) parts.push(err.message);
    if (err.cause?.code) parts.push(err.cause.code);
    if (err.cause?.message && err.cause.message !== err.message) parts.push(err.cause.message);
    return [...new Set(parts.filter(Boolean))].join(' / ') || '未知网络错误';
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function sendResendEmail({ to, subject, html, text }) {
    const normalizedTo = normalizeEmail(to);
    if (!normalizedTo) throw new Error('收件邮箱格式无效');
    if (!isQqEmail(normalizedTo)) throw new Error('目前仅支持 QQ 邮箱（@qq.com）');
    const config = getEmailConfig();
    if (!config.apiKey || !config.from) {
        throw new Error('邮件服务未配置，请在后台或环境变量里设置 Resend API Key 和发件邮箱');
    }
    const requestBody = JSON.stringify({
        from: config.from,
        to: [normalizedTo],
        subject,
        html,
        text
    });

    let response = null;
    let lastError = null;
    for (let attempt = 0; attempt <= EMAIL_SEND_RETRIES; attempt += 1) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), EMAIL_SEND_TIMEOUT_MS);
        try {
            response = await fetch(RESEND_EMAIL_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${config.apiKey}`
                },
                body: requestBody,
                signal: controller.signal
            });
            lastError = null;
            break;
        } catch (err) {
            lastError = err;
            if (attempt < EMAIL_SEND_RETRIES) await delay(500);
        } finally {
            clearTimeout(timeout);
        }
    }

    if (!response) {
        throw new Error(`Resend 连接失败：${describeFetchFailure(lastError)}`);
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        const detail = data?.message || data?.error || data?.errors?.[0]?.extensions?.code || `HTTP ${response.status}`;
        throw new Error(`邮件发送失败：${detail}`);
    }
    return data;
}

function sendResendEmailQuietly(payload) {
    sendResendEmail(payload).catch((err) => {
        const target = payload?.to ? maskEmail(normalizeEmail(payload.to)) : '-';
        console.error(`[Email] Notification send failed (${target}):`, err.message);
    });
}

function hashEmailCode(email, purpose, code, userId) {
    return crypto.createHmac('sha256', JWT_SECRET)
        .update(`${normalizeEmail(email)}:${purpose}:${userId || ''}:${String(code || '').trim()}`)
        .digest('hex');
}

function cleanupEmailCodes() {
    try {
        db.prepare("DELETE FROM email_verification_codes WHERE expires_at < datetime('now', '-1 day') OR used_at IS NOT NULL").run();
    } catch (err) {
        console.error('Cleanup email codes error:', err);
    }
}

function createEmailCode({ email, purpose, userId, ip }) {
    const normalizedEmail = normalizeEmail(email);
    const code = String(crypto.randomInt(100000, 1000000));
    const now = new Date();
    const expiresAt = new Date(now.getTime() + EMAIL_CODE_TTL_MINUTES * 60 * 1000).toISOString();
    const codeHash = hashEmailCode(normalizedEmail, purpose, code, userId);
    db.prepare(
        `UPDATE email_verification_codes
         SET used_at = ?
         WHERE email = ? AND purpose = ? AND COALESCE(user_id, 0) = COALESCE(?, 0) AND used_at IS NULL`
    ).run(now.toISOString(), normalizedEmail, purpose, userId || null);
    db.prepare(
        `INSERT INTO email_verification_codes
         (email, purpose, user_id, code_hash, expires_at, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).run(normalizedEmail, purpose, userId || null, codeHash, expiresAt, ip || null);
    return { code, expiresAt };
}

function getEmailCodeCooldown({ email, purpose, userId }) {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !purpose) return 0;
    const recent = db.prepare(
        `SELECT CAST(strftime('%s', 'now') - strftime('%s', created_at) AS INTEGER) AS elapsed_seconds
         FROM email_verification_codes
         WHERE email = ? AND purpose = ? AND COALESCE(user_id, 0) = COALESCE(?, 0)
           AND created_at > datetime('now', ?)
         ORDER BY created_at DESC LIMIT 1`
    ).get(normalizedEmail, purpose, userId || null, `-${EMAIL_CODE_COOLDOWN_SECONDS} seconds`);
    if (!recent) return 0;
    return Math.max(1, EMAIL_CODE_COOLDOWN_SECONDS - Number(recent.elapsed_seconds || 0));
}

function getEmailCodeIpRetryAfter(ip) {
    if (!ip) return 0;
    const thirdNewest = db.prepare(
        `SELECT CAST(strftime('%s', 'now') - strftime('%s', created_at) AS INTEGER) AS elapsed_seconds
         FROM email_verification_codes
         WHERE ip_address = ? AND created_at > datetime('now', '-1 minute')
         ORDER BY created_at DESC LIMIT 1 OFFSET ?`
    ).get(ip, EMAIL_CODE_IP_MAX_PER_WINDOW - 1);
    if (!thirdNewest) return 0;
    return Math.max(1, Math.ceil(EMAIL_CODE_IP_WINDOW_MS / 1000) - Number(thirdNewest.elapsed_seconds || 0));
}

function verifyEmailCode({ email, purpose, userId, code }) {
    const normalizedEmail = normalizeEmail(email);
    const normalizedCode = String(code || '').trim();
    if (!normalizedEmail || !/^\d{6}$/.test(normalizedCode)) {
        return { ok: false, error: '邮箱验证码不正确' };
    }

    const record = db.prepare(
        `SELECT * FROM email_verification_codes
         WHERE email = ? AND purpose = ? AND COALESCE(user_id, 0) = COALESCE(?, 0)
           AND used_at IS NULL AND expires_at > ?
         ORDER BY created_at DESC LIMIT 1`
    ).get(normalizedEmail, purpose, userId || null, new Date().toISOString());

    if (!record) return { ok: false, error: '验证码不存在或已过期，请重新发送' };
    if (Number(record.attempts || 0) >= EMAIL_CODE_MAX_ATTEMPTS) {
        return { ok: false, error: '验证码尝试次数太多，请重新发送' };
    }

    const expected = record.code_hash;
    const actual = hashEmailCode(normalizedEmail, purpose, normalizedCode, userId);
    const match = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
    if (!match) {
        db.prepare('UPDATE email_verification_codes SET attempts = attempts + 1 WHERE id = ?').run(record.id);
        return { ok: false, error: '邮箱验证码不正确' };
    }

    db.prepare('UPDATE email_verification_codes SET used_at = ? WHERE id = ?').run(new Date().toISOString(), record.id);
    return { ok: true };
}

function buildUserResponse(user) {
    return {
        id: user.id,
        username: user.username,
        email: user.email || '',
        email_verified: Number(user.email_verified || 0),
        newapi_user_id: user.newapi_user_id || '',
        newapi_redeemed_cookies: floorToTwoDecimals(Math.max(0, Number(user.newapi_redeemed_cookies || 0))),
        newapi_penalty_cookies: floorToTwoDecimals(Math.max(0, Number(user.newapi_penalty_cookies || 0))),
        comment_email_notifications: Number(user.comment_email_notifications || 0) === 1 ? 1 : 0,
        requires_email_binding: !userEmailBound(user),
        download_credits: user.download_credits,
        created_at: user.created_at,
        is_moderator: Number(user.is_moderator || 0),
        is_banned: user.is_banned || 0,
        ban_reason: user.ban_reason || null
    };
}

function userEmailBound(user) {
    return Boolean(user && isQqEmail(user.email) && Number(user.email_verified || 0) === 1);
}

function userCommentEmailNotificationsEnabled(user) {
    return Number(user?.comment_email_notifications || 0) === 1;
}

function rejectUnboundEmail(req, res) {
    return res.status(403).json({
        error: '请先绑定邮箱再继续使用广场',
        requires_email_binding: true
    });
}

function sendVerificationCodeEmail({ email, code, purpose }) {
    const purposeLabel = {
        register: '注册账号',
        bind: '绑定邮箱',
        reset_password: '重置密码'
    }[purpose] || '验证邮箱';
    return sendResendEmail({
        to: email,
        subject: `你的邮箱验证码：${code}`,
        html: `<p>你正在进行「${escapeHtml(purposeLabel)}」。</p><p style="font-size:24px;font-weight:700;letter-spacing:4px;">${code}</p><p>验证码 ${EMAIL_CODE_TTL_MINUTES} 分钟内有效。如果不是你本人操作，可以忽略这封邮件。</p>`,
        text: `你正在进行「${purposeLabel}」。验证码：${code}。${EMAIL_CODE_TTL_MINUTES} 分钟内有效。`
    });
}

function sendReviewResultEmail({ to, username, itemType, title, status, reason }) {
    const approved = status === 'approved';
    const resultText = approved ? '已通过' : '未通过';
    const reasonText = reason ? `\n原因：${reason}` : '';
    sendResendEmailQuietly({
        to,
        subject: `你的${itemType}审核${resultText}`,
        html: `<p>${escapeHtml(username || '你好')}，你的${escapeHtml(itemType)}「${escapeHtml(title)}」审核${escapeHtml(resultText)}。</p>${reason ? `<p>原因：${escapeHtml(reason)}</p>` : ''}`,
        text: `${username || '你好'}，你的${itemType}「${title}」审核${resultText}。${reasonText}`
    });
}

function sendFeaturedNotificationEmail({ to, username, itemType, title }) {
    sendResendEmailQuietly({
        to,
        subject: `恭喜，你的${itemType}被设为精选`,
        html: `<p>${escapeHtml(username || '你好')}，恭喜！你的${escapeHtml(itemType)}「${escapeHtml(title)}」已经被设为精选。</p><p>它会获得更多展示机会，感谢你的优质创作。</p>`,
        text: `${username || '你好'}，恭喜！你的${itemType}「${title}」已经被设为精选。\n它会获得更多展示机会，感谢你的优质创作。`
    });
}

function sendAdminReviewPendingEmail({ itemType, title, uploader, ip }) {
    const recipients = getAdminNotificationEmails();
    if (recipients.length === 0) return;
    const uploaderText = uploader || '未知用户';
    const html = `<p>有新的${escapeHtml(itemType)}进入待审核。</p><p>名称：${escapeHtml(title)}</p><p>上传者：${escapeHtml(uploaderText)}</p>${ip ? `<p>上传 IP：${escapeHtml(ip)}</p>` : ''}`;
    const text = `有新的${itemType}进入待审核。\n名称：${title}\n上传者：${uploaderText}${ip ? `\n上传 IP：${ip}` : ''}`;
    recipients.forEach((to) => {
        sendResendEmailQuietly({
            to,
            subject: `新的${itemType}待审核：${title}`,
            html,
            text
        });
    });
}

function sendCommentNotificationEmail({ to, ownerName, commenterName, itemType, title, content }) {
    const commentText = String(content || '').trim();
    if (!commentText) return;
    if (isCommentEmailBlocked(commentText)) return;
    const htmlContent = escapeHtml(commentText).replace(/\n/g, '<br>');
    sendResendEmailQuietly({
        to,
        subject: `你的${itemType}「${title}」有新评论`,
        html: `<p>${escapeHtml(ownerName || '你好')}，你的${escapeHtml(itemType)}「${escapeHtml(title)}」收到了来自 ${escapeHtml(commenterName || '用户')} 的新评论。</p><p>评论内容：</p><blockquote style="margin:12px 0;padding:12px;border-left:4px solid #dbeafe;background:#f8fafc;">${htmlContent}</blockquote>`,
        text: `${ownerName || '你好'}，你的${itemType}「${title}」收到了来自 ${commenterName || '用户'} 的新评论。\n评论内容：\n${commentText}`
    });
}

function sendCommentReplyNotificationEmail({ to, ownerName, commenterName, itemType, title, content }) {
    const commentText = String(content || '').trim();
    if (!commentText) return;
    if (isCommentEmailBlocked(commentText)) return;
    const htmlContent = escapeHtml(commentText).replace(/\n/g, '<br>');
    sendResendEmailQuietly({
        to,
        subject: `你在${itemType}「${title}」下的评论收到了回复`,
        html: `<p>${escapeHtml(ownerName || '你好')}，你在${escapeHtml(itemType)}「${escapeHtml(title)}」下的评论收到了来自 ${escapeHtml(commenterName || '用户')} 的回复。</p><p>回复内容：</p><blockquote style="margin:12px 0;padding:12px;border-left:4px solid #dbeafe;background:#f8fafc;">${htmlContent}</blockquote>`,
        text: `${ownerName || '你好'}，你在${itemType}「${title}」下的评论收到了来自 ${commenterName || '用户'} 的回复。\n回复内容：\n${commentText}`
    });
}

function sendNewApiRedemptionSuccessEmail({ to, username, cookies, newApiUserId }) {
    const cookiesText = floorToTwoDecimals(cookies).toFixed(2).replace(/\.?0+$/, '');
    sendResendEmailQuietly({
        to,
        subject: `提现成功：${cookiesText}🍪`,
        html: `<p>${escapeHtml(username || '你好')}，你的提现已经成功到账。</p><p>提现数量：${escapeHtml(cookiesText)}🍪</p><p>STA1N API ID：${escapeHtml(newApiUserId || '-')}</p>`,
        text: `${username || '你好'}，你的提现已经成功到账。\n提现数量：${cookiesText}🍪\nSTA1N API ID：${newApiUserId || '-'}`
    });
}

function cardCommentCountExpr(cardAlias = 'character_cards') {
    return `(SELECT COUNT(*) FROM character_comments cmt WHERE cmt.card_id = ${cardAlias}.id)`;
}

function cardCommentHeatCountExpr(cardAlias = 'character_cards') {
    return cardCommentCountExpr(cardAlias);
}

function templateCommentCountExpr(templateAlias = 'ui_templates') {
    return `(SELECT COUNT(*) FROM ui_template_comments utc WHERE utc.template_id = ${templateAlias}.id)`;
}

function templateCommentHeatCountExpr(templateAlias = 'ui_templates') {
    return templateCommentCountExpr(templateAlias);
}

function getRankingPeriodModifier(sortMode) {
    return { daily: '-1 day', weekly: '-7 days', monthly: '-30 days' }[sortMode] || '';
}

function cardPeriodHeatExpr(cardAlias, periodModifier) {
    const cutoff = `datetime('now', '${periodModifier}')`;
    return `(
        (SELECT COUNT(*) FROM content_view_events cve
         WHERE cve.content_type = 'card' AND cve.content_id = ${cardAlias}.id AND cve.created_at >= ${cutoff}) * ${VIEW_HEAT_WEIGHT}
        + (SELECT COUNT(*) FROM character_comments cmt
           WHERE cmt.card_id = ${cardAlias}.id AND cmt.created_at >= ${cutoff}) * ${COMMENT_HEAT_WEIGHT}
        + (SELECT COUNT(*) FROM card_downloads cd
           WHERE cd.card_id = ${cardAlias}.id AND cd.created_at >= ${cutoff}) * ${DOWNLOAD_HEAT_WEIGHT}
    )`;
}

function templatePeriodHeatExpr(templateAlias, periodModifier) {
    const cutoff = `datetime('now', '${periodModifier}')`;
    return `(
        (SELECT COUNT(*) FROM content_view_events cve
         WHERE cve.content_type = 'ui_template' AND cve.content_id = ${templateAlias}.id AND cve.created_at >= ${cutoff}) * ${VIEW_HEAT_WEIGHT}
        + (SELECT COUNT(*) FROM ui_template_comments utc
           WHERE utc.template_id = ${templateAlias}.id AND utc.created_at >= ${cutoff}) * ${COMMENT_HEAT_WEIGHT}
        + (SELECT COUNT(*) FROM ui_template_downloads utd
           WHERE utd.template_id = ${templateAlias}.id AND utd.created_at >= ${cutoff}) * ${DOWNLOAD_HEAT_WEIGHT}
    )`;
}

function getCommentHeatCount(row) {
    return Number(row?.comment_heat_count ?? row?.comment_count ?? 0);
}

function computeContentHeatFromRow(row) {
    return Math.round(
        (row.views_count || 0) * VIEW_HEAT_WEIGHT
        + getCommentHeatCount(row) * COMMENT_HEAT_WEIGHT
        + (row.downloads_count || 0) * DOWNLOAD_HEAT_WEIGHT
    );
}

function computeCardHeatFromRow(row) {
    return computeContentHeatFromRow(row);
}

function computeTemplateHeatFromRow(row) {
    return computeContentHeatFromRow(row);
}

const CARD_LIST_CACHE_TTL_MS = Math.max(1000, parseInt(process.env.CARD_LIST_CACHE_TTL_MS || '15000', 10) || 15000);
const CARD_LIST_CACHE_MAX_ENTRIES = Math.max(3, parseInt(process.env.CARD_LIST_CACHE_MAX_ENTRIES || '256', 10) || 256);
const cardListCache = new Map();
let cardListCacheRevision = 1;

function extractCardTags(creatorNotes) {
    const tags = [];
    const pattern = /#([^#\s]+)/g;
    let match;
    while ((match = pattern.exec(String(creatorNotes || ''))) !== null) tags.push(match[1]);
    return tags;
}

const replaceCardTags = db.transaction((cardId, creatorNotes) => {
    db.prepare('DELETE FROM character_card_tags WHERE card_id = ?').run(cardId);
    const insert = db.prepare('INSERT OR IGNORE INTO character_card_tags (card_id, tag, tag_key) VALUES (?, ?, ?)');
    for (const tag of extractCardTags(creatorNotes)) insert.run(cardId, tag, tag.toLowerCase());
});

function syncCardTags(cardId, creatorNotes) {
    replaceCardTags(cardId, creatorNotes);
}

function getCardListCacheKey(req, sortMode, zone, representation = 'full') {
    if (req.admin) return `admin:${req.admin.id}:${zone}:${sortMode}:${representation}`;
    if (isModeratorUser(req.user)) return `moderator:${req.user.id}:${zone}:${sortMode}:${representation}`;
    if (req.user) return `user:${req.user.id}:${zone}:${sortMode}:${representation}`;
    return `guest:${zone}:${sortMode}:${representation}`;
}

function hasRequestEtag(req, etag) {
    return String(req.headers['if-none-match'] || '')
        .split(',')
        .map(value => value.trim())
        .includes(etag);
}

function getFreshCardListCache(key) {
    const cached = cardListCache.get(key);
    if (!cached) return null;
    if (cached.revision !== cardListCacheRevision || Date.now() - cached.createdAt > CARD_LIST_CACHE_TTL_MS) {
        cardListCache.delete(key);
        return null;
    }
    cardListCache.delete(key);
    cardListCache.set(key, cached);
    return cached;
}

function setCardListCache(key, cards, totalCount = cards.length) {
    while (cardListCache.size >= CARD_LIST_CACHE_MAX_ENTRIES) {
        const firstKey = cardListCache.keys().next().value;
        cardListCache.delete(firstKey);
    }
    const body = JSON.stringify(cards);
    const gzipBody = zlib.gzipSync(body, { level: 6 });
    const etagHash = crypto.createHash('sha1').update(`${key}:${cardListCacheRevision}:${body}`).digest('hex').slice(0, 16);
    const cached = {
        body,
        gzipBody,
        etag: `"cards-${cardListCacheRevision}-${etagHash}"`,
        totalCount,
        revision: cardListCacheRevision,
        createdAt: Date.now()
    };
    cardListCache.set(key, cached);
    return cached;
}

function sendCardListCache(req, res, cached) {
    res.set('ETag', cached.etag);
    res.set('X-Total-Count', String(cached.totalCount));
    res.set('Cache-Control', 'private, max-age=0, must-revalidate');
    res.set('Vary', 'Accept-Encoding');
    res.type('application/json');

    if (hasRequestEtag(req, cached.etag)) {
        markPerf(req, 'cards-cache-not-modified');
        return res.status(304).end();
    }

    const acceptsGzip = /\bgzip\b/i.test(String(req.headers['accept-encoding'] || ''));
    if (acceptsGzip && cached.gzipBody) {
        res.set('Content-Encoding', 'gzip');
        res.set('Content-Length', cached.gzipBody.length);
        markPerf(req, 'cards-response-gzip', { bytes: cached.gzipBody.length });
        return res.end(cached.gzipBody);
    }

    res.set('Content-Length', Buffer.byteLength(cached.body, 'utf8'));
    markPerf(req, 'cards-response-json', { bytes: cached.body.length });
    return res.send(cached.body);
}

function clearCardListCache(reason = '') {
    cardListCacheRevision += 1;
    cardListCache.clear();
    if (reason) console.info(`[CardsCache] cleared reason=${reason} revision=${cardListCacheRevision}`);
}

function floorToTwoDecimals(value) {
    const number = Number(value || 0);
    if (!Number.isFinite(number)) return 0;
    return Math.floor(number * 100 + 1e-8) / 100;
}

function parseCookieAmount(value) {
    const raw = String(value ?? '').trim();
    if (!/^\d+(?:\.\d{1,2})?$/.test(raw)) return null;
    const amount = Number(raw);
    if (!Number.isFinite(amount)) return null;
    return floorToTwoDecimals(amount);
}

function recordAccountViewHeat(req, contentType, contentId) {
    const userId = req.user?.id;
    if (!userId) return { counted: false, limited: false, reason: 'login_required' };

    const now = new Date().toISOString();
    const recordViewEvent = () => db.prepare(
        'INSERT INTO content_view_events (content_type, content_id, user_id, created_at) VALUES (?, ?, ?, ?)'
    ).run(contentType, String(contentId), userId, now);
    const windowModifier = `-${VIEW_HEAT_ACCOUNT_WINDOW_HOURS} hours`;
    const row = db.prepare(
        `SELECT id, view_count,
                CASE WHEN datetime(window_started_at) <= datetime('now', ?) THEN 1 ELSE 0 END AS expired
         FROM account_view_limits
         WHERE content_type = ? AND content_id = ? AND user_id = ?`
    ).get(windowModifier, contentType, String(contentId), userId);

    if (!row) {
        db.prepare(
            `INSERT INTO account_view_limits (content_type, content_id, user_id, view_count, window_started_at, last_view_at)
             VALUES (?, ?, ?, 1, ?, ?)`
        ).run(contentType, String(contentId), userId, now, now);
        recordViewEvent();
        return { counted: true, limited: false };
    }

    if (Number(row.expired || 0) === 1) {
        db.prepare(
            `UPDATE account_view_limits
             SET view_count = 1, window_started_at = ?, last_view_at = ?
             WHERE id = ?`
        ).run(now, now, row.id);
        recordViewEvent();
        return { counted: true, limited: false };
    }

    if (Number(row.view_count || 0) >= VIEW_HEAT_ACCOUNT_MAX_PER_ITEM) {
        db.prepare('UPDATE account_view_limits SET last_view_at = ? WHERE id = ?').run(now, row.id);
        return { counted: false, limited: true };
    }

    db.prepare(
        `UPDATE account_view_limits
         SET view_count = view_count + 1, last_view_at = ?
         WHERE id = ?`
    ).run(now, row.id);
    recordViewEvent();
    return { counted: true, limited: false };
}

function makeNewApiRewardStats(user, cardHeat = 0, templateHeat = 0) {
    const totalHeat = cardHeat + templateHeat;
    const totalCookies = floorToTwoDecimals(totalHeat / NEWAPI_HEAT_PER_COOKIE);
    const redeemedCookies = floorToTwoDecimals(Math.max(0, Number(user?.newapi_redeemed_cookies ?? user?.redeemed_cookies ?? 0)));
    const penaltyCookies = floorToTwoDecimals(Math.max(0, Number(user?.newapi_penalty_cookies ?? user?.penalty_cookies ?? 0)));
    const availableCookies = floorToTwoDecimals(totalCookies - redeemedCookies - penaltyCookies);
    return {
        newapi_user_id: user?.newapi_user_id || '',
        card_heat: cardHeat,
        template_heat: templateHeat,
        total_heat: totalHeat,
        total_cookies: totalCookies,
        redeemed_cookies: redeemedCookies,
        penalty_cookies: penaltyCookies,
        available_cookies: availableCookies,
        available_quota: Math.round(availableCookies * NEWAPI_QUOTA_PER_COOKIE),
        heat_per_cookie: NEWAPI_HEAT_PER_COOKIE,
        quota_per_cookie: NEWAPI_QUOTA_PER_COOKIE,
        min_redeem_cookies: 1,
        newapi_configured: isNewApiConfigured()
    };
}

function getUsersNewApiRewardStatsMap(userIds) {
    const ids = [...new Set(
        (userIds || [])
            .map((id) => Number(id))
            .filter((id) => Number.isInteger(id) && id > 0)
    )];
    const statsByUser = new Map();
    if (!ids.length) return statsByUser;

    const placeholders = ids.map(() => '?').join(',');
    const users = db.prepare(
        `SELECT id, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies
         FROM users
         WHERE id IN (${placeholders})`
    ).all(...ids);

    for (const id of ids) {
        statsByUser.set(id, makeNewApiRewardStats({ id }, 0, 0));
    }
    for (const user of users) {
        statsByUser.set(Number(user.id), makeNewApiRewardStats(user, 0, 0));
    }

    const cardRows = db.prepare(
        `SELECT uploader_user_id AS user_id, views_count, downloads_count,
                ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
         FROM character_cards
         WHERE uploader_user_id IN (${placeholders}) AND review_status = 'approved'`
    ).all(...ids);
    for (const row of cardRows) {
        const id = Number(row.user_id);
        const current = statsByUser.get(id) || makeNewApiRewardStats({ id }, 0, 0);
        statsByUser.set(id, makeNewApiRewardStats(current, current.card_heat + computeCardHeatFromRow(row), current.template_heat));
    }

    const templateRows = db.prepare(
        `SELECT uploader_user_id AS user_id, views_count, downloads_count,
                ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
         FROM ui_templates
         WHERE uploader_user_id IN (${placeholders}) AND review_status = 'approved'`
    ).all(...ids);
    for (const row of templateRows) {
        const id = Number(row.user_id);
        const current = statsByUser.get(id) || makeNewApiRewardStats({ id }, 0, 0);
        statsByUser.set(id, makeNewApiRewardStats(current, current.card_heat, current.template_heat + computeTemplateHeatFromRow(row)));
    }

    return statsByUser;
}

function getUserNewApiRewardStats(userId) {
    return getUsersNewApiRewardStatsMap([userId]).get(Number(userId)) || makeNewApiRewardStats(null, 0, 0);
}

function getContentCookieValueFromHeatRow(row) {
    if (!row || row.review_status !== 'approved') return 0;
    return floorToTwoDecimals(computeContentHeatFromRow(row) / NEWAPI_HEAT_PER_COOKIE);
}

function addNewApiCookiePenalty(userId, cookies) {
    const id = Number(userId);
    const amount = floorToTwoDecimals(cookies);
    if (!Number.isInteger(id) || id <= 0 || amount <= 0) return;
    db.prepare(
        `UPDATE users
         SET newapi_penalty_cookies = IFNULL(newapi_penalty_cookies, 0) + ?
         WHERE id = ?`
    ).run(amount, id);
}

function maybeSendCardHeatMilestoneEmail(cardId, req) {
    try {
        const row = db.prepare(
            `SELECT cc.id, cc.name, cc.views_count, cc.downloads_count, cc.heat_email_milestone,
                    u.username, u.email, u.email_verified,
                    ${cardCommentHeatCountExpr('cc')} AS comment_heat_count
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ?`
        ).get(cardId);
        if (!row || !userEmailBound(row)) return;

        const heat = computeCardHeatFromRow(row);
        const nextMilestone = Math.floor(heat / HEAT_EMAIL_STEP) * HEAT_EMAIL_STEP;
        const lastMilestone = Number(row.heat_email_milestone || 0);
        if (nextMilestone < HEAT_EMAIL_STEP || nextMilestone <= lastMilestone) return;

        const updated = db.prepare(
            'UPDATE character_cards SET heat_email_milestone = ? WHERE id = ? AND IFNULL(heat_email_milestone, 0) < ?'
        ).run(nextMilestone, cardId, nextMilestone);
        if (updated.changes === 0) return;

        sendResendEmailQuietly({
            to: row.email,
            subject: `你的角色卡热度达到 ${nextMilestone}`,
            html: `<p>${escapeHtml(row.username)}，你的角色卡「${escapeHtml(row.name)}」热度已经达到 ${nextMilestone}。</p><p>当前热度：${heat}</p>`,
            text: `${row.username}，你的角色卡「${row.name}」热度已经达到 ${nextMilestone}。\n当前热度：${heat}`
        });
    } catch (err) {
        console.error('[Email] Heat milestone check failed:', err.message);
    }
}

// ============== Auth Routes ==============
app.post('/api/auth/login', (req, res) => {
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: '请输入管理员密码' });
    }

    const ip = getRequestIp(req);
    const username = 'admin';

    // Brute force protection for admin login
    const bruteCheck = checkBruteForce(ip, username);
    if (bruteCheck.blocked) {
        return res.status(429).json({ error: bruteCheck.reason });
    }

    if (!validateAdminPassword(password)) {
        recordLoginAttempt(ip, username, false);
        return res.status(401).json({ error: '管理员密码错误' });
    }

    const user = db.prepare('SELECT id, username, token_version FROM admin_users ORDER BY id LIMIT 1').get();
    if (!user) {
        return res.status(500).json({ error: '管理员账号未初始化' });
    }

    // Success
    recordLoginAttempt(ip, username, true);
    db.prepare('UPDATE admin_users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
    logOperation({ userType: 'admin', userId: user.id, username: user.username, action: 'admin_login', targetType: 'user', targetId: String(user.id), ip, details: { role: 'admin' } });

    const token = generateAdminToken(user);
    setAdminAuthCookie(res, token);
    res.json({ user: { id: user.id, username: user.username } });
});

app.get('/api/auth/me', authenticateAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ user: req.admin });
});

app.post('/api/auth/logout', (req, res) => {
    clearAdminAuthCookie(res);
    res.json({ success: true });
});

// ============== User Registration & Login ==============
app.post('/api/email/send-code', async (req, res) => {
    try {
        cleanupEmailCodes();
        const purpose = String(req.body.purpose || '').trim();
        const emailCheck = validateQqEmail(req.body.email);
        const email = emailCheck.email;
        const turnstileToken = String(req.body.turnstileToken || '').trim();
        if (!['register', 'bind', 'reset_password'].includes(purpose)) {
            return res.status(400).json({ error: '验证码用途无效' });
        }
        if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

        let userId = null;
        if (purpose === 'register') {
            const existingEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
            if (existingEmail) return res.status(409).json({ error: '这个邮箱已经注册过了' });

            const username = String(req.body.username || '').trim();
            if (username) {
                const existingUsername = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
                if (existingUsername) return res.status(409).json({ error: '用户名已存在' });
            }
        } else if (purpose === 'bind') {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: '请先登录' });
            }
            const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            const existingEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(email, user.id);
            if (existingEmail) return res.status(409).json({ error: '这个邮箱已经被其他账号绑定' });
            userId = user.id;
        } else if (purpose === 'reset_password') {
            const user = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND email_verified = 1').get(email);
            if (!user) return res.status(404).json({ error: '没有找到绑定这个邮箱的账号' });
            userId = user.id;
        }

        const cooldown = getEmailCodeCooldown({ email, purpose, userId });
        if (cooldown > 0) {
            return res.status(429).json({
                error: `请 ${cooldown} 秒后再发送验证码`,
                cooldown_seconds: cooldown
            });
        }

        const requestIp = getRequestIp(req);
        const ipRetryAfter = getEmailCodeIpRetryAfter(requestIp);
        if (ipRetryAfter > 0) {
            return res.status(429).json({
                error: `这个网络发送邮件太频繁，请 ${ipRetryAfter} 秒后再试`,
                retry_after_seconds: ipRetryAfter
            });
        }

        await verifyTurnstileToken(turnstileToken, requestIp);

        const { code } = createEmailCode({ email, purpose, userId, ip: requestIp });
        await sendVerificationCodeEmail({ email, code, purpose });
        res.json({
            success: true,
            message: `验证码已发送到 ${maskEmail(email)}，${EMAIL_CODE_TTL_MINUTES} 分钟内有效`,
            cooldown_seconds: EMAIL_CODE_COOLDOWN_SECONDS
        });
    } catch (err) {
        console.error('Send email code error:', err);
        res.status(err.statusCode || 500).json({ error: err.message || '发送验证码失败' });
    }
});

app.post('/api/user/register', async (req, res) => {
    try {
        const { username, password, emailCode } = req.body;
        const emailCheck = validateQqEmail(req.body.email);
        const email = emailCheck.email;

        if (!username || !password || !email) {
            return res.status(400).json({ error: '请输入用户名、邮箱和密码' });
        }
        if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });
        const normalizedUsername = String(username || '').trim();
        if (normalizedUsername.length < 2 || normalizedUsername.length > 20) {
            return res.status(400).json({ error: '用户名长度需为2-20个字符' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: '密码长度至少6个字符' });
        }

        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(normalizedUsername);
        if (existing) {
            return res.status(409).json({ error: '用户名已存在' });
        }
        const existingEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
        if (existingEmail) {
            return res.status(409).json({ error: '这个邮箱已经注册过了' });
        }

        const codeCheck = verifyEmailCode({ email, purpose: 'register', userId: null, code: emailCode });
        if (!codeCheck.ok) return res.status(400).json({ error: codeCheck.error });

        const hash = await bcrypt.hash(password, 12);
        const now = new Date().toISOString();
        const result = db.prepare(
            'INSERT INTO users (username, email, email_verified, password_hash, download_credits, comment_email_notifications, last_login) VALUES (?, ?, 1, ?, ?, 1, ?)'
        ).run(normalizedUsername, email, hash, REGISTRATION_DOWNLOAD_CREDITS, now);

        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
        logOperation({ userType: 'user', userId: user.id, username: user.username, action: 'register', targetType: 'user', targetId: String(user.id), ip: getRequestIp(req) });
        const token = generateUserToken(user);
        res.json({ token, user: buildUserResponse(user) });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: '注册失败' });
    }
});

app.post('/api/user/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const ip = getRequestIp(req);
    try {
        await verifyTurnstileToken(String(req.body.turnstileToken || '').trim(), ip, 'user_login');
    } catch (err) {
        return res.status(err.statusCode || 500).json({ error: err.message || '安全验证失败' });
    }
    const loginRate = checkUserLoginRate(ip, username);
    if (loginRate.blocked) {
        res.set('Retry-After', String(loginRate.retryAfter));
        return res.status(429).json({ error: loginRate.reason });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }
    if (user.is_banned) {
        return res.status(403).json({ error: user.ban_reason ? `账号已被封禁：${user.ban_reason}` : '账号已被封禁' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
    logOperation({ userType: 'user', userId: user.id, username: user.username, action: 'login', targetType: 'user', targetId: String(user.id), ip });

    const token = generateUserToken(user);
    res.json({ 
        token, 
        user: buildUserResponse(user)
    });
});

app.get('/api/user/me', authenticateUserAllowUnbound, (req, res) => {
    res.set('Cache-Control', 'no-store');
    markPerf(req, 'user-me-start', { userId: req.user.id });
    const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
    markPerf(req, 'user-me-db-read', { found: Boolean(user) });
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json({ user: buildUserResponse(user) });
    markPerf(req, 'user-me-response-json');
});

app.put('/api/user/preferences', authenticateUser, (req, res) => {
    try {
        const commentEmailNotifications = req.body.comment_email_notifications === true
            || req.body.comment_email_notifications === 1
            || req.body.comment_email_notifications === '1'
            || req.body.comment_email_notifications === 'true';
        db.prepare('UPDATE users SET comment_email_notifications = ? WHERE id = ?')
            .run(commentEmailNotifications ? 1 : 0, req.user.id);
        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
        logOperation({
            userType: 'user',
            userId: req.user.id,
            username: req.user.username,
            action: 'update_user_preferences',
            targetType: 'user',
            targetId: String(req.user.id),
            ip: getRequestIp(req),
            details: { comment_email_notifications: commentEmailNotifications }
        });
        res.json({ success: true, user: buildUserResponse(user) });
    } catch (err) {
        console.error('Update user preferences error:', err);
        res.status(500).json({ error: '保存个人设置失败' });
    }
});

app.post('/api/user/bind-email', authenticateUserAllowUnbound, (req, res) => {
    try {
        const emailCheck = validateQqEmail(req.body.email);
        const email = emailCheck.email;
        const emailCode = String(req.body.emailCode || '').trim();
        if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

        const existingEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(email, req.user.id);
        if (existingEmail) return res.status(409).json({ error: '这个邮箱已经被其他账号绑定' });

        const codeCheck = verifyEmailCode({ email, purpose: 'bind', userId: req.user.id, code: emailCode });
        if (!codeCheck.ok) return res.status(400).json({ error: codeCheck.error });

        db.prepare('UPDATE users SET email = ?, email_verified = 1, token_version = token_version + 1 WHERE id = ?').run(email, req.user.id);
        const updated = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
        logOperation({ userType: 'user', userId: req.user.id, username: req.user.username, action: 'bind_email', targetType: 'user', targetId: String(req.user.id), ip: getRequestIp(req), details: { email: maskEmail(email) } });
        const token = generateUserToken(updated);
        res.json({ success: true, token, user: buildUserResponse(updated) });
    } catch (err) {
        console.error('Bind email error:', err);
        res.status(500).json({ error: '绑定邮箱失败' });
    }
});

app.post('/api/user/forgot-password/reset', async (req, res) => {
    try {
        const emailCheck = validateQqEmail(req.body.email);
        const email = emailCheck.email;
        const emailCode = String(req.body.emailCode || '').trim();
        const newPassword = String(req.body.newPassword || '');
        if (!email || !emailCode || !newPassword) {
            return res.status(400).json({ error: '请输入邮箱、验证码和新密码' });
        }
        if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });
        if (newPassword.length < 6) {
            return res.status(400).json({ error: '新密码长度至少6位' });
        }
        const user = db.prepare('SELECT id, username FROM users WHERE email = ? COLLATE NOCASE AND email_verified = 1').get(email);
        if (!user) return res.status(404).json({ error: '没有找到绑定这个邮箱的账号' });

        const codeCheck = verifyEmailCode({ email, purpose: 'reset_password', userId: user.id, code: emailCode });
        if (!codeCheck.ok) return res.status(400).json({ error: codeCheck.error });

        const hash = await bcrypt.hash(newPassword, 12);
        db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?').run(hash, user.id);
        logOperation({ userType: 'user', userId: user.id, username: user.username, action: 'reset_password_by_email', targetType: 'user', targetId: String(user.id), ip: getRequestIp(req) });
        res.json({ success: true });
    } catch (err) {
        console.error('Forgot password reset error:', err);
        res.status(500).json({ error: '重置密码失败' });
    }
});

app.get('/api/user/newapi/reward', authenticateUser, (req, res) => {
    try {
        res.json(getUserNewApiRewardStats(req.user.id));
    } catch (err) {
        console.error('New API reward status error:', err);
        res.status(500).json({ error: '获取可兑换额度失败' });
    }
});

app.put('/api/user/newapi/bind', authenticateUser, (req, res) => {
    try {
        const rawId = String(req.body.newapi_user_id || '').trim();
        if (!/^\d{1,18}$/.test(rawId)) {
            return res.status(400).json({ error: '请输入有效的 STA1N API 用户 ID' });
        }
        const current = db.prepare('SELECT newapi_user_id FROM users WHERE id = ?').get(req.user.id);
        if (current?.newapi_user_id && current.newapi_user_id !== rawId) {
            return res.status(409).json({ error: '请先解绑当前 STA1N API 用户 ID，再绑定新的 ID' });
        }
        const existing = db.prepare('SELECT id FROM users WHERE newapi_user_id = ? AND id != ?').get(rawId, req.user.id);
        if (existing) {
            return res.status(409).json({ error: '这个 STA1N API 用户 ID 已被其他账号绑定' });
        }
        db.prepare('UPDATE users SET newapi_user_id = ? WHERE id = ?').run(rawId, req.user.id);
        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
        logOperation({
            userType: 'user',
            userId: req.user.id,
            username: req.user.username,
            action: 'bind_newapi_user',
            targetType: 'user',
            targetId: String(req.user.id),
            ip: getRequestIp(req),
            details: { newapi_user_id: rawId }
        });
        res.json({ success: true, user: buildUserResponse(user), reward: getUserNewApiRewardStats(req.user.id) });
    } catch (err) {
        console.error('Bind New API user error:', err);
        res.status(500).json({ error: '绑定 STA1N API 用户 ID 失败' });
    }
});

app.delete('/api/user/newapi/bind', authenticateUser, (req, res) => {
    try {
        const current = db.prepare('SELECT newapi_user_id FROM users WHERE id = ?').get(req.user.id);
        if (!current?.newapi_user_id) {
            const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
            return res.json({ success: true, user: buildUserResponse(user), reward: getUserNewApiRewardStats(req.user.id) });
        }
        db.prepare("UPDATE users SET newapi_user_id = '' WHERE id = ?").run(req.user.id);
        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, newapi_penalty_cookies, comment_email_notifications, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
        logOperation({
            userType: 'user',
            userId: req.user.id,
            username: req.user.username,
            action: 'unbind_newapi_user',
            targetType: 'user',
            targetId: String(req.user.id),
            ip: getRequestIp(req),
            details: { newapi_user_id: current.newapi_user_id }
        });
        res.json({ success: true, user: buildUserResponse(user), reward: getUserNewApiRewardStats(req.user.id) });
    } catch (err) {
        console.error('Unbind STA1N API user error:', err);
        res.status(500).json({ error: '解绑 STA1N API 用户 ID 失败' });
    }
});

app.post('/api/user/newapi/redeem', authenticateUser, async (req, res) => {
    let reservation = null;
    try {
        const requestedCookies = parseCookieAmount(req.body.cookies);
        if (requestedCookies === null) {
            return res.status(400).json({ error: '提现数量最多支持 2 位小数' });
        }
        if (requestedCookies < 1) {
            return res.status(400).json({ error: '最少提现 1🍪' });
        }
        if (!isNewApiConfigured()) {
            return res.status(400).json({ error: 'STA1N API 未配置，请联系管理员' });
        }

        const reserve = db.transaction(() => {
            const user = db.prepare('SELECT id, username, newapi_user_id, newapi_redeemed_cookies FROM users WHERE id = ?').get(req.user.id);
            if (!user) throw new Error('用户不存在');
            if (!user.newapi_user_id) throw new Error('请先绑定 STA1N API 用户 ID');
            const stats = getUserNewApiRewardStats(req.user.id);
            if (stats.available_cookies < 1) throw new Error('当前还没有可提现的 🍪');
            if (requestedCookies > stats.available_cookies) throw new Error(`最多可提现 ${stats.available_cookies.toFixed(2)}🍪`);

            const quota = Math.round(requestedCookies * NEWAPI_QUOTA_PER_COOKIE);
            const heatUsed = floorToTwoDecimals(requestedCookies * NEWAPI_HEAT_PER_COOKIE);
            const redemptionId = generateId();
            db.prepare(
                `UPDATE users
                 SET newapi_redeemed_cookies = IFNULL(newapi_redeemed_cookies, 0) + ?
                 WHERE id = ?`
            ).run(requestedCookies, req.user.id);
            db.prepare(
                `INSERT INTO newapi_redemptions
                 (id, user_id, newapi_user_id, cookies, quota, heat_used, status)
                 VALUES (?, ?, ?, ?, ?, ?, 'pending')`
            ).run(redemptionId, req.user.id, user.newapi_user_id, requestedCookies, quota, heatUsed);
            return { redemptionId, newapiUserId: user.newapi_user_id, cookies: requestedCookies, quota, heatUsed };
        });

        reservation = reserve();
        const newApiResult = await addNewApiQuota(reservation.newapiUserId, reservation.quota);
        db.prepare(
            `UPDATE newapi_redemptions
             SET status = 'success', quota_before = ?, quota_after = ?, completed_at = ?
             WHERE id = ?`
        ).run(newApiResult.quotaBefore, newApiResult.quotaAfter, new Date().toISOString(), reservation.redemptionId);
        logOperation({
            userType: 'user',
            userId: req.user.id,
            username: req.user.username,
            action: 'newapi_redeem',
            targetType: 'user',
            targetId: String(req.user.id),
            ip: getRequestIp(req),
            details: {
                newapi_user_id: reservation.newapiUserId,
                cookies: reservation.cookies,
                quota: reservation.quota,
                quota_before: newApiResult.quotaBefore,
                quota_after: newApiResult.quotaAfter
            }
        });
        if (userEmailBound(req.user)) {
            sendNewApiRedemptionSuccessEmail({
                to: req.user.email,
                username: req.user.username,
                cookies: reservation.cookies,
                newApiUserId: reservation.newapiUserId
            });
        }
        res.json({
            success: true,
            cookies: reservation.cookies,
            quota: reservation.quota,
            quota_before: newApiResult.quotaBefore,
            quota_after: newApiResult.quotaAfter,
            reward: getUserNewApiRewardStats(req.user.id)
        });
    } catch (err) {
        if (reservation) {
            try {
                db.prepare(
                    `UPDATE users
                     SET newapi_redeemed_cookies = MAX(0, IFNULL(newapi_redeemed_cookies, 0) - ?)
                     WHERE id = ?`
                ).run(reservation.cookies, req.user.id);
                db.prepare(
                    `UPDATE newapi_redemptions
                     SET status = 'failed', error = ?, completed_at = ?
                     WHERE id = ?`
                ).run(String(err.message || '兑换失败').slice(0, 500), new Date().toISOString(), reservation.redemptionId);
            } catch (rollbackErr) {
                console.error('New API redemption rollback error:', rollbackErr);
            }
        }
        console.error('New API redeem error:', err);
        res.status(reservation ? 502 : 400).json({ error: err.message || '提现失败' });
    }
});

// ============== Card Routes (Public) ==============
function generateId() {
    return crypto.randomUUID();
}

function stableStringify(obj) {
    if (obj === null || obj === undefined) return String(obj);
    if (typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

function hashCardData(data) {
    if (!data) return null;
    return crypto.createHash('sha256').update(stableStringify(data)).digest('hex');
}

function parseStoredCardData(data) {
    if (!data) return null;
    if (typeof data === 'object') return data;
    try {
        return JSON.parse(data);
    } catch {
        return null;
    }
}

function clonePlainObject(value) {
    if (!value || typeof value !== 'object') return {};
    try {
        return JSON.parse(JSON.stringify(value));
    } catch {
        return { ...value };
    }
}

function isEmbeddedAvatarPayload(value) {
    if (typeof value !== 'string') return false;
    const normalized = value.trim();
    if (!normalized) return false;
    if (/^data:/i.test(normalized)) return true;
    if (/^(blob|file):/i.test(normalized)) return true;
    return /\/api\/cards\/[^/?#]+\/(?:avatar|thumbnail|preview-image)(?:[?#].*)?$/i.test(normalized);
}

function stripEmbeddedAvatarPayloadsFromContent(content) {
    if (!content || typeof content !== 'object') return false;
    let changed = false;
    for (const key of ['avatar', 'avatar_url']) {
        if (isEmbeddedAvatarPayload(content[key])) {
            delete content[key];
            changed = true;
        }
    }
    return changed;
}

function sanitizeCardDataForStorage(rawData) {
    const parsed = parseStoredCardData(rawData);
    if (!parsed || typeof parsed !== 'object') {
        return { value: parsed ?? rawData ?? null, changed: false };
    }

    const cloned = clonePlainObject(parsed);
    const content = cloned.data && typeof cloned.data === 'object' && !Array.isArray(cloned.data)
        ? cloned.data
        : cloned;
    const changed = stripEmbeddedAvatarPayloadsFromContent(content);
    return { value: cloned, changed };
}

function getCharacterDisplayName(content = {}) {
    return content.name || content.char_name || 'Character';
}

function applyCardDisplayMacros(text, content = {}) {
    if (!text) return '';
    return String(text).replace(/\{\{char\}\}/gi, getCharacterDisplayName(content));
}

function applyCardRegexScripts(text, content = {}, raw = {}) {
    if (!text) return '';

    const charName = getCharacterDisplayName(content);
    const protectedSegmentPattern = /(<!DOCTYPE html>[\s\S]*?<\/html>|<html\b[^>]*>[\s\S]*?<\/html>|<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>|```[\s\S]*?```|`[^`]+`|<\/?[a-zA-Z][\w:-]*[^>]*>)/gi;
    const protectedSegmentExactPattern = /^(<!DOCTYPE html>[\s\S]*?<\/html>|<html\b[^>]*>[\s\S]*?<\/html>|<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>|```[\s\S]*?```|`[^`]+`|<\/?[a-zA-Z][\w:-]*[^>]*>)$/i;
    const replaceOutsideProtectedSegments = (source, regex, replacement) => {
        return String(source || '').split(protectedSegmentPattern).map(part => {
            if (!part || protectedSegmentExactPattern.test(part)) return part;
            return part.replace(regex, replacement);
        }).join('');
    };

    const htmlDocPattern = /(<!doctype html>|<html\b[^>]*>)/i;
    const htmlMatch = String(text).trim().match(htmlDocPattern);
    let protectedHtml = '';
    let hasProtectedHtml = false;
    let preText = '';
    let postText = '';

    if (htmlMatch) {
        const startIndex = String(text).indexOf(htmlMatch[0]);
        const closeTag = '</html>';
        const closeIndex = String(text).toLowerCase().lastIndexOf(closeTag);
        if (closeIndex !== -1 && closeIndex > startIndex) {
            const endIndex = closeIndex + closeTag.length;
            protectedHtml = String(text).substring(startIndex, endIndex).replace(/\{\{char\}\}/gi, charName);
            preText = String(text).substring(0, startIndex);
            postText = String(text).substring(endIndex);
            hasProtectedHtml = true;
        }
    }

    let result = hasProtectedHtml ? `${preText}___HTML_BLOCK_PLACEHOLDER___${postText}` : String(text);
    result = result.replace(/\{\{char\}\}/gi, charName);

    const scripts =
        content.extensions?.regex_scripts
        || raw.extensions?.regex_scripts
        || content.regex_scripts
        || raw.regex_scripts
        || content.data?.extensions?.regex_scripts
        || null;

    if (scripts) {
        const scriptList = Array.isArray(scripts) ? scripts : Object.values(scripts);
        scriptList.forEach(script => {
            try {
                if (!script || script.disabled === true || script.promptOnly) return;
                let regexPattern = script.regex || script.findRegex;
                let flags = script.flags || script.regexFlags || 'g';
                const replacement = Object.prototype.hasOwnProperty.call(script, 'replacement')
                    ? script.replacement
                    : (script.replaceString || '');
                if (!regexPattern) return;

                if (typeof regexPattern === 'string' && regexPattern.startsWith('/') && regexPattern.lastIndexOf('/') > 0) {
                    const lastSlash = regexPattern.lastIndexOf('/');
                    const potentialFlags = regexPattern.substring(lastSlash + 1);
                    if (/^[gimsuy]*$/.test(potentialFlags)) {
                        flags = potentialFlags;
                        regexPattern = regexPattern.substring(1, lastSlash);
                    }
                }

                [
                    ['(?s)', 's'],
                    ['(?i)', 'i'],
                    ['(?m)', 'm']
                ].forEach(([modifier, flag]) => {
                    if (typeof regexPattern === 'string' && regexPattern.includes(modifier)) {
                        regexPattern = regexPattern.split(modifier).join('');
                        if (!String(flags).includes(flag)) flags += flag;
                    }
                });

                flags = Array.from(new Set(String(flags || 'g').split(''))).join('');
                const re = new RegExp(regexPattern, flags);
                const shouldProtectHtml = typeof regexPattern === 'string' && !/[<>]/.test(regexPattern) && !regexPattern.includes('```');
                result = shouldProtectHtml
                    ? replaceOutsideProtectedSegments(result, re, replacement)
                    : result.replace(re, replacement);
            } catch (err) {
                console.warn('[CardDetailPreview] regex script skipped:', err.message);
            }
        });
    }

    if (hasProtectedHtml) {
        result = result.replace('___HTML_BLOCK_PLACEHOLDER___', protectedHtml);
    }

    return result;
}

function getCardUiTemplateMarkup(template) {
    const candidates = [
        template?.htmlTemplate,
        template?.template,
        template?.html,
        template?.content,
        template?.markup
    ];
    return candidates.find(item => typeof item === 'string' && item.trim()) || '';
}

function normalizeCardUiTemplatePreviewItem(template, index, options = {}) {
    const html = getCardUiTemplateMarkup(template);
    if (!html) return null;
    const fallbackName = options.fallbackName || 'UI模板';
    const fallbackVariables = options.fallbackVariables || {};
    const idPrefix = options.idPrefix || 'embedded-ui';
    return {
        ...template,
        id: template.id || `${idPrefix}-${index + 1}`,
        name: template.name || template.title || `${fallbackName} ${index + 1}`,
        htmlTemplate: stripTemplateCodeFence(String(html)),
        initialVariableState: clonePlainObject(
            template.initialVariableState
            || template.initialVariables
            || template.variables
            || template.variableState
            || template.previewData
            || template.sampleData
            || fallbackVariables
            || {}
        ),
        order: Number.isFinite(Number(template.order)) ? Number(template.order) : 100
    };
}

function collectCardUiTemplateList(value) {
    if (!value) return [];
    if (typeof value === 'string') {
        try {
            return collectCardUiTemplateList(JSON.parse(stripTemplateCodeFence(value)));
        } catch {
            return [];
        }
    }
    if (Array.isArray(value)) return value;
    if (Array.isArray(value.templates)) return value.templates;
    if (Array.isArray(value.uiTemplates)) return value.uiTemplates;
    if (Array.isArray(value.ui_templates)) return value.ui_templates;
    return [];
}

function extractCardUiTemplatePreviewItems(sources = [], options = {}) {
    const seen = new Set();
    const templates = [];
    const addTemplate = (template) => {
        const normalized = normalizeCardUiTemplatePreviewItem(template, templates.length, options);
        if (!normalized) return;
        const key = template.id || `${normalized.name || ''}:${String(normalized.htmlTemplate).slice(0, 120)}`;
        if (seen.has(key)) return;
        seen.add(key);
        templates.push(normalized);
    };
    const visit = (candidate) => {
        if (!candidate) return;
        if (typeof candidate === 'string') {
            const cleaned = stripTemplateCodeFence(candidate);
            try {
                visit(JSON.parse(cleaned));
            } catch {
                if (/<[a-z][\s\S]*>/i.test(cleaned)) addTemplate({ htmlTemplate: cleaned });
            }
            return;
        }
        if (Array.isArray(candidate)) {
            candidate.forEach(visit);
            return;
        }
        if (getCardUiTemplateMarkup(candidate)) addTemplate(candidate);
        collectCardUiTemplateList(candidate).forEach(addTemplate);
    };
    sources.forEach(visit);
    return templates.sort((a, b) => (b.order || 0) - (a.order || 0));
}

function extractCardEmbeddedUiTemplates(rawData = {}) {
    const content = rawData?.data || rawData || {};
    const candidates = [
        content.uiTemplates,
        content.ui_templates,
        rawData.uiTemplates,
        rawData.ui_templates,
        content.extensions?.uiTemplates,
        content.extensions?.ui_templates,
        content.extensions?.rp_hub_ui_templates,
        rawData.extensions?.uiTemplates,
        rawData.extensions?.ui_templates,
        rawData.extensions?.rp_hub_ui_templates
    ];
    return extractCardUiTemplatePreviewItems(candidates, {
        fallbackName: 'UI模板',
        idPrefix: 'embedded-ui'
    });
}

function buildCardDetailPreview(rawData, fallback = {}) {
    const raw = parseStoredCardData(rawData) || {};
    const content = raw.data || raw || {};
    const sourceDescription = fallback.description || content.description || content.char_persona || '';
    return {
        version: 1,
        detail_ready: true,
        name: fallback.name || content.name || content.char_name || '',
        description: applyCardDisplayMacros(sourceDescription, content),
        personality: applyCardDisplayMacros(content.personality || '', content),
        first_mes: applyCardRegexScripts(content.first_mes || '', content, raw),
        uiTemplates: extractCardEmbeddedUiTemplates(raw)
    };
}

function buildCardDetailPreviewJson(rawData, fallback = {}) {
    try {
        return JSON.stringify(buildCardDetailPreview(rawData, fallback));
    } catch (err) {
        console.warn('[CardDetailPreview] build failed:', err.message);
        return JSON.stringify({
            version: 1,
            detail_ready: true,
            name: fallback.name || '',
            description: fallback.description || '',
            personality: '',
            first_mes: '',
            uiTemplates: []
        });
    }
}

let aiReviewWorkerRunning = false;
let aiReviewWorkerTimer = null;

function buildAiReviewText(card) {
    const raw = parseStoredCardData(card?.data) || {};
    const content = raw.data && typeof raw.data === 'object' ? raw.data : raw;
    const clip = (value, maxLength) => String(value || '').trim().slice(0, maxLength);
    const greetings = [
        content.first_mes,
        ...(Array.isArray(content.alternate_greetings) ? content.alternate_greetings : [])
    ].filter(value => typeof value === 'string' && value.trim());
    const worldBookSources = [
        content.character_book,
        content.world_book,
        content.lorebook,
        content.extensions?.character_book,
        content.extensions?.world_book,
        content.extensions?.lorebook,
        raw.character_book,
        raw.world_book,
        raw.lorebook
    ];
    const worldBook = worldBookSources
        .map(source => Array.isArray(source) ? source : source?.entries)
        .find(entries => Array.isArray(entries) && entries.length) || [];
    const worldBookText = worldBook.slice(0, 3).map((entry, index) => {
        const title = entry?.comment || entry?.name || entry?.title || `世界书 ${index + 1}`;
        const keys = Array.isArray(entry?.keys) ? entry.keys.filter(Boolean).join('、') : '';
        const body = entry?.content ?? entry?.text ?? entry?.value ?? '';
        return [
            `第 ${index + 1} 条：${clip(title, 300)}`,
            keys ? `关键词：${clip(keys, 500)}` : '',
            `内容：${clip(body, 3000)}`
        ].filter(Boolean).join('\n');
    }).join('\n\n');
    return [
        `角色卡名称：${clip(card?.name || content.name || content.char_name, 500)}`,
        `简介：${clip(card?.creator_notes || content.creator_notes, 5000)}`,
        `描述：${clip(card?.description || content.description || content.char_persona, 8000)}`,
        `开场白：\n${clip(greetings.join('\n\n--- 其他开场白 ---\n'), 10000)}`,
        `世界书（最多前 3 条）：\n${worldBookText || '无'}`
    ].join('\n\n').slice(0, AI_REVIEW_MAX_TEXT_LENGTH);
}

async function buildAiReviewCoverImage(card) {
    const avatarUrl = sanitizeAvatarUrl(card?.avatar_url, card?.id);
    if (!avatarUrl) return '';
    const asset = await resolveAvatarAsset(avatarUrl);
    if (!asset?.buffer?.length) return '';
    if (sharp) {
        const cover = await sharp(asset.buffer)
            .rotate()
            .resize({ width: 768, height: 768, fit: 'inside', withoutEnlargement: true })
            .jpeg({ quality: 78 })
            .toBuffer();
        return `data:image/jpeg;base64,${cover.toString('base64')}`;
    }
    if (!String(asset.contentType || '').toLowerCase().startsWith('image/')) {
        throw new Error('封面不是可识别的图片格式');
    }
    return `data:${asset.contentType};base64,${Buffer.from(asset.buffer).toString('base64')}`;
}

function parseAiReviewResponse(payload, { rejectOnEmpty = false, emptyReason = '', requireDecision = false } = {}) {
    const content = payload?.choices?.[0]?.message?.content;
    const text = typeof content === 'string'
        ? content
        : (Array.isArray(content) ? content.map(item => item?.text || '').join('') : '');
    if (!text.trim()) {
        return rejectOnEmpty
            ? { decision: 'REJECT', reason: emptyReason || '审核模型返回空内容，审核不通过' }
            : { decision: 'ALLOW', reason: 'AI 返回空内容，按规则放行' };
    }
    const cleaned = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
    const jsonStart = cleaned.indexOf('{');
    const jsonEnd = cleaned.lastIndexOf('}');
    if (jsonStart < 0 || jsonEnd <= jsonStart) {
        return requireDecision
            ? { decision: 'REJECT', reason: '封面审核模型未返回有效审核结果，审核不通过' }
            : { decision: 'ALLOW', reason: 'AI 返回格式无法确认，按规则放行' };
    }
    try {
        const result = JSON.parse(cleaned.slice(jsonStart, jsonEnd + 1));
        const decision = String(result.decision || '').trim().toUpperCase();
        if (requireDecision && !['ALLOW', 'REJECT'].includes(decision)) {
            return { decision: 'REJECT', reason: '封面审核模型未给出明确结论，审核不通过' };
        }
        if (decision !== 'REJECT') {
            return { decision: 'ALLOW', reason: String(result.reason || '未明确判定违规').slice(0, 500) };
        }
        const certain = result.certain === true || String(result.certain || '').trim().toLowerCase() === 'true';
        if (!certain) {
            return { decision: 'ALLOW', reason: String(result.reason || 'AI 未明确确认违规，按规则放行').slice(0, 500) };
        }
        const category = String(result.category || '').trim().toLowerCase();
        if (!['political', 'violence', 'extreme_violence', 'deceased_public_figure', 'public_figure_mockery', 'explicit_genitals'].includes(category)) {
            return { decision: 'ALLOW', reason: '拒绝类别不在规则范围内，按规则放行' };
        }
        const fallbackReasons = {
            political: '包含政治敏感内容',
            violence: '包含暴力或犯罪内容',
            extreme_violence: '包含重口或极端暴力内容',
            deceased_public_figure: '包含以逝世公众人物取乐的内容',
            public_figure_mockery: '包含以公众人物取乐的内容',
            explicit_genitals: '封面露点或清晰出现性器官'
        };
        return {
            decision: 'REJECT',
            reason: String(result.reason || fallbackReasons[category]).slice(0, 500)
        };
    } catch {
        return requireDecision
            ? { decision: 'REJECT', reason: '封面审核模型返回内容无法解析，审核不通过' }
            : { decision: 'ALLOW', reason: 'AI 返回内容无法解析，按规则放行' };
    }
}

async function requestAiReviewCompletion(config, { model, systemPrompt, userContent, rejectOnEmpty = false, emptyReason = '', requireDecision = false }) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), AI_REVIEW_TIMEOUT_MS);
    try {
        const response = await fetch(`${config.baseUrl}/chat/completions`, {
            method: 'POST',
            signal: controller.signal,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${config.apiKey}`
            },
            body: JSON.stringify({
                model,
                temperature: 0,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userContent }
                ]
            })
        });
        const body = await response.text();
        if (!response.ok) {
            throw new Error(`AI 接口返回 ${response.status}: ${body.slice(0, 200)}`);
        }
        let payload;
        try {
            payload = JSON.parse(body);
        } catch {
            throw new Error('AI 接口返回了无效 JSON');
        }
        return parseAiReviewResponse(payload, { rejectOnEmpty, emptyReason, requireDecision });
    } finally {
        clearTimeout(timeout);
    }
}

async function requestAiCardReview(card, config) {
    const outputRule = '只输出 JSON：{"decision":"ALLOW或REJECT","certain":true或false,"category":"none、political、violence、extreme_violence、deceased_public_figure、public_figure_mockery或explicit_genitals","reason":"简短中文理由"}。只有完全确定时 certain 才能为 true。';
    const textPromise = requestAiReviewCompletion(config, {
        model: config.model,
        systemPrompt: `${config.textPrompt}\n${outputRule}`,
        userContent: buildAiReviewText(card)
    });
    let coverImage = '';
    let coverBuildError = null;
    try {
        coverImage = await buildAiReviewCoverImage(card);
    } catch (err) {
        coverBuildError = err;
    }
    const coverPromise = coverImage
        ? requestAiReviewCompletion(config, {
            model: config.visionModel,
            systemPrompt: `${config.coverPrompt}\n${outputRule}`,
            userContent: [
                { type: 'text', text: '请审核这张角色卡封面。' },
                { type: 'image_url', image_url: { url: coverImage } }
            ],
            rejectOnEmpty: true,
            emptyReason: '封面审核模型返回空内容，审核不通过',
            requireDecision: true
        })
        : (coverBuildError
            ? Promise.reject(coverBuildError)
            : Promise.resolve({ decision: 'REJECT', reason: '角色卡没有可审核的封面，封面审核不通过' }));
    const [textSettled, coverSettled] = await Promise.allSettled([textPromise, coverPromise]);
    const textResult = textSettled.status === 'fulfilled'
        ? textSettled.value
        : {
            decision: 'ALLOW',
            reason: '内容审核接口失败，按规则自动放行',
            error: textSettled.reason?.message || String(textSettled.reason || '未知错误')
        };
    const coverResult = coverSettled.status === 'fulfilled'
        ? coverSettled.value
        : {
            decision: 'ALLOW',
            reason: '封面审核接口失败，按规则自动放行',
            error: coverSettled.reason?.message || String(coverSettled.reason || '未知错误')
        };
    const rejected = [textResult, coverResult].filter(result => result.decision === 'REJECT');
    const errors = [
        textResult.error ? `内容审核：${textResult.error}` : '',
        coverResult.error ? `封面审核：${coverResult.error}` : ''
    ].filter(Boolean);
    return {
        decision: rejected.length ? 'REJECT' : 'ALLOW',
        reason: rejected.length
            ? rejected.map(result => result.reason).join('；')
            : `内容审核：${textResult.reason}；封面审核：${coverResult.reason}`,
        error: errors.join('\n'),
        text: textResult,
        cover: coverResult
    };
}

function completeAiReviewJob(job, { decision, reason, error = '', model = '', text: textResult = {}, cover: coverResult = {} }) {
    const now = new Date().toISOString();
    const shouldReject = decision === 'REJECT';
    const nextStatus = shouldReject ? 'rejected' : 'unreviewed';
    const queueStatus = shouldReject ? 'rejected' : 'allowed';
    const update = db.prepare(
        `UPDATE character_cards
         SET review_status = ?, rejection_reason = ?, reviewed_at = ?
         WHERE id = ? AND review_status = 'ai_pending'`
    ).run(nextStatus, shouldReject ? `AI审核：${reason}` : null, shouldReject ? now : null, job.card_id);
    db.prepare(
        `UPDATE ai_review_queue
         SET status = ?, decision = ?, reason = ?, error = ?, model = ?,
             text_decision = ?, text_reason = ?, text_error = ?, text_model = ?,
             cover_decision = ?, cover_reason = ?, cover_error = ?, cover_model = ?,
             completed_at = ?
         WHERE id = ?`
    ).run(
        update.changes ? queueStatus : 'skipped',
        decision,
        reason,
        String(error || '').slice(0, 1000),
        model,
        textResult.decision || null,
        String(textResult.reason || '').slice(0, 500) || null,
        String(textResult.error || '').slice(0, 1000) || null,
        textResult.model || null,
        coverResult.decision || null,
        String(coverResult.reason || '').slice(0, 500) || null,
        String(coverResult.error || '').slice(0, 1000) || null,
        coverResult.model || null,
        now,
        job.id
    );
    if (!update.changes) return;
    clearCardListCache('ai-review-complete');
    logOperation({
        userType: 'system',
        action: shouldReject ? 'ai_review_reject' : 'ai_review_allow',
        targetType: 'card',
        targetId: job.card_id,
        details: { reason, fail_open: Boolean(error), model }
    });
}

function claimNextAiReviewJob() {
    return db.transaction(() => {
        const job = db.prepare("SELECT * FROM ai_review_queue WHERE status = 'pending' ORDER BY id LIMIT 1").get();
        if (!job) return null;
        db.prepare(
            "UPDATE ai_review_queue SET status = 'processing', attempts = attempts + 1, started_at = ?, completed_at = NULL WHERE id = ?"
        ).run(new Date().toISOString(), job.id);
        return job;
    })();
}

async function processAiReviewQueue() {
    if (aiReviewWorkerRunning) return;
    aiReviewWorkerRunning = true;
    try {
        while (true) {
            const job = claimNextAiReviewJob();
            if (!job) break;
            const card = db.prepare(
                'SELECT id, name, description, creator_notes, avatar_url, data, review_status FROM character_cards WHERE id = ?'
            ).get(job.card_id);
            if (!card || card.review_status !== 'ai_pending') {
                completeAiReviewJob(job, { decision: 'ALLOW', reason: '卡片状态已变化，跳过审核' });
                continue;
            }
            const config = getAiReviewConfig();
            if (!isAiReviewConfigured(config)) {
                completeAiReviewJob(job, {
                    decision: 'ALLOW',
                    reason: 'AI 审核未配置完整，按规则自动放行',
                    error: 'AI review is not configured',
                    model: `${config.model} / ${config.visionModel}`,
                    text: {
                        decision: 'ALLOW',
                        reason: '内容审核未配置完整，按规则自动放行',
                        error: 'AI review is not configured',
                        model: config.model
                    },
                    cover: {
                        decision: 'ALLOW',
                        reason: '封面审核未配置完整，按规则自动放行',
                        error: 'AI review is not configured',
                        model: config.visionModel
                    }
                });
                continue;
            }
            try {
                const result = await requestAiCardReview(card, config);
                result.text.model = config.model;
                result.cover.model = config.visionModel;
                completeAiReviewJob(job, {
                    ...result,
                    model: `${config.model} / ${config.visionModel}`
                });
            } catch (err) {
                completeAiReviewJob(job, {
                    decision: 'ALLOW',
                    reason: 'AI 审核失败，按规则自动放行',
                    error: err.message,
                    model: `${config.model} / ${config.visionModel}`,
                    text: {
                        decision: 'ALLOW',
                        reason: '内容审核发生内部错误，按规则自动放行',
                        error: err.message,
                        model: config.model
                    },
                    cover: {
                        decision: 'ALLOW',
                        reason: '封面审核发生内部错误，按规则自动放行',
                        error: err.message,
                        model: config.visionModel
                    }
                });
            }
        }
    } finally {
        aiReviewWorkerRunning = false;
    }
}

function scheduleAiReviewQueue() {
    if (aiReviewWorkerRunning || aiReviewWorkerTimer) return;
    aiReviewWorkerTimer = setTimeout(() => {
        aiReviewWorkerTimer = null;
        processAiReviewQueue().catch(err => console.error('AI review queue error:', err));
    }, 0);
}

function enqueueAiCardReview(cardId) {
    db.prepare(
        `INSERT INTO ai_review_queue (
            card_id, card_name, uploader_user_id, uploader_username, status
         )
         SELECT c.id, c.name, c.uploader_user_id, u.username, 'pending'
           FROM character_cards c
           LEFT JOIN users u ON u.id = c.uploader_user_id
          WHERE c.id = ?
         ON CONFLICT(card_id) DO UPDATE SET
            card_name = excluded.card_name,
            uploader_user_id = excluded.uploader_user_id,
            uploader_username = excluded.uploader_username,
            status = 'pending', decision = NULL, reason = NULL, error = NULL,
            model = NULL,
            text_decision = NULL, text_reason = NULL, text_error = NULL, text_model = NULL,
            cover_decision = NULL, cover_reason = NULL, cover_error = NULL, cover_model = NULL,
            started_at = NULL, completed_at = NULL`
    ).run(cardId);
    scheduleAiReviewQueue();
}

function recoverAiReviewQueue() {
    db.prepare("UPDATE ai_review_queue SET status = 'pending', started_at = NULL WHERE status = 'processing'").run();
    scheduleAiReviewQueue();
}

function syncCardEditableFieldsIntoData(rawData, updates = {}) {
    const parsed = parseStoredCardData(rawData);
    if (!parsed || typeof parsed !== 'object') return rawData || null;
    const cloned = clonePlainObject(parsed);
    const content = cloned.data && typeof cloned.data === 'object' && !Array.isArray(cloned.data)
        ? cloned.data
        : cloned;

    if (Object.prototype.hasOwnProperty.call(updates, 'name')) {
        const value = String(updates.name || '');
        content.name = value;
        if (Object.prototype.hasOwnProperty.call(content, 'char_name')) content.char_name = value;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'description')) {
        const value = String(updates.description || '');
        content.description = value;
        if (Object.prototype.hasOwnProperty.call(content, 'char_persona')) content.char_persona = value;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'creator_notes')) {
        content.creator_notes = String(updates.creator_notes || '');
    }
    if (
        Object.prototype.hasOwnProperty.call(updates, 'avatar_url')
        && updates.avatar_url
        && !isEmbeddedAvatarPayload(updates.avatar_url)
        && Object.prototype.hasOwnProperty.call(content, 'avatar')
    ) {
        content.avatar = String(updates.avatar_url);
    }
    stripEmbeddedAvatarPayloadsFromContent(content);

    return JSON.stringify(cloned);
}

function parseCardDetailPreview(value) {
    const parsed = parseStoredCardData(value);
    if (!parsed || typeof parsed !== 'object') return null;
    return {
        version: Number(parsed.version || 1),
        detail_ready: true,
        name: parsed.name || '',
        description: parsed.description || '',
        personality: parsed.personality || '',
        first_mes: parsed.first_mes || '',
        uiTemplates: Array.isArray(parsed.uiTemplates) ? parsed.uiTemplates : []
    };
}

function attachCardDetailPreview(card, { keepPreviewColumn = false } = {}) {
    if (!card) return card;
    const preview = parseCardDetailPreview(card.detail_preview);
    card._display = preview || {
        version: 1,
        detail_ready: false,
        name: card.name || '',
        description: card.description || '',
        personality: '',
        first_mes: '',
        uiTemplates: []
    };
    if (!keepPreviewColumn) delete card.detail_preview;
    return card;
}

function sanitizeCharacterCardForClient(card, { viewer = {} } = {}) {
    if (!card) return card;
    const result = { ...card };
    delete result.data;
    delete result.data_hash;
    delete result.avatar_url;
    delete result.detail_preview;
    delete result.heat_email_milestone;
    delete result.reviewed_by_admin_id;

    const canSeeModerationMeta = Boolean(viewer.admin || isModeratorUser(viewer.user));
    if (!canSeeModerationMeta) {
        delete result.uploader_ip_address;
    }

    return result;
}

const NON_RPH_CARD_UPLOAD_MESSAGE = '非本站卡片，多次尝试将被封禁';

function hasRpHubWatermark(data) {
    const parsed = parseStoredCardData(data);
    if (!parsed || typeof parsed !== 'object') return false;
    const content = parsed.data && typeof parsed.data === 'object' ? parsed.data : parsed;
    const watermark = content.extensions?.rp_hub_watermark;
    return typeof watermark === 'string' && watermark.trim().toLowerCase() === 'rp-hub';
}

function normalizeUiTemplateCollection(value) {
    if (!value) return [];
    if (typeof value === 'string') {
        try {
            return normalizeUiTemplateCollection(JSON.parse(value));
        } catch {
            return [];
        }
    }
    if (Array.isArray(value)) return value;
    if (Array.isArray(value.templates)) return value.templates;
    if (Array.isArray(value.uiTemplates)) return value.uiTemplates;
    if (Array.isArray(value.ui_templates)) return value.ui_templates;
    if (typeof value === 'object') return Object.values(value);
    return [];
}

function stripTemplateCodeFence(value) {
    const text = String(value || '').trim();
    if (!text.startsWith('```')) return String(value || '');
    return text
        .replace(/^```[a-zA-Z0-9_-]*\s*\n?/, '')
        .replace(/\n?```\s*$/, '')
        .trim();
}

function addVariableKeysFromObject(value, target) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    Object.keys(value).forEach(key => {
        if (!key || String(key).startsWith('_')) return;
        target.add(String(key));
    });
}

function addVariableKeysFromMarkup(markup, target) {
    const text = stripTemplateCodeFence(markup);
    for (const match of text.matchAll(/{{\s*([^}]+?)\s*}}/g)) {
        const raw = String(match[1] || '').trim();
        if (!raw || raw === 'else' || raw.startsWith('/') || raw.startsWith('@')) continue;
        if (raw.startsWith('#each ')) {
            const path = raw.replace(/^#each\s+/, '').trim();
            if (path) target.add(path.split('.')[0]);
            continue;
        }
        if (raw.startsWith('#')) continue;
        target.add(raw.split('.')[0]);
    }
}

function collectUiTemplateVariableKeys(value, target = new Set()) {
    if (!value) return target;
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
                return collectUiTemplateVariableKeys(JSON.parse(trimmed), target);
            } catch {
                addVariableKeysFromMarkup(trimmed, target);
                return target;
            }
        }
        addVariableKeysFromMarkup(trimmed, target);
        return target;
    }
    if (Array.isArray(value)) {
        value.forEach(item => collectUiTemplateVariableKeys(item, target));
        return target;
    }
    if (typeof value !== 'object') return target;

    const beforeDeclaredCount = target.size;
    [
        value.initialVariableState,
        value.initialVariables,
        value.variableState,
        value.variables,
        value.variableSchema,
        value.previewData,
        value.sampleData
    ].forEach(candidate => addVariableKeysFromObject(candidate, target));
    const hasDeclaredVariables = target.size > beforeDeclaredCount;

    if (!hasDeclaredVariables) {
        [
            value.htmlTemplate,
            value.template,
            value.html,
            value.content,
            value.markup
        ].filter(item => typeof item === 'string').forEach(markup => addVariableKeysFromMarkup(markup, target));
    }

    [
        value.templates,
        value.uiTemplates,
        value.ui_templates,
        value.data?.templates,
        value.data?.uiTemplates,
        value.data?.ui_templates,
        value.extensions?.templates,
        value.extensions?.uiTemplates,
        value.extensions?.ui_templates,
        value.extensions?.rp_hub_ui_templates
    ].filter(Boolean).forEach(candidate => {
        normalizeUiTemplateCollection(candidate).forEach(item => collectUiTemplateVariableKeys(item, target));
    });

    return target;
}

function getUiTemplateVariableCount(value) {
    return collectUiTemplateVariableKeys(value).size;
}

function getUiTemplateCount(rawData) {
    const parsed = parseStoredCardData(rawData);
    const content = parsed?.data || parsed || {};
    const candidates = [
        content.uiTemplates,
        content.ui_templates,
        parsed?.uiTemplates,
        parsed?.ui_templates,
        content.extensions?.uiTemplates,
        content.extensions?.ui_templates,
        content.extensions?.rp_hub_ui_templates,
        parsed?.extensions?.uiTemplates,
        parsed?.extensions?.ui_templates,
        parsed?.extensions?.rp_hub_ui_templates
    ];

    return candidates.reduce((count, candidate) => {
        return count + normalizeUiTemplateCollection(candidate).filter(template => {
            if (typeof template === 'string') return template.trim().length > 0;
            if (!template || typeof template !== 'object') return false;
            return Boolean(template.htmlTemplate || template.template || template.html || template.content);
        }).length;
    }, 0);
}

function getEmbeddedUiTemplateVariableCount(rawData) {
    const parsed = parseStoredCardData(rawData);
    const content = parsed?.data || parsed || {};
    const candidates = [
        content.uiTemplates,
        content.ui_templates,
        parsed?.uiTemplates,
        parsed?.ui_templates,
        content.extensions?.uiTemplates,
        content.extensions?.ui_templates,
        content.extensions?.rp_hub_ui_templates,
        parsed?.extensions?.uiTemplates,
        parsed?.extensions?.ui_templates,
        parsed?.extensions?.rp_hub_ui_templates
    ];
    const keys = new Set();
    candidates.forEach(candidate => {
        normalizeUiTemplateCollection(candidate).forEach(template => collectUiTemplateVariableKeys(template, keys));
    });
    return keys.size;
}

function attachUiTemplateSummary(card, { keepData = false, preferStoredSummary = false } = {}) {
    if (!card) return card;
    if (!preferStoredSummary && Object.prototype.hasOwnProperty.call(card, 'data') && card.data != null) {
        Object.assign(card, buildCardUiTemplateSummary(card.data));
    } else {
        card.ui_template_count = Number(card.ui_template_count || 0);
        card.has_ui_templates = Number(card.has_ui_templates || 0);
        card.ui_template_variable_count = Number(card.ui_template_variable_count || 0);
    }
    if (!keepData) delete card.data;
    return card;
}

function buildCardUiTemplateSummary(cardData) {
    const uiTemplateCount = getUiTemplateCount(cardData);
    return {
        has_ui_templates: uiTemplateCount > 0 ? 1 : 0,
        ui_template_count: uiTemplateCount,
        ui_template_variable_count: getEmbeddedUiTemplateVariableCount(cardData)
    };
}

function pushCardUiTemplateSummaryUpdate(fields, values, cardData) {
    const summary = buildCardUiTemplateSummary(cardData);
    fields.push('has_ui_templates = ?');
    values.push(summary.has_ui_templates);
    fields.push('ui_template_count = ?');
    values.push(summary.ui_template_count);
    fields.push('ui_template_variable_count = ?');
    values.push(summary.ui_template_variable_count);
}

function scheduleCardUiSummaryBackfill() {
    if (!CARD_UI_SUMMARY_BACKFILL) return;
    let processed = 0;
    const started = performance.now();

    const runNext = () => {
        try {
            const row = db.prepare(
                `SELECT id, data
                 FROM character_cards
                 WHERE has_ui_templates IS NULL
                    OR ui_template_count IS NULL
                    OR ui_template_variable_count IS NULL
                 LIMIT 1`
            ).get();

            if (!row) {
                if (processed > 0) {
                    console.info(`[CardSummary] backfill complete processed=${processed} total=${formatDuration(performance.now() - started)}`);
                }
                return;
            }

            const summary = buildCardUiTemplateSummary(row.data);
            db.prepare(
                `UPDATE character_cards
                 SET has_ui_templates = ?,
                     ui_template_count = ?,
                     ui_template_variable_count = ?
                 WHERE id = ?`
            ).run(summary.has_ui_templates, summary.ui_template_count, summary.ui_template_variable_count, row.id);

            processed += 1;
            if (processed % 100 === 0) {
                console.info(`[CardSummary] backfilled ${processed} card(s) total=${formatDuration(performance.now() - started)}`);
            }
        } catch (err) {
            console.warn('[CardSummary] backfill failed:', err.message);
        }

        setTimeout(runNext, 25);
    };

    setTimeout(runNext, 3000);
}

function scheduleCardDetailPreviewBackfill() {
    if (!CARD_DETAIL_PREVIEW_BACKFILL) return;
    let processed = 0;
    const started = performance.now();

    const runNext = () => {
        try {
            const row = db.prepare(
                `SELECT id, name, description, data
                 FROM character_cards
                 WHERE detail_preview IS NULL OR detail_preview = ''
                 ORDER BY created_at DESC
                 LIMIT 1`
            ).get();

            if (!row) {
                if (processed > 0) {
                    console.info(`[CardDetailPreview] backfill complete processed=${processed} total=${formatDuration(performance.now() - started)}`);
                }
                return;
            }

            const detailPreview = buildCardDetailPreviewJson(row.data, {
                name: row.name,
                description: row.description || ''
            });
            db.prepare('UPDATE character_cards SET detail_preview = ? WHERE id = ?')
                .run(detailPreview, row.id);

            processed += 1;
            if (processed % 100 === 0) {
                console.info(`[CardDetailPreview] backfilled ${processed} card(s) total=${formatDuration(performance.now() - started)}`);
            }
        } catch (err) {
            console.warn('[CardDetailPreview] backfill failed:', err.message);
        }

        setTimeout(runNext, 25);
    };

    setTimeout(runNext, 5000);
}

function updateCardDataAfterAvatarCleanup(row, sanitizedValue) {
    const dataStr = JSON.stringify(sanitizedValue);
    const summary = buildCardUiTemplateSummary(dataStr);
    const detailPreview = buildCardDetailPreviewJson(dataStr, {
        name: row.name,
        description: row.description || ''
    });
    const dataHash = hashCardData(sanitizedValue);
    try {
        db.prepare(
            `UPDATE character_cards
             SET data = ?,
                 data_hash = ?,
                 detail_preview = ?,
                 has_ui_templates = ?,
                 ui_template_count = ?,
                 ui_template_variable_count = ?
             WHERE id = ?`
        ).run(
            dataStr, dataHash, detailPreview,
            summary.has_ui_templates, summary.ui_template_count, summary.ui_template_variable_count,
            row.id
        );
    } catch (err) {
        if (!String(err.message || '').includes('UNIQUE constraint failed')) throw err;
        db.prepare(
            `UPDATE character_cards
             SET data = ?,
                 data_hash = NULL,
                 detail_preview = ?,
                 has_ui_templates = ?,
                 ui_template_count = ?,
                 ui_template_variable_count = ?
             WHERE id = ?`
        ).run(
            dataStr, detailPreview,
            summary.has_ui_templates, summary.ui_template_count, summary.ui_template_variable_count,
            row.id
        );
    }
}

function scheduleCardDataAvatarCleanup() {
    if (!CARD_DATA_AVATAR_CLEANUP) return;
    let processed = 0;
    let cleaned = 0;
    let lastId = '';
    const started = performance.now();

    const runNext = () => {
        try {
            const row = db.prepare(
                `SELECT id, name, description, data
                 FROM character_cards
                 WHERE id > ?
                   AND data LIKE '%"avatar%'
                   AND (data LIKE '%data:%' OR data LIKE '%/api/cards/%')
                 ORDER BY id ASC
                 LIMIT 1`
            ).get(lastId);

            if (!row) {
                if (processed > 0) {
                    console.info(`[CardDataCleanup] complete processed=${processed} cleaned=${cleaned} total=${formatDuration(performance.now() - started)}`);
                }
                return;
            }

            lastId = row.id;
            processed += 1;
            const sanitized = sanitizeCardDataForStorage(row.data);
            if (sanitized.changed && sanitized.value && typeof sanitized.value === 'object') {
                updateCardDataAfterAvatarCleanup(row, sanitized.value);
                cleaned += 1;
                if (cleaned % 50 === 0) {
                    console.info(`[CardDataCleanup] cleaned ${cleaned} card(s), processed=${processed}`);
                }
            }
        } catch (err) {
            console.warn('[CardDataCleanup] failed:', err.message);
        }

        setTimeout(runNext, 25);
    };

    setTimeout(runNext, 7000);
}

function sanitizeUiTemplateFileName(fileName) {
    const cleaned = String(fileName || 'ui-template.json')
        .trim()
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
        .replace(/\s+/g, ' ')
        .replace(/[. ]+$/g, '');
    return (cleaned || 'ui-template.json').slice(0, 160);
}

function getFileExt(fileName) {
    const match = String(fileName || '').match(/\.([a-z0-9_-]{1,16})$/i);
    return match ? match[1].toLowerCase() : '';
}

function isValidJsonContent(content) {
    try {
        JSON.parse(String(content || ''));
        return true;
    } catch (err) {
        return false;
    }
}

function getUiTemplateCommentCounts(templateId) {
    return db.prepare(
        `SELECT
            ${templateCommentCountExpr('ui_templates')} AS comment_count,
            ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
         FROM ui_templates
         WHERE id = ?`
    ).get(templateId) || { comment_count: 0, comment_heat_count: 0 };
}

function sanitizeUiTemplateRow(row, { includeContent = false, viewer = {} } = {}) {
    if (!row) return row;
    const result = { ...row };
    const contentSource = String(row.content ?? row.content_preview_source ?? row.content_preview ?? '');
    const commentCount = Number(row.comment_count || 0);
    const commentHeatCount = getCommentHeatCount(row);
    const downloadsCount = Number(row.downloads_count || 0);
    const viewsCount = Number(row.views_count || 0);
    const canViewDownloads = Boolean(viewer.admin || (viewer.user && row.uploader_user_id === viewer.user.id));
    result.content_preview = contentSource.slice(0, 600);
    result.variable_count = getUiTemplateVariableCount(contentSource);
    result.comment_count = commentCount;
    result.comment_heat_count = commentHeatCount;
    result.heat_score = computeTemplateHeatFromRow({ views_count: viewsCount, comment_heat_count: commentHeatCount, downloads_count: downloadsCount });
    result.can_view_downloads = canViewDownloads;
    if (!canViewDownloads) result.downloads_count = null;
    if (!viewer.admin && !isModeratorUser(viewer.user)) {
        delete result.uploader_ip_address;
        delete result.reviewed_by_admin_id;
    }
    delete result.content_preview_source;
    if (!includeContent) delete result.content;
    return result;
}

function getUiTemplateMetrics(templateId, { viewer = {} } = {}) {
    const row = db.prepare(
        `SELECT id, uploader_user_id, views_count, downloads_count,
                ${templateCommentCountExpr('ui_templates')} AS comment_count,
                ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
         FROM ui_templates
         WHERE id = ?`
    ).get(templateId);
    if (!row) return null;
    const commentCount = Number(row.comment_count || 0);
    const commentHeatCount = getCommentHeatCount(row);
    const downloadsCount = Number(row.downloads_count || 0);
    const viewsCount = Number(row.views_count || 0);
    const canViewDownloads = Boolean(viewer.admin || (viewer.user && row.uploader_user_id === viewer.user.id));
    const metrics = {
        comment_count: commentCount,
        comment_heat_count: commentHeatCount,
        views_count: viewsCount,
        heat_score: computeTemplateHeatFromRow({ views_count: viewsCount, comment_heat_count: commentHeatCount, downloads_count: downloadsCount })
    };
    if (canViewDownloads) {
        metrics.downloads_count = downloadsCount;
    }
    return metrics;
}

function getCardMetrics(cardId, { viewer = {} } = {}) {
    const row = db.prepare(
        `SELECT id, uploader_user_id, views_count, downloads_count,
                ${cardCommentCountExpr('character_cards')} AS comment_count,
                ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
         FROM character_cards
         WHERE id = ?`
    ).get(cardId);
    if (!row) return null;
    const commentCount = Number(row.comment_count || 0);
    const commentHeatCount = getCommentHeatCount(row);
    const downloadsCount = Number(row.downloads_count || 0);
    const viewsCount = Number(row.views_count || 0);
    const canViewDownloads = Boolean(viewer.admin || (viewer.user && row.uploader_user_id === viewer.user.id));
    const metrics = {
        comment_count: commentCount,
        comment_heat_count: commentHeatCount,
        views_count: viewsCount,
        heat_score: computeCardHeatFromRow({ views_count: viewsCount, comment_heat_count: commentHeatCount, downloads_count: downloadsCount })
    };
    if (canViewDownloads) {
        metrics.downloads_count = downloadsCount;
    }
    return metrics;
}

app.get('/api/cards/counts', optionalUserAuth, async (req, res) => {
    try {
        let reviewedWhere = "review_status = 'approved'";
        const params = [];
        if (req.admin || isModeratorUser(req.user)) {
            reviewedWhere = "review_status NOT IN ('unreviewed', 'ai_pending')";
        } else if (req.user) {
            reviewedWhere = "review_status NOT IN ('unreviewed', 'ai_pending') AND (review_status = 'approved' OR uploader_user_id = ?)";
            params.push(req.user.id);
        }
        const reviewedQuery = sqliteReadPool.fastGet(`SELECT COUNT(*) AS count FROM character_card_catalog WHERE ${reviewedWhere}`, params);
        const unreviewedQuery = sqliteReadPool.fastGet("SELECT COUNT(*) AS count FROM character_card_catalog WHERE review_status = 'unreviewed'", []);
        let templateWhere = "review_status = 'approved'";
        const templateParams = [];
        if (req.admin || isModeratorUser(req.user)) {
            templateWhere = '1 = 1';
        } else if (req.user) {
            templateWhere = "review_status = 'approved' OR uploader_user_id = ?";
            templateParams.push(req.user.id);
        }
        const [reviewedRow, unreviewedRow, uiTemplatesRow] = await Promise.all([
            reviewedQuery,
            unreviewedQuery,
            sqliteReadPool.fastGet(`SELECT COUNT(*) AS count FROM ui_templates WHERE ${templateWhere}`, templateParams)
        ]);
        const reviewed = reviewedRow.count;
        const unreviewed = unreviewedRow.count;
        const uiTemplates = uiTemplatesRow.count;
        res.json({ reviewed, unreviewed, ui_templates: uiTemplates });
    } catch (err) {
        console.error('Fetch card counts error:', err);
        res.status(500).json({ error: '获取卡片数量失败' });
    }
});

app.get('/api/cards/tags', optionalUserAuth, async (req, res) => {
    try {
        const zone = req.query.zone === 'unreviewed' ? 'unreviewed' : 'reviewed';
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 200, 1), 200);
        const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
        const cacheKey = getCardListCacheKey(req, 'tags', zone, `page-${limit}-${offset}`);
        const cached = getFreshCardListCache(cacheKey);
        if (cached) return sendCardListCache(req, res, cached);

        const whereParts = [];
        const params = [];
        if (zone === 'unreviewed') {
            whereParts.push("cc.review_status = 'unreviewed'");
        } else if (req.admin || isModeratorUser(req.user)) {
            whereParts.push("cc.review_status NOT IN ('unreviewed', 'ai_pending')");
        } else if (req.user) {
            whereParts.push("(cc.review_status = 'approved' OR cc.uploader_user_id = ?)");
            whereParts.push("cc.review_status NOT IN ('unreviewed', 'ai_pending')");
            params.push(req.user.id);
        } else {
            whereParts.push("cc.review_status = 'approved'");
        }

        const hiddenTags = parseTagSettingValue(getSettingValue('hidden_tag_library')).map(tag => tag.toLowerCase());
        if (hiddenTags.length > 0) {
            whereParts.push(`cct.tag_key NOT IN (${hiddenTags.map(() => '?').join(', ')})`);
            params.push(...hiddenTags);
        }
        const rows = await sqliteReadPool.fastAll(
            `SELECT MIN(cct.tag) AS tag, COUNT(*) AS count, COUNT(*) OVER() AS __total_count
             FROM character_card_tags cct
             JOIN character_card_catalog cc ON cc.id = cct.card_id
             WHERE ${whereParts.join(' AND ')}
             GROUP BY cct.tag_key
             ORDER BY count DESC, tag ASC
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );
        const totalCount = Number(rows[0]?.__total_count || 0);
        const tags = rows.map(row => ({ tag: row.tag, count: row.count }));
        return sendCardListCache(req, res, setCardListCache(cacheKey, tags, totalCount));
    } catch (err) {
        console.error('Fetch card tags error:', err);
        res.status(500).json({ error: '获取标签失败' });
    }
});

app.get('/api/cards', optionalUserAuth, async (req, res) => {
    try {
        const sortMode = req.query.sort || 'latest';
        const zone = req.query.zone === 'unreviewed' ? 'unreviewed' : 'reviewed';
        const idsOnly = req.query.ids_only === '1';
        const searchQuery = String(req.query.q || '').trim().toLowerCase().slice(0, 100);
        const tagFilter = String(req.query.tag || '').trim().toLowerCase().slice(0, 100);
        const mineOnly = req.query.mine === '1';
        const requestedLimit = parseInt(req.query.limit, 10);
        const limit = !idsOnly
            ? (Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(requestedLimit, 100) : 10)
            : 0;
        const requestedOffset = parseInt(req.query.offset, 10);
        const offset = limit && Number.isFinite(requestedOffset) && requestedOffset > 0
            ? Math.min(requestedOffset, 1000000)
            : 0;
        markPerf(req, 'cards-start', { sortMode, zone, idsOnly, limit, offset, hasSearch: Boolean(searchQuery), hasTag: Boolean(tagFilter), mineOnly });
        const filterHash = crypto.createHash('sha1').update(JSON.stringify([searchQuery, tagFilter, mineOnly])).digest('hex').slice(0, 12);
        const representation = `${idsOnly ? 'ids' : (limit ? `full-${limit}-${offset}` : 'full')}-${filterHash}`;
        const cacheKey = getCardListCacheKey(req, sortMode, zone, representation);
        const cached = getFreshCardListCache(cacheKey);
        if (cached) {
            markPerf(req, 'cards-cache-hit', { bytes: cached.body.length, gzipBytes: cached.gzipBody?.length || 0 });
            return sendCardListCache(req, res, cached);
        }

        const commentCountSql = cardCommentCountExpr('cc');
        const commentHeatCountSql = cardCommentHeatCountExpr('cc');
        const heatExpr = `((IFNULL(cc.views_count, 0) * ${VIEW_HEAT_WEIGHT}) + (IFNULL(${commentHeatCountSql}, 0) * ${COMMENT_HEAT_WEIGHT}) + (IFNULL(cc.downloads_count, 0) * ${DOWNLOAD_HEAT_WEIGHT}))`;
        const periodModifier = getRankingPeriodModifier(sortMode);
        const whereParts = [];
        const params = [];
        const joinParams = [];
        const orderParams = [];
        let joinClause = '';
        let orderByClause = 'cc.created_at DESC';

        if (zone === 'unreviewed') {
            whereParts.push("cc.review_status = 'unreviewed'");
        } else if (req.admin || isModeratorUser(req.user)) {
            // Admins and front-end moderators can review every status.
            whereParts.push("cc.review_status NOT IN ('unreviewed', 'ai_pending')");
        } else if (req.user) {
            whereParts.push("(cc.review_status = 'approved' OR cc.uploader_user_id = ?)");
            whereParts.push("cc.review_status NOT IN ('unreviewed', 'ai_pending')");
            params.push(req.user.id);
        } else {
            whereParts.push("cc.review_status = 'approved'");
        }

        if (mineOnly) {
            if (req.admin || isModeratorUser(req.user)) {
                whereParts.push("cc.review_status = 'pending'");
            } else if (req.user) {
                whereParts.push('cc.uploader_user_id = ?');
                params.push(req.user.id);
            } else {
                whereParts.push('1 = 0');
            }
        }

        if (searchQuery) {
            const searchPattern = `%${searchQuery}%`;
            whereParts.push('cc.search_text LIKE ?');
            params.push(searchPattern);
            if (sortMode === 'latest') {
                orderByClause = "CASE WHEN LOWER(COALESCE(cc.name, '')) LIKE ? THEN 0 ELSE 1 END, cc.created_at DESC";
                orderParams.push(searchPattern);
            }
        }

        if (tagFilter) {
            joinClause = 'JOIN character_card_tags filter_tag ON filter_tag.card_id = cc.id AND filter_tag.tag_key = ?';
            joinParams.push(tagFilter);
        }

        if (sortMode === 'featured') {
            whereParts.push('cc.is_featured = 1');
            orderByClause = 'cc.created_at DESC';
        } else if (sortMode === 'updated') {
            whereParts.push('cc.updated_at IS NOT NULL AND julianday(cc.updated_at) > julianday(cc.created_at)');
            orderByClause = 'cc.updated_at DESC, cc.created_at DESC';
        } else if (sortMode === 'hot') {
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        } else if (periodModifier) {
            orderByClause = `${cardPeriodHeatExpr('cc', periodModifier)} DESC, ${heatExpr} DESC, cc.created_at DESC`;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
        markPerf(req, 'cards-query-built', { whereParts: whereParts.length, params: params.length });
        const useFastLane = !idsOnly && !searchQuery && !tagFilter && !mineOnly
            && (sortMode === 'latest' || sortMode === 'featured');
        const readGet = useFastLane ? sqliteReadPool.fastGet.bind(sqliteReadPool) : sqliteReadPool.get.bind(sqliteReadPool);
        const readAll = useFastLane ? sqliteReadPool.fastAll.bind(sqliteReadPool) : sqliteReadPool.all.bind(sqliteReadPool);
        const totalQuery = idsOnly
            ? Promise.resolve({ count: 0 })
            : readGet(
                `SELECT COUNT(*) AS count
                 FROM character_card_catalog cc
                 ${joinClause}
                 ${whereClause}`,
                [...joinParams, ...params]
            );
        const selectColumns = idsOnly
            ? 'cc.id'
            : `cc.id, cc.name, cc.description, cc.creator_notes,
                    cc.downloads_count, cc.uploader_user_id, cc.created_at, cc.latest_rank_at, cc.updated_at,
                    cc.views_count, cc.is_featured, cc.review_status,
                    cc.reviewed_at, cc.rejection_reason, cc.uploader_ip_address,
                    COALESCE(cc.has_ui_templates, 0) AS has_ui_templates,
                    COALESCE(cc.ui_template_count, 0) AS ui_template_count,
                    COALESCE(cc.ui_template_variable_count, 0) AS ui_template_variable_count,
                    ${commentCountSql} AS comment_count,
                    ${commentHeatCountSql} AS comment_heat_count`;
        const cardsQuery = readAll(
            `SELECT ${selectColumns}
             FROM character_card_catalog cc
             ${joinClause}
             ${whereClause}
             ORDER BY ${orderByClause}
             ${limit ? 'LIMIT ? OFFSET ?' : ''}`,
            [...joinParams, ...params, ...orderParams, ...(limit ? [limit, offset] : [])]
        );
        const [totalRow, rawCards] = await Promise.all([totalQuery, cardsQuery]);
        const totalCount = Number(totalRow.count || 0);
        markPerf(req, 'cards-db-read', { rows: rawCards.length });
        if (idsOnly) {
            const ids = rawCards.map(card => card.id);
            const newCache = setCardListCache(cacheKey, ids);
            markPerf(req, 'cards-cache-store', { rows: ids.length, bytes: newCache.body.length, gzipBytes: newCache.gzipBody.length, idsOnly: true });
            return sendCardListCache(req, res, newCache);
        }
        const cards = rawCards.map(card => {
            return sanitizeCharacterCardForClient(
                attachUiTemplateSummary(card),
                { viewer: { admin: req.admin, user: req.user } }
            );
        });
        markPerf(req, 'cards-normalize-summary', { rows: cards.length });
        const newCache = setCardListCache(cacheKey, cards, totalCount);
        markPerf(req, 'cards-cache-store', { rows: cards.length, bytes: newCache.body.length, gzipBytes: newCache.gzipBody.length });
        return sendCardListCache(req, res, newCache);
    } catch (err) {
        console.error('Fetch cards error:', err);
        res.status(500).json({ error: '获取卡片失败' });
    }
});

// ============== UI Template Routes ==============
app.get('/api/ui-templates', optionalUserAuth, async (req, res) => {
    try {
        const sortMode = req.query.sort || 'latest';
        const searchQuery = String(req.query.q || '').trim().toLowerCase().slice(0, 100);
        const mineOnly = req.query.mine === '1';
        const requestedLimit = parseInt(req.query.limit, 10);
        const limit = Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(requestedLimit, 100) : 10;
        const requestedOffset = parseInt(req.query.offset, 10);
        const offset = limit && Number.isFinite(requestedOffset) && requestedOffset > 0 ? Math.min(requestedOffset, 1000000) : 0;
        markPerf(req, 'ui-templates-start', { sortMode, limit, offset, hasSearch: Boolean(searchQuery), mineOnly });
        const whereParts = [];
        const params = [];
        const orderParams = [];
        let orderByClause = 'ui_templates.created_at DESC';

        if (req.admin || isModeratorUser(req.user)) {
            // Admins and front-end moderators can review every status.
        } else if (req.user) {
            whereParts.push("(review_status = 'approved' OR uploader_user_id = ?)");
            params.push(req.user.id);
        } else {
            whereParts.push("review_status = 'approved'");
        }

        if (mineOnly) {
            if (req.admin || isModeratorUser(req.user)) {
                whereParts.push("review_status = 'pending'");
            } else if (req.user) {
                whereParts.push('uploader_user_id = ?');
                params.push(req.user.id);
            } else {
                whereParts.push('1 = 0');
            }
        }

        if (searchQuery) {
            const searchPattern = `%${searchQuery}%`;
            whereParts.push("(LOWER(COALESCE(title, '')) LIKE ? OR LOWER(COALESCE(description, '')) LIKE ? OR LOWER(COALESCE(file_name, '')) LIKE ?)");
            params.push(searchPattern, searchPattern, searchPattern);
            if (sortMode === 'latest') {
                orderByClause = "CASE WHEN LOWER(COALESCE(title, '')) LIKE ? THEN 0 ELSE 1 END, created_at DESC";
                orderParams.push(searchPattern);
            }
        }

        const templateCommentCountSql = templateCommentCountExpr('ui_templates');
        const templateCommentHeatCountSql = templateCommentHeatCountExpr('ui_templates');
        const heatExpr = `((IFNULL(views_count, 0) * ${VIEW_HEAT_WEIGHT})
            + (${templateCommentHeatCountSql} * ${COMMENT_HEAT_WEIGHT})
            + (IFNULL(downloads_count, 0) * ${DOWNLOAD_HEAT_WEIGHT}))`;
        const periodModifier = getRankingPeriodModifier(sortMode);
        if (sortMode === 'featured') {
            whereParts.push('is_featured = 1');
            orderByClause = 'created_at DESC';
        } else if (sortMode === 'updated') {
            whereParts.push('updated_at IS NOT NULL AND julianday(updated_at) > julianday(created_at)');
            orderByClause = 'updated_at DESC, created_at DESC';
        } else if (sortMode === 'hot') {
            orderByClause = `${heatExpr} DESC, downloads_count DESC, created_at DESC`;
        } else if (periodModifier) {
            orderByClause = `${templatePeriodHeatExpr('ui_templates', periodModifier)} DESC, ${heatExpr} DESC, created_at DESC`;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
        markPerf(req, 'ui-templates-query-built', { whereParts: whereParts.length, params: params.length });
        const useFastLane = !searchQuery && !mineOnly && (sortMode === 'latest' || sortMode === 'featured');
        const readGet = useFastLane ? sqliteReadPool.fastGet.bind(sqliteReadPool) : sqliteReadPool.get.bind(sqliteReadPool);
        const readAll = useFastLane ? sqliteReadPool.fastAll.bind(sqliteReadPool) : sqliteReadPool.all.bind(sqliteReadPool);
        const totalQuery = readGet(
            `SELECT COUNT(*) AS count
             FROM ui_templates
             ${whereClause}`,
            params
        );
        const templatesQuery = readAll(
            `SELECT id, title, description, file_name, file_ext, mime_type,
                    substr(content, 1, 65536) AS content_preview_source, file_size,
                    downloads_count, views_count, is_featured, uploader_user_id, review_status, reviewed_at,
                    rejection_reason, uploader_ip_address, created_at, latest_rank_at, updated_at,
                    ${templateCommentCountSql} AS comment_count,
                    ${templateCommentHeatCountSql} AS comment_heat_count
             FROM ui_templates
             ${whereClause}
             ORDER BY ${orderByClause}
             ${limit ? 'LIMIT ? OFFSET ?' : ''}`,
            [...params, ...orderParams, ...(limit ? [limit, offset] : [])]
        );
        const [totalRow, rawTemplates] = await Promise.all([totalQuery, templatesQuery]);
        const totalCount = Number(totalRow.count || 0);
        const previewBytes = rawTemplates.reduce((sum, row) => sum + Buffer.byteLength(row.content_preview_source || '', 'utf8'), 0);
        markPerf(req, 'ui-templates-db-read', { rows: rawTemplates.length, previewBytes });
        const templates = rawTemplates.map(row => sanitizeUiTemplateRow(row, { viewer: { admin: req.admin, user: req.user } }));
        markPerf(req, 'ui-templates-sanitize', { rows: templates.length });
        res.setHeader('X-Total-Count', String(totalCount));
        res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count');
        res.json(templates);
        markPerf(req, 'ui-templates-response-json', { rows: templates.length });
    } catch (err) {
        console.error('Fetch UI templates error:', err);
        res.status(500).json({ error: '获取 UI 模板失败' });
    }
});

app.post('/api/ui-templates', requireUserOrAdmin, (req, res) => {
    try {
        const { title, description, file_name, mime_type, content } = req.body;
        const normalizedTitle = String(title || '').trim().slice(0, 120);
        const normalizedContent = typeof content === 'string' ? content : '';
        if (!normalizedTitle) return res.status(400).json({ error: '模板名称不能为空' });
        if (!normalizedContent.trim()) return res.status(400).json({ error: '模板文件内容不能为空' });

        const fileSize = Buffer.byteLength(normalizedContent, 'utf8');
        if (fileSize > MAX_UI_TEMPLATE_FILE_SIZE_BYTES) {
            return res.status(400).json({ error: `模板文件不能超过 2MB (${(fileSize / 1024 / 1024).toFixed(1)}MB)` });
        }

        const safeFileName = sanitizeUiTemplateFileName(file_name || `${normalizedTitle}.json`);
        const fileExt = getFileExt(safeFileName);
        if (fileExt !== 'json') {
            return res.status(400).json({ error: 'UI模板只支持 .json 文件' });
        }
        if (!isValidJsonContent(normalizedContent)) {
            return res.status(400).json({ error: 'JSON 模板解析失败，请检查文件内容' });
        }

        if (!req.admin) {
            const rateKey = req.user ? `user:${req.user.id}` : `ip:${getRequestIp(req)}`;
            if (!checkUploadRate(rateKey)) {
                return res.status(429).json({ error: '上传太频繁，每分钟最多上传 2 个文件，请稍后再试' });
            }
            recordUpload(rateKey);
        }

        const id = generateId();
        const now = new Date().toISOString();
        const uploaderUserId = req.user ? req.user.id : null;
        const reviewStatus = req.admin ? 'approved' : 'pending';
        const reviewedBy = req.admin ? req.admin.id : null;
        const reviewedAt = req.admin ? now : null;
        const uploaderIp = getRequestIp(req);

        db.prepare(
            `INSERT INTO ui_templates
             (id, title, description, file_name, file_ext, mime_type, content, file_size,
              uploader_user_id, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at, latest_rank_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
            id, normalizedTitle, String(description || '').trim().slice(0, 1000), safeFileName,
            fileExt, String(mime_type || 'application/json').slice(0, 120), normalizedContent, fileSize,
            uploaderUserId, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now, now, now
        );

        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(id);
        logOperation({
            userType: req.user ? 'user' : 'admin',
            userId: uploaderUserId || req.admin?.id,
            username: req.user?.username || req.admin?.username,
            action: req.admin ? 'upload_ui_template' : 'upload_ui_template_pending',
            targetType: 'ui_template',
            targetId: id,
            ip: uploaderIp,
            details: { title: normalizedTitle, file_name: safeFileName, review_status: reviewStatus }
        });
        if (reviewStatus === 'pending') {
            sendAdminReviewPendingEmail({
                itemType: 'UI模板',
                title: normalizedTitle,
                uploader: req.user?.username || '',
                ip: uploaderIp
            });
        }

        template.comment_count = 0;
        res.json([sanitizeUiTemplateRow(template, { viewer: { admin: req.admin, user: req.user } }), { pending_review: reviewStatus === 'pending' }]);
    } catch (err) {
        console.error('Create UI template error:', err);
        res.status(500).json({ error: '创建 UI 模板失败' });
    }
});

app.put('/api/admin/ui-templates/:id/review', requireModeration, (req, res) => {
    try {
        const status = String(req.body.status || '').trim();
        const reason = String(req.body.reason || '').trim().slice(0, 500);
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: '无效的审核状态' });
        }
        const template = db.prepare(
            `SELECT ut.id, ut.title, ut.review_status, ut.uploader_user_id,
                    u.username, u.email, u.email_verified
             FROM ui_templates ut
             LEFT JOIN users u ON ut.uploader_user_id = u.id
             WHERE ut.id = ?`
        ).get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const now = new Date().toISOString();
        const reviewAndReward = db.transaction(() => {
            db.prepare(
                `UPDATE ui_templates
                 SET review_status = ?, reviewed_by_admin_id = ?, reviewed_at = ?, rejection_reason = ?
                 WHERE id = ?`
            ).run(status, req.admin?.id || null, now, status === 'rejected' ? reason : null, req.params.id);

            if (status === 'approved' && template.review_status !== 'approved' && template.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = download_credits + 3 WHERE id = ?').run(template.uploader_user_id);
            }
            if (status !== 'approved' && template.review_status === 'approved' && template.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(template.uploader_user_id);
            }
        });
        reviewAndReward();

        const updated = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        const actor = getModerationActor(req);
        logOperation({
            userType: actor.userType,
            userId: actor.userId,
            username: actor.username,
            action: req.admin
                ? (status === 'approved' ? 'admin_approve_ui_template' : 'admin_reject_ui_template')
                : (status === 'approved' ? 'moderator_approve_ui_template' : 'moderator_reject_ui_template'),
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: {
                title: template.title,
                reason: status === 'rejected' ? reason : undefined,
                reviewer_type: actor.reviewerType,
                reviewer_id: actor.userId,
                reviewer_username: actor.username
            }
        });
        if (userEmailBound(template)) {
            sendReviewResultEmail({
                to: template.email,
                username: template.username,
                itemType: 'UI模板',
                title: template.title,
                status,
                reason: status === 'rejected' ? reason : ''
            });
        }
        Object.assign(updated, getUiTemplateCommentCounts(req.params.id));
        res.json({ template: sanitizeUiTemplateRow(updated, { viewer: { admin: req.admin, user: req.user } }) });
    } catch (err) {
        console.error('Review UI template error:', err);
        res.status(500).json({ error: '审核模板失败' });
    }
});

app.put('/api/ui-templates/:id/feature', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const template = db.prepare(
            `SELECT ut.id, ut.title, ut.is_featured,
                    u.username, u.email, u.email_verified
             FROM ui_templates ut
             LEFT JOIN users u ON ut.uploader_user_id = u.id
             WHERE ut.id = ?`
        ).get(id);
        if (!template) return res.status(404).json({ error: '模板不存在' });

        const newFeatured = template.is_featured ? 0 : 1;
        db.prepare('UPDATE ui_templates SET is_featured = ? WHERE id = ?').run(newFeatured, id);

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: newFeatured ? 'feature_ui_template' : 'unfeature_ui_template',
            targetType: 'ui_template',
            targetId: id,
            ip: getRequestIp(req),
            details: { title: template.title }
        });
        if (newFeatured && userEmailBound(template)) {
            sendFeaturedNotificationEmail({
                to: template.email,
                username: template.username,
                itemType: 'UI模板',
                title: template.title
            });
        }

        res.json({ id, is_featured: newFeatured });
    } catch (err) {
        console.error('Feature UI template error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

app.put('/api/ui-templates/:id', requireUserOrAdmin, (req, res) => {
    try {
        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const isOwner = req.user && template.uploader_user_id === req.user.id;
        if (!req.admin && !isOwner) return res.status(403).json({ error: '无权编辑此模板' });

        const fields = [];
        const values = [];
        const setField = (name, value) => {
            fields.push(`${name} = ?`);
            values.push(value);
        };
        const hasContentUpdate = Object.prototype.hasOwnProperty.call(req.body, 'content');
        const hasFileNameUpdate = Object.prototype.hasOwnProperty.call(req.body, 'file_name');
        const hasMimeTypeUpdate = Object.prototype.hasOwnProperty.call(req.body, 'mime_type');
        const shouldRefreshLatestRank = hasContentUpdate;

        if (Object.prototype.hasOwnProperty.call(req.body, 'title')) {
            const title = String(req.body.title || '').trim().slice(0, 120);
            if (!title) return res.status(400).json({ error: '模板名称不能为空' });
            setField('title', title);
        }
        if (Object.prototype.hasOwnProperty.call(req.body, 'description')) {
            setField('description', String(req.body.description || '').trim().slice(0, 1000));
        }
        if (hasContentUpdate || hasFileNameUpdate) {
            const safeFileName = hasFileNameUpdate
                ? sanitizeUiTemplateFileName(req.body.file_name || template.file_name)
                : sanitizeUiTemplateFileName(template.file_name || 'ui-template.json');
            const fileExt = getFileExt(safeFileName);
            if (fileExt !== 'json') {
                return res.status(400).json({ error: 'UI模板只支持 .json 文件' });
            }
            const nextContent = hasContentUpdate ? req.body.content : template.content;
            if (!isValidJsonContent(nextContent)) {
                return res.status(400).json({ error: 'JSON 模板解析失败，请检查文件内容' });
            }
        }
        if (hasContentUpdate) {
            const content = typeof req.body.content === 'string' ? req.body.content : '';
            if (!content.trim()) return res.status(400).json({ error: '模板文件内容不能为空' });
            const fileSize = Buffer.byteLength(content, 'utf8');
            if (fileSize > MAX_UI_TEMPLATE_FILE_SIZE_BYTES) {
                return res.status(400).json({ error: '模板文件不能超过 2MB' });
            }
            setField('content', content);
            setField('file_size', fileSize);
        }
        if (hasFileNameUpdate) {
            const safeFileName = sanitizeUiTemplateFileName(req.body.file_name || template.file_name);
            setField('file_name', safeFileName);
            setField('file_ext', getFileExt(safeFileName));
        }
        if (hasMimeTypeUpdate) {
            setField('mime_type', String(req.body.mime_type || template.mime_type || 'application/json').slice(0, 120));
        }

        if (!req.admin && hasContentUpdate) {
            setField('review_status', 'pending');
            setField('reviewed_by_admin_id', null);
            setField('reviewed_at', null);
            setField('rejection_reason', null);
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        const editTime = new Date().toISOString();
        setField('updated_at', editTime);
        if (shouldRefreshLatestRank) {
            setField('latest_rank_at', editTime);
        }
        values.push(req.params.id);
        db.prepare(`UPDATE ui_templates SET ${fields.join(', ')} WHERE id = ?`).run(...values);

        const updated = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        Object.assign(updated, getUiTemplateCommentCounts(req.params.id));
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'edit_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { title: updated.title, refreshed_latest_rank: shouldRefreshLatestRank }
        });
        res.json({ template: sanitizeUiTemplateRow(updated, { viewer: { admin: req.admin, user: req.user }, includeContent: true }) });
    } catch (err) {
        console.error('Update UI template error:', err);
        res.status(500).json({ error: '更新 UI 模板失败' });
    }
});

app.delete('/api/ui-templates/:id', requireUserOrAdmin, (req, res) => {
    try {
        const template = db.prepare(
            `SELECT id, title, uploader_user_id, review_status, views_count, downloads_count,
                    ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
             FROM ui_templates WHERE id = ?`
        ).get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const isOwner = req.user && template.uploader_user_id === req.user.id;
        const isModerator = isModeratorUser(req.user);
        if (!req.admin && !isModerator && !isOwner) return res.status(403).json({ error: '无权删除此模板' });
        const isOwnerDelete = Boolean(!req.admin && !isModerator && isOwner);
        const shouldPenaltyCookies = Boolean(template.uploader_user_id && template.review_status === 'approved' && !isOwnerDelete && (req.admin || isModerator));
        const cookiePenalty = shouldPenaltyCookies ? getContentCookieValueFromHeatRow(template) : 0;

        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM ui_templates WHERE id = ?').run(req.params.id);
            if (template.uploader_user_id && template.review_status === 'approved') {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(template.uploader_user_id);
            }
            if (cookiePenalty > 0) {
                addNewApiCookiePenalty(template.uploader_user_id, cookiePenalty);
            }
        });
        deleteAndReclaim();
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: req.admin ? 'admin_delete_ui_template' : (isModerator ? 'moderator_delete_ui_template' : 'delete_ui_template'),
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { title: template.title, cookie_penalty: cookiePenalty }
        });
        res.json([{ id: req.params.id }]);
    } catch (err) {
        console.error('Delete UI template error:', err);
        res.status(500).json({ error: '删除模板失败' });
    }
});

app.get('/api/ui-templates/:id', optionalUserAuth, (req, res) => {
    try {
        markPerf(req, 'ui-template-detail-start', { id: req.params.id });
        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        markPerf(req, 'ui-template-detail-db-read', { found: Boolean(template), contentBytes: template ? Buffer.byteLength(template.content || '', 'utf8') : 0 });
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });
        template.already_downloaded = Boolean(req.user && db.prepare(
            'SELECT 1 FROM ui_template_downloads WHERE template_id = ? AND user_id = ? LIMIT 1'
        ).get(req.params.id, req.user.id));

        if (!req.admin && !isModeratorUser(req.user) && !(req.user && template.uploader_user_id === req.user.id)) {
            const viewLimit = recordAccountViewHeat(req, 'ui_template', req.params.id);
            markPerf(req, 'ui-template-detail-view-limit', viewLimit);
            if (viewLimit.counted) {
                db.prepare('UPDATE ui_templates SET views_count = views_count + 1 WHERE id = ?').run(req.params.id);
                template.views_count = (template.views_count || 0) + 1;
                markPerf(req, 'ui-template-detail-view-incremented', { viewsCount: template.views_count });
            }
        }
        Object.assign(template, getUiTemplateCommentCounts(req.params.id));
        markPerf(req, 'ui-template-detail-comments-counted');

        res.json(sanitizeUiTemplateRow(template, { includeContent: true, viewer: { admin: req.admin, user: req.user } }));
        markPerf(req, 'ui-template-detail-response-json');
    } catch (err) {
        console.error('Fetch UI template detail error:', err);
        res.status(500).json({ error: '获取 UI 模板详情失败' });
    }
});

function prepareUiTemplateDownload(req, templateId) {
    const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(templateId);
    if (!template) {
        const error = new Error('模板不存在');
        error.statusCode = 404;
        throw error;
    }
    const isOwner = req.user && template.uploader_user_id === req.user.id;
    const isModerator = isModeratorUser(req.user);
    if (template.review_status !== 'approved' && !req.admin && !isModerator && !isOwner) {
        const error = new Error('模板不存在');
        error.statusCode = 404;
        throw error;
    }

    let newCredits = null;
    let downloadCounted = false;
    let previouslyDownloaded = false;
    const recordDownload = db.transaction(() => {
        if (req.user && !isOwner && !isModerator) {
            previouslyDownloaded = Boolean(db.prepare(
                'SELECT 1 FROM ui_template_downloads WHERE template_id = ? AND user_id = ? LIMIT 1'
            ).get(templateId, req.user.id));
        }
        if (!req.admin && !isModerator) {
            if (!isOwner && !previouslyDownloaded) {
                const result = db.prepare('UPDATE users SET download_credits = download_credits - 1 WHERE id = ? AND download_credits > 0').run(req.user.id);
                if (result.changes === 0) {
                    const error = new Error('下载次数不足');
                    error.statusCode = 403;
                    throw error;
                }
            }
            newCredits = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(req.user.id)?.download_credits ?? null;
        }

        if (!isOwner && !req.admin && !isModerator && !previouslyDownloaded) {
            const inserted = db.prepare(
                `INSERT OR IGNORE INTO ui_template_downloads (template_id, user_id)
                 VALUES (?, ?)`
            ).run(templateId, req.user.id);
            if (inserted.changes > 0) {
                db.prepare('UPDATE ui_templates SET downloads_count = downloads_count + 1 WHERE id = ?').run(templateId);
                downloadCounted = true;
            }
        }
    });
    recordDownload();

    const latestDownloads = db.prepare('SELECT downloads_count FROM ui_templates WHERE id = ?').get(templateId)?.downloads_count ?? template.downloads_count ?? 0;
    return { template, newCredits, downloadCounted, downloadsCount: latestDownloads, previouslyDownloaded };
}

app.get('/api/ui-templates/:id/download', requireUserOrAdmin, (req, res) => {
    try {
        const { template } = prepareUiTemplateDownload(req, req.params.id);
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'download_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req)
        });

        const fileName = sanitizeUiTemplateFileName(template.file_name || `${template.title}.ui`);
        res.setHeader('Content-Type', template.mime_type || 'text/plain; charset=utf-8');
        res.setHeader('Content-Disposition', createAttachmentDisposition(fileName));
        res.send(template.content);
    } catch (err) {
        if (err.statusCode) {
            return res.status(err.statusCode).json({ error: err.message });
        }
        console.error('Download UI template error:', err);
        res.status(500).json({ error: '下载模板失败' });
    }
});

app.post('/api/ui-templates/:id/download', requireUserOrAdmin, (req, res) => {
    try {
        const result = prepareUiTemplateDownload(req, req.params.id);
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'download_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req)
        });

        res.json({
            success: true,
            new_credits: result.newCredits,
            download_counted: result.downloadCounted,
            downloads_count: result.downloadsCount,
            previously_downloaded: result.previouslyDownloaded,
            download_url: `/api/ui-templates/${encodeURIComponent(req.params.id)}/download/file`
        });
    } catch (err) {
        if (err.statusCode) {
            return res.status(err.statusCode).json({ error: err.message });
        }
        console.error('Prepare UI template download error:', err);
        res.status(500).json({ error: '下载模板失败' });
    }
});

app.get('/api/ui-templates/:id/download/file', optionalUserAuth, (req, res) => {
    try {
        const template = db.prepare('SELECT id, title, file_name, mime_type, content, review_status, uploader_user_id FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) {
            return res.status(404).json({ error: '模板不存在' });
        }

        const fileName = sanitizeUiTemplateFileName(template.file_name || `${template.title}.ui`);
        res.set('Content-Type', template.mime_type || 'text/plain; charset=utf-8');
        res.set('Cache-Control', 'no-store');
        res.set('Content-Disposition', createAttachmentDisposition(fileName));
        res.send(template.content);
    } catch (err) {
        console.error('Download UI template file error:', err);
        res.status(500).json({ error: '下载模板失败' });
    }
});

function buildPlaceholderSvg(name, seed, width, height, fontSize) {
    const firstChar = Array.from(((name || '?').trim() || '?'))[0] || '?';
    const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316', '#14b8a6', '#3b82f6', '#10b981'];
    const key = String(seed || name || '?');
    const colorIndex = Array.from(key).reduce((sum, char) => sum + char.charCodeAt(0), 0) % colors.length;
    const color = colors[colorIndex];
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <rect width="${width}" height="${height}" fill="${color}"/>
        <text x="${width / 2}" y="${height / 2 + fontSize * 0.08}" font-size="${fontSize}" fill="white" text-anchor="middle" dominant-baseline="middle" font-family="sans-serif">${firstChar}</text>
    </svg>`;
}

function isCorruptedAvatarUrl(avatarUrl, cardId) {
    if (!avatarUrl) return false;
    const normalized = String(avatarUrl).trim();
    if (!normalized) return false;
    if (normalized.startsWith('blob:') || normalized.startsWith('file:')) return true;
    return new RegExp(`/api/cards/${cardId}/(?:avatar|thumbnail|preview-image)(?:\\?.*)?$`, 'i').test(normalized);
}

function sanitizeAvatarUrl(avatarUrl, cardId) {
    if (!avatarUrl) return '';
    const normalized = String(avatarUrl).trim();
    if (!normalized || isCorruptedAvatarUrl(normalized, cardId)) return '';
    if (normalized.startsWith('data:')) return normalized;
    if (/^https?:\/\//i.test(normalized)) return normalized;
    return '';
}

function parseDataUrlAsset(dataUrl) {
    const match = String(dataUrl).match(/^data:([^;]+);base64,(.+)$/);
    if (!match) {
        throw new Error('无效的 data URL');
    }
    return {
        buffer: Buffer.from(match[2], 'base64'),
        contentType: match[1],
        cacheControl: 'public, max-age=604800, immutable'
    };
}

async function fetchRemoteAvatarAsset(url) {
    const parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('不支持的远程图片协议');
    }

    const host = parsedUrl.hostname.toLowerCase();
    const isPrivateIpAddress = (ipAddress) => {
        const ipVersion = net.isIP(ipAddress);
        if (ipVersion === 4) {
            if (ipAddress.startsWith('10.') || ipAddress.startsWith('127.') || ipAddress.startsWith('169.254.') || ipAddress.startsWith('192.168.')) {
                return true;
            }
            if (ipAddress.startsWith('172.')) {
                const secondOctet = Number(ipAddress.split('.')[1]);
                return secondOctet >= 16 && secondOctet <= 31;
            }
            return false;
        }
        if (ipVersion === 6) {
            const normalized = ipAddress.toLowerCase();
            return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80');
        }
        return false;
    };

    if (host === 'localhost' || host.endsWith('.local') || isPrivateIpAddress(host)) {
        throw new Error('不允许访问内网图片地址');
    }

    const resolved = await dns.lookup(host, { all: true, verbatim: true }).catch(() => []);
    if (resolved.some(entry => isPrivateIpAddress(entry.address))) {
        throw new Error('不允许访问内网图片地址');
    }

    for (let attempt = 0; attempt <= MAX_REMOTE_FETCH_RETRIES; attempt++) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REMOTE_FETCH_TIMEOUT_MS);
        try {
            const response = await fetch(url, {
                redirect: 'follow',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'RP-Forum-ImageProxy/1.0'
                }
            });
            if (!response.ok) {
                if (response.status >= 500 && attempt < MAX_REMOTE_FETCH_RETRIES) {
                    continue;
                }
                throw new Error(`远程图片请求失败: ${response.status}`);
            }

            const chunks = [];
            let totalBytes = 0;
            for await (const chunk of response.body) {
                totalBytes += chunk.length;
                if (totalBytes > MAX_REMOTE_IMAGE_BYTES) {
                    throw new Error('远程图片体积过大');
                }
                chunks.push(chunk);
            }

            const contentType = response.headers.get('content-type') || 'application/octet-stream';
            const cacheControl = response.headers.get('cache-control') || 'public, max-age=86400';
            return {
                buffer: Buffer.concat(chunks),
                contentType,
                cacheControl
            };
        } catch (error) {
            const shouldRetry = attempt < MAX_REMOTE_FETCH_RETRIES && (error.name === 'AbortError' || /远程图片请求失败: 5\d\d/.test(error.message));
            if (!shouldRetry) {
                throw error;
            }
        } finally {
            clearTimeout(timeout);
        }
    }

    throw new Error('远程图片请求失败');
}

async function resolveAvatarAsset(avatarUrl) {
    if (!avatarUrl) return null;
    if (avatarUrl.startsWith('data:')) {
        return parseDataUrlAsset(avatarUrl);
    }
    return fetchRemoteAvatarAsset(avatarUrl);
}

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const PNG_IHDR_END_OFFSET = 33;
const crc32Table = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let current = i;
    for (let bit = 0; bit < 8; bit++) {
        current = (current & 1) ? (0xEDB88320 ^ (current >>> 1)) : (current >>> 1);
    }
    crc32Table[i] = current >>> 0;
}

function crc32(buffer) {
    let crc = 0xFFFFFFFF;
    for (const value of buffer) {
        crc = (crc >>> 8) ^ crc32Table[(crc ^ value) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function sanitizeDownloadFilename(name) {
    const normalizedName = String(name || 'character-card')
        .trim()
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')
        .replace(/\s+/g, ' ')
        .replace(/[. ]+$/g, '') || 'character-card';
    const baseName = normalizedName
        .replace(/\.(png|jpe?g|webp|gif|bmp|svg)$/i, '')
        .slice(0, 120) || 'character-card';
    return `${baseName}.png`;
}

function createAttachmentDisposition(filename) {
    const asciiFallback = filename
        .replace(/[^\x20-\x7E]/g, '_')
        .replace(/["]/g, '_') || 'character-card.png';
    return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

function buildCardMetadataChunk(cardData) {
    const sanitized = sanitizeCardDataForStorage(cardData).value;
    const payload = Buffer.from(JSON.stringify(sanitized ?? null), 'utf8').toString('base64');
    const chunkData = Buffer.concat([
        Buffer.from('chara\0', 'latin1'),
        Buffer.from(payload, 'utf8')
    ]);
    const chunkType = Buffer.from('tEXt', 'ascii');
    const chunkLength = Buffer.alloc(4);
    chunkLength.writeUInt32BE(chunkData.length, 0);
    const chunkCrc = Buffer.alloc(4);
    chunkCrc.writeUInt32BE(crc32(Buffer.concat([chunkType, chunkData])), 0);
    return Buffer.concat([chunkLength, chunkType, chunkData, chunkCrc]);
}

const CARD_METADATA_CHUNK_KEYS = new Set([
    'chara',
    'ccv2',
    'ccv3',
    'character',
    'character_card',
    'character-card'
]);

function getPngTextChunkKeyword(type, chunkData) {
    if (!['tEXt', 'zTXt', 'iTXt'].includes(type)) return '';
    const splitIndex = chunkData.indexOf(0);
    if (splitIndex < 0) return '';
    return chunkData.subarray(0, splitIndex).toString('latin1').trim().toLowerCase();
}

function stripExistingCardMetadataChunks(pngBuffer) {
    const source = Buffer.isBuffer(pngBuffer) ? pngBuffer : Buffer.from(pngBuffer);
    if (source.length < PNG_IHDR_END_OFFSET || !source.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
        throw new Error('下载图片不是有效的 PNG 文件');
    }

    const parts = [source.subarray(0, PNG_SIGNATURE.length)];
    let offset = PNG_SIGNATURE.length;
    while (offset + 8 <= source.length) {
        const length = source.readUInt32BE(offset);
        const type = source.subarray(offset + 4, offset + 8).toString('ascii');
        const chunkStart = offset;
        const chunkEnd = offset + 12 + length;
        if (chunkEnd > source.length) {
            throw new Error('PNG 文件结构不完整');
        }

        const chunkData = source.subarray(offset + 8, offset + 8 + length);
        const keyword = getPngTextChunkKeyword(type, chunkData);
        const shouldStrip = keyword && CARD_METADATA_CHUNK_KEYS.has(keyword);
        if (!shouldStrip) {
            parts.push(source.subarray(chunkStart, chunkEnd));
        }

        offset = chunkEnd;
        if (type === 'IEND') break;
    }

    return Buffer.concat(parts);
}

function injectCardMetadataIntoPng(pngBuffer, cardData) {
    const source = stripExistingCardMetadataChunks(pngBuffer);
    if (source.length < PNG_IHDR_END_OFFSET || !source.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
        throw new Error('下载图片不是有效的 PNG 文件');
    }

    const metadataChunk = buildCardMetadataChunk(cardData);
    return Buffer.concat([
        source.subarray(0, PNG_IHDR_END_OFFSET),
        metadataChunk,
        source.subarray(PNG_IHDR_END_OFFSET)
    ]);
}

async function buildCardDownloadFile(card) {
    const safeAvatarUrl = sanitizeAvatarUrl(card.avatar_url, card.id);
    let pngBuffer = null;

    if (!safeAvatarUrl) {
        if (!sharp) {
            throw new Error('sharp 不可用，无法生成下载卡图片');
        }
        const placeholder = buildPlaceholderSvg(card.name, card.id, 800, 1067, 320);
        pngBuffer = await sharp(Buffer.from(placeholder)).png().toBuffer();
    } else {
        const asset = await resolveAvatarAsset(safeAvatarUrl);
        const contentType = String(asset.contentType || '').toLowerCase();
        if (contentType.includes('png') && Buffer.from(asset.buffer).subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
            pngBuffer = Buffer.from(asset.buffer);
        } else if (sharp) {
            pngBuffer = await sharp(asset.buffer).png().toBuffer();
        } else {
            throw new Error('sharp 不可用，无法转换下载卡图片');
        }
    }

    return injectCardMetadataIntoPng(pngBuffer, card.data);
}

const CARD_DOWNLOAD_CACHE_VERSION = 'card-download-v1';
const CARD_DOWNLOAD_CACHE_DIR = path.join(SERVER_DATA_DIR, 'card-download-cache');
const CARD_DOWNLOAD_MEMORY_MAX = 50;
const cardDownloadCache = new Map();
const cardDownloadBuildPromises = new Map();

function rememberCardDownload(cacheKey, buffer) {
    cardDownloadCache.delete(cacheKey);
    while (cardDownloadCache.size >= CARD_DOWNLOAD_MEMORY_MAX) {
        cardDownloadCache.delete(cardDownloadCache.keys().next().value);
    }
    cardDownloadCache.set(cacheKey, buffer);
    return buffer;
}

function makeCardDownloadCacheKey(card) {
    const signature = crypto.createHash('sha1')
        .update(CARD_DOWNLOAD_CACHE_VERSION)
        .update('\0')
        .update(String(card.id || ''))
        .update('\0')
        .update(String(card.avatar_url || ''))
        .update('\0')
        .update(JSON.stringify(card.data ?? null))
        .digest('hex')
        .slice(0, 24);
    return `${getCardCacheFilePrefix(card.id)}-${signature}.png`;
}

async function getCardDownloadFile(card) {
    const cacheKey = makeCardDownloadCacheKey(card);
    if (cardDownloadCache.has(cacheKey)) return rememberCardDownload(cacheKey, cardDownloadCache.get(cacheKey));

    const cachePath = path.join(CARD_DOWNLOAD_CACHE_DIR, cacheKey);
    try {
        const cached = await fs.promises.readFile(cachePath);
        return rememberCardDownload(cacheKey, cached);
    } catch {}

    if (cardDownloadBuildPromises.has(cacheKey)) return cardDownloadBuildPromises.get(cacheKey);
    const buildPromise = buildCardDownloadFile(card).then((buffer) => {
        rememberCardDownload(cacheKey, buffer);
        fs.promises.mkdir(CARD_DOWNLOAD_CACHE_DIR, { recursive: true })
            .then(() => fs.promises.writeFile(cachePath, buffer))
            .catch(err => console.warn('[CardDownload] cache write failed:', err.message));
        return buffer;
    }).finally(() => cardDownloadBuildPromises.delete(cacheKey));
    cardDownloadBuildPromises.set(cacheKey, buildPromise);
    return buildPromise;
}

function clearCardDownloadCache(cardId) {
    const prefix = `${getCardCacheFilePrefix(cardId)}-`;
    for (const key of cardDownloadCache.keys()) {
        if (key.startsWith(prefix)) cardDownloadCache.delete(key);
    }
    clearCardCacheFiles(CARD_DOWNLOAD_CACHE_DIR, cardId, 'card-download');
}

function warmCardDownloadCache(cardId) {
    setImmediate(() => {
        const card = db.prepare('SELECT id, name, avatar_url, data FROM character_cards WHERE id = ?').get(cardId);
        if (!card) return;
        try {
            card.data = card.data ? JSON.parse(card.data) : null;
        } catch {
            card.data = null;
        }
        getCardDownloadFile(card).catch(err => console.warn('[CardDownload] warmup failed:', err.message));
    });
}

function cacheThumbnail(cardId, body, contentType, cacheControl, cacheKey = '') {
    if (thumbnailCache.size >= THUMBNAIL_MAX_CACHE) {
        const firstKey = thumbnailCache.keys().next().value;
        thumbnailCache.delete(firstKey);
    }
    thumbnailCache.set(cardId, { body, contentType, cacheControl, cacheKey });
}

function getCachedThumbnail(cardId, expectedCacheKey = '') {
    const cached = thumbnailCache.get(cardId);
    if (!cached) return null;
    if (expectedCacheKey && cached.cacheKey !== expectedCacheKey) {
        thumbnailCache.delete(cardId);
        return null;
    }
    thumbnailCache.delete(cardId);
    thumbnailCache.set(cardId, cached);
    return cached;
}

function clearCardImageCaches(cardId) {
    thumbnailCache.delete(cardId);
    previewImageCache.delete(cardId);
    clearCardDownloadCache(cardId);
    clearCardCacheFiles(THUMBNAIL_CACHE_DIR, cardId, 'thumbnail');
    clearCardCacheFiles(PREVIEW_IMAGE_CACHE_DIR, cardId, 'preview-image');
}

app.get('/api/cards/:id/avatar', async (req, res) => {
    markPerf(req, 'avatar-redirect-start', { cardId: req.params.id });
    const query = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
    const target = `/api/cards/${encodeURIComponent(req.params.id)}/thumbnail${query}`;
    markPerf(req, 'avatar-redirect', { target });
    res.redirect(302, target);
});

// Thumbnail endpoint - compressed preview for card listing and detail cover.
const thumbnailCache = new Map();
const THUMBNAIL_MAX_CACHE = Math.max(100, parseInt(process.env.THUMBNAIL_MAX_CACHE || '1200', 10) || 1200);
const thumbnailBuildPromises = new Map();
const THUMBNAIL_CACHE_DIR = path.join(SERVER_DATA_DIR, 'thumbnail-cache');
const THUMBNAIL_CACHE_VERSION = 'thumbnail-v3-w800-q84';
const previewImageCache = new Map();
const PREVIEW_IMAGE_MAX_CACHE = 300;
const previewImageBuildPromises = new Map();
const PREVIEW_IMAGE_CACHE_DIR = path.join(SERVER_DATA_DIR, 'preview-image-cache');
const PREVIEW_IMAGE_CACHE_VERSION = 'preview-image-v2-w800-q84';
const REMOTE_FETCH_TIMEOUT_MS = 5000;
const MAX_REMOTE_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_REMOTE_FETCH_RETRIES = 2;

function getCardCacheFilePrefix(cardId) {
    return String(cardId || 'card').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80) || 'card';
}

function clearCardCacheFiles(cacheDir, cardId, label) {
    try {
        if (!fs.existsSync(cacheDir)) return;
        const prefix = `${getCardCacheFilePrefix(cardId)}-`;
        let removed = 0;
        for (const entry of fs.readdirSync(cacheDir, { withFileTypes: true })) {
            if (!entry.isFile() || !entry.name.startsWith(prefix)) continue;
            fs.rmSync(path.join(cacheDir, entry.name), { force: true });
            removed += 1;
        }
        if (removed > 0) console.info(`[ImageCache] cleared ${removed} ${label} file(s) for card=${cardId}`);
    } catch (err) {
        console.warn(`[ImageCache] failed to clear ${label} files for card=${cardId}:`, err.message);
    }
}

function ensureImageCacheVersion(cacheDir, version, label) {
    try {
        fs.mkdirSync(cacheDir, { recursive: true });
        const markerPath = path.join(cacheDir, '.cache-version');
        const currentVersion = fs.existsSync(markerPath) ? fs.readFileSync(markerPath, 'utf8').trim() : '';
        if (currentVersion === version) return;

        fs.writeFileSync(markerPath, version);
        console.info(`[ImageCache] ${label} cache version ${currentVersion || 'none'} -> ${version}, cleanup scheduled`);

        fs.promises.readdir(cacheDir, { withFileTypes: true })
            .then((entries) => {
                const targets = entries.filter(entry => entry.name !== '.cache-version');
                let index = 0;
                let removed = 0;
                const removeNextBatch = () => {
                    const batch = targets.slice(index, index + 25);
                    index += batch.length;
                    Promise.all(batch.map(entry => (
                        fs.promises.rm(path.join(cacheDir, entry.name), { recursive: true, force: true })
                            .then(() => { removed += 1; })
                            .catch(() => {})
                    ))).finally(() => {
                        if (index < targets.length) {
                            setTimeout(removeNextBatch, 20);
                        } else {
                            console.info(`[ImageCache] ${label} old cache cleanup complete removed=${removed}`);
                        }
                    });
                };
                removeNextBatch();
            })
            .catch((err) => console.warn(`[ImageCache] failed to list ${label} cache for cleanup:`, err.message));
    } catch (err) {
        console.warn(`[ImageCache] failed to prepare ${label} cache:`, err.message);
    }
}

function cleanupOutdatedImageCaches() {
    ensureImageCacheVersion(THUMBNAIL_CACHE_DIR, THUMBNAIL_CACHE_VERSION, 'thumbnail');
    ensureImageCacheVersion(PREVIEW_IMAGE_CACHE_DIR, PREVIEW_IMAGE_CACHE_VERSION, 'preview-image');
    ensureImageCacheVersion(CARD_DOWNLOAD_CACHE_DIR, CARD_DOWNLOAD_CACHE_VERSION, 'card-download');
}

function warmPublicAssetCache() {
    ['index.html', 'admin.html'].forEach(fileName => {
        try {
            const asset = getCachedHtmlAsset(fileName);
            console.info(`[AssetCache] warmed html ${fileName} bytes=${asset.body.length} gzip=${asset.gzip.length}`);
        } catch (err) {
            console.warn(`[AssetCache] failed to warm html ${fileName}:`, err.message);
        }
    });
    for (const fileName of CACHED_PUBLIC_ASSETS) {
        try {
            const asset = getCachedPublicAsset(fileName);
            console.info(`[AssetCache] warmed asset ${fileName} bytes=${asset.body.length} gzip=${asset.gzip.length}`);
        } catch (err) {
            console.warn(`[AssetCache] failed to warm asset ${fileName}:`, err.message);
        }
    }
}

function makeThumbnailCacheKey(cardId, row) {
    const signature = crypto
        .createHash('sha1')
        .update(THUMBNAIL_CACHE_VERSION)
        .update('\0')
        .update(String(cardId || ''))
        .update('\0')
        .update(String(row?.name || ''))
        .update('\0')
        .update(String(row?.avatar_url || ''))
        .digest('hex')
        .slice(0, 24);
    const safeId = getCardCacheFilePrefix(cardId);
    return `${safeId}-${signature}.webp`;
}

function getThumbnailCachePath(cacheKey) {
    return path.join(THUMBNAIL_CACHE_DIR, cacheKey);
}

async function readThumbnailFromDisk(cacheKey) {
    try {
        const body = await fs.promises.readFile(getThumbnailCachePath(cacheKey));
        return {
            body,
            contentType: 'image/webp',
            cacheControl: 'public, max-age=2592000, immutable'
        };
    } catch {
        return null;
    }
}

async function writeThumbnailToDisk(cacheKey, body) {
    try {
        await fs.promises.mkdir(THUMBNAIL_CACHE_DIR, { recursive: true });
        const finalPath = getThumbnailCachePath(cacheKey);
        const tempPath = `${finalPath}.${process.pid}.${Date.now()}.tmp`;
        await fs.promises.writeFile(tempPath, body);
        await fs.promises.rename(tempPath, finalPath);
    } catch (err) {
        console.warn('[Thumbnail] disk cache write failed:', err.message);
    }
}

function writeThumbnailToDiskLater(cacheKey, body) {
    writeThumbnailToDisk(cacheKey, body)
        .then(() => console.info(`[Thumbnail] disk cache written key=${cacheKey} bytes=${body.length}`))
        .catch((err) => console.warn('[Thumbnail] background disk cache write failed:', err.message));
}

function cachePreviewImage(cardId, body, contentType, cacheControl, cacheKey = '') {
    if (previewImageCache.size >= PREVIEW_IMAGE_MAX_CACHE) {
        const firstKey = previewImageCache.keys().next().value;
        previewImageCache.delete(firstKey);
    }
    previewImageCache.set(cardId, { body, contentType, cacheControl, cacheKey });
}

function makePreviewImageCacheKey(cardId, row) {
    const signature = crypto
        .createHash('sha1')
        .update(PREVIEW_IMAGE_CACHE_VERSION)
        .update('\0')
        .update(String(cardId || ''))
        .update('\0')
        .update(String(row?.name || ''))
        .update('\0')
        .update(String(row?.avatar_url || ''))
        .digest('hex')
        .slice(0, 24);
    const safeId = getCardCacheFilePrefix(cardId);
    return `${safeId}-${signature}.webp`;
}

function getPreviewImageCachePath(cacheKey) {
    return path.join(PREVIEW_IMAGE_CACHE_DIR, cacheKey);
}

async function readPreviewImageFromDisk(cacheKey) {
    try {
        const body = await fs.promises.readFile(getPreviewImageCachePath(cacheKey));
        return {
            body,
            contentType: 'image/webp',
            cacheControl: 'public, max-age=2592000, immutable'
        };
    } catch {
        return null;
    }
}

async function writePreviewImageToDisk(cacheKey, body) {
    try {
        await fs.promises.mkdir(PREVIEW_IMAGE_CACHE_DIR, { recursive: true });
        const finalPath = getPreviewImageCachePath(cacheKey);
        const tempPath = `${finalPath}.${process.pid}.${Date.now()}.tmp`;
        await fs.promises.writeFile(tempPath, body);
        await fs.promises.rename(tempPath, finalPath);
    } catch (err) {
        console.warn('[PreviewImage] disk cache write failed:', err.message);
    }
}

function writePreviewImageToDiskLater(cacheKey, body) {
    writePreviewImageToDisk(cacheKey, body)
        .then(() => console.info(`[PreviewImage] disk cache written key=${cacheKey} bytes=${body.length}`))
        .catch((err) => console.warn('[PreviewImage] background disk cache write failed:', err.message));
}

app.get('/api/cards/:id/thumbnail', async (req, res) => {
    try {
        const cardId = req.params.id;
        markPerf(req, 'thumbnail-start', { cardId });

        // Hot path: edits/deletes clear this memory cache, so repeated list renders
        // should not touch SQLite or sharp at all.
        const hotCached = getCachedThumbnail(cardId);
        if (hotCached) {
            const cached = hotCached;
            markPerf(req, 'thumbnail-memory-hit', { bytes: cached.body.length });
            res.set('Content-Type', cached.contentType);
            res.set('Cache-Control', cached.cacheControl);
            return res.send(cached.body);
        }

        const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(cardId);
        markPerf(req, 'thumbnail-db-read', { found: Boolean(row) });
        if (!row) return res.status(404).end();
        const safeAvatarUrl = sanitizeAvatarUrl(row.avatar_url, cardId);
        const cacheKey = makeThumbnailCacheKey(cardId, row);

        // Check memory cache
        const cached = getCachedThumbnail(cardId, cacheKey);
        if (cached) {
            markPerf(req, 'thumbnail-memory-hit', { bytes: cached.body.length });
            res.set('Content-Type', cached.contentType);
            res.set('Cache-Control', cached.cacheControl);
            return res.send(cached.body);
        }

        const diskCached = await readThumbnailFromDisk(cacheKey);
        if (diskCached) {
            markPerf(req, 'thumbnail-disk-hit', { bytes: diskCached.body.length });
            cacheThumbnail(cardId, diskCached.body, diskCached.contentType, diskCached.cacheControl, cacheKey);
            res.set('Content-Type', diskCached.contentType);
            res.set('Cache-Control', diskCached.cacheControl);
            return res.send(diskCached.body);
        }

        if (thumbnailBuildPromises.has(cacheKey)) {
            markPerf(req, 'thumbnail-wait-existing-build');
            const generated = await thumbnailBuildPromises.get(cacheKey);
            cacheThumbnail(cardId, generated.body, generated.contentType, generated.cacheControl, cacheKey);
            res.set('Content-Type', generated.contentType);
            res.set('Cache-Control', generated.cacheControl);
            return res.send(generated.body);
        }

        const buildThumbnail = async () => {
            // No avatar data — generate placeholder thumbnail with first character
            if (!safeAvatarUrl) {
                const svg = buildPlaceholderSvg(row.name, cardId, 800, 1067, 320);
                if (!sharp) {
                    return {
                        body: Buffer.from(svg),
                        contentType: 'image/svg+xml',
                        cacheControl: 'public, max-age=86400'
                    };
                }
                const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 84 }).toBuffer();
                return {
                    body: placeholder,
                    contentType: 'image/webp',
                    cacheControl: 'public, max-age=2592000, immutable',
                    persist: true
                };
            }

            if (!sharp) {
                const svg = buildPlaceholderSvg(row.name, cardId, 800, 1067, 320);
                return {
                    body: Buffer.from(svg),
                    contentType: 'image/svg+xml',
                    cacheControl: 'public, max-age=86400'
                };
            }

            markPerf(req, 'thumbnail-resolve-asset-start');
            const asset = await resolveAvatarAsset(safeAvatarUrl);
            markPerf(req, 'thumbnail-resolve-asset-done', { bytes: asset.buffer.length, contentType: asset.contentType });

            const thumbnail = await sharp(asset.buffer)
                .resize(800, null)
                .webp({ quality: 84 })
                .toBuffer();

            markPerf(req, 'thumbnail-sharp-generate', { bytes: thumbnail.length });
            return {
                body: thumbnail,
                contentType: 'image/webp',
                cacheControl: 'public, max-age=2592000, immutable',
                persist: true
            };
        };

        const buildPromise = buildThumbnail();
        thumbnailBuildPromises.set(cacheKey, buildPromise);
        const generated = await buildPromise;
        thumbnailBuildPromises.delete(cacheKey);
        cacheThumbnail(cardId, generated.body, generated.contentType, generated.cacheControl, cacheKey);

        res.set('Content-Type', generated.contentType);
        res.set('Cache-Control', generated.cacheControl);
        res.send(generated.body);
        markPerf(req, 'thumbnail-response', { bytes: generated.body.length });
        if (generated.persist) {
            markPerf(req, 'thumbnail-disk-write-queued', { bytes: generated.body.length });
            writeThumbnailToDiskLater(cacheKey, generated.body);
        }
    } catch (err) {
        if (req.params?.id) {
            const cacheKeyPrefix = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
            for (const key of thumbnailBuildPromises.keys()) {
                if (key.startsWith(cacheKeyPrefix)) thumbnailBuildPromises.delete(key);
            }
        }
        console.error('Thumbnail generation error:', err);
        try {
            const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(req.params.id);
            if (row) {
                const svg = buildPlaceholderSvg(row.name, req.params.id, 800, 1067, 320);
                if (!sharp) {
                    res.set('Content-Type', 'image/svg+xml');
                    res.set('Cache-Control', 'public, max-age=86400');
                    return res.send(svg);
                }
                const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 84 }).toBuffer();
                res.set('Content-Type', 'image/webp');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(placeholder);
            }
        } catch {}
        res.status(500).end();
    }
});

app.get('/api/cards/:id/preview-image', async (req, res) => {
    try {
        const cardId = req.params.id;
        markPerf(req, 'preview-image-start', { cardId });

        if (previewImageCache.has(cardId)) {
            const cached = previewImageCache.get(cardId);
            markPerf(req, 'preview-image-memory-hit', { bytes: cached.body.length });
            res.set('Content-Type', cached.contentType);
            res.set('Cache-Control', cached.cacheControl);
            return res.send(cached.body);
        }

        const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(cardId);
        markPerf(req, 'preview-image-db-read', { found: Boolean(row) });
        if (!row) return res.status(404).end();
        const safeAvatarUrl = sanitizeAvatarUrl(row.avatar_url, cardId);
        const cacheKey = makePreviewImageCacheKey(cardId, row);

        const diskCached = await readPreviewImageFromDisk(cacheKey);
        if (diskCached) {
            markPerf(req, 'preview-image-disk-hit', { bytes: diskCached.body.length });
            cachePreviewImage(cardId, diskCached.body, diskCached.contentType, diskCached.cacheControl, cacheKey);
            res.set('Content-Type', diskCached.contentType);
            res.set('Cache-Control', diskCached.cacheControl);
            return res.send(diskCached.body);
        }

        if (previewImageBuildPromises.has(cacheKey)) {
            markPerf(req, 'preview-image-wait-existing-build');
            const generated = await previewImageBuildPromises.get(cacheKey);
            cachePreviewImage(cardId, generated.body, generated.contentType, generated.cacheControl, cacheKey);
            res.set('Content-Type', generated.contentType);
            res.set('Cache-Control', generated.cacheControl);
            return res.send(generated.body);
        }

        const buildPreviewImage = async () => {
            if (!safeAvatarUrl) {
                const svg = buildPlaceholderSvg(row.name, cardId, 800, 1067, 320);
                if (!sharp) {
                    return {
                        body: Buffer.from(svg),
                        contentType: 'image/svg+xml',
                        cacheControl: 'public, max-age=86400'
                    };
                }
                const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 84 }).toBuffer();
                return {
                    body: placeholder,
                    contentType: 'image/webp',
                    cacheControl: 'public, max-age=2592000, immutable',
                    persist: true
                };
            }

            if (!sharp) {
                const svg = buildPlaceholderSvg(row.name, cardId, 800, 1067, 320);
                return {
                    body: Buffer.from(svg),
                    contentType: 'image/svg+xml',
                    cacheControl: 'public, max-age=86400'
                };
            }

            markPerf(req, 'preview-image-resolve-asset-start');
            const asset = await resolveAvatarAsset(safeAvatarUrl);
            markPerf(req, 'preview-image-resolve-asset-done', { bytes: asset.buffer.length, contentType: asset.contentType });

            const preview = await sharp(asset.buffer)
                .resize(800, null)
                .webp({ quality: 84 })
                .toBuffer();

            markPerf(req, 'preview-image-sharp-generate', { bytes: preview.length });
            return {
                body: preview,
                contentType: 'image/webp',
                cacheControl: 'public, max-age=2592000, immutable',
                persist: true
            };
        };

        const buildPromise = buildPreviewImage();
        previewImageBuildPromises.set(cacheKey, buildPromise);
        const generated = await buildPromise;
        previewImageBuildPromises.delete(cacheKey);
        cachePreviewImage(cardId, generated.body, generated.contentType, generated.cacheControl, cacheKey);

        res.set('Content-Type', generated.contentType);
        res.set('Cache-Control', generated.cacheControl);
        res.send(generated.body);
        markPerf(req, 'preview-image-response', { bytes: generated.body.length });
        if (generated.persist) {
            markPerf(req, 'preview-image-disk-write-queued', { bytes: generated.body.length });
            writePreviewImageToDiskLater(cacheKey, generated.body);
        }
    } catch (err) {
        if (req.params?.id) {
            const cacheKeyPrefix = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
            for (const key of previewImageBuildPromises.keys()) {
                if (key.startsWith(cacheKeyPrefix)) previewImageBuildPromises.delete(key);
            }
        }
        console.error('Preview image generation error:', err);
        try {
            const row = db.prepare('SELECT name FROM character_cards WHERE id = ?').get(req.params.id);
            if (!row) return res.status(404).end();
            const svg = buildPlaceholderSvg(row.name, req.params.id, 800, 1067, 320);
            if (!sharp) {
                res.set('Content-Type', 'image/svg+xml');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(svg);
            }
            const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 84 }).toBuffer();
            res.set('Content-Type', 'image/webp');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(placeholder);
        } catch (fallbackError) {
            console.error('Preview image placeholder fallback error:', fallbackError);
            res.status(500).end();
        }
    }
});

app.get('/api/cards/:id', optionalUserAuth, (req, res) => {
    try {
        markPerf(req, 'card-detail-start', { id: req.params.id });
        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.description, cc.detail_preview,
                    cc.has_ui_templates, cc.ui_template_count, cc.ui_template_variable_count,
                    cc.creator_notes, cc.downloads_count, cc.comment_count_override,
                    cc.uploader_user_id, cc.review_status, cc.reviewed_by_admin_id,
                    cc.reviewed_at, cc.rejection_reason, cc.uploader_ip_address,
                    cc.heat_email_milestone, cc.created_at, cc.latest_rank_at, cc.updated_at,
                    cc.views_count, cc.is_featured
             FROM character_cards cc
             WHERE cc.id = ?`
        ).get(req.params.id);
        markPerf(req, 'card-detail-db-read', {
            found: Boolean(card),
            previewBytes: card ? Buffer.byteLength(card.detail_preview || '', 'utf8') : 0,
            reviewStatus: card?.review_status || null
        });
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const canView = isPublicCardStatus(card.review_status)
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && card.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '卡片不存在' });
        card.already_downloaded = Boolean(req.user && db.prepare(
            'SELECT 1 FROM card_downloads WHERE card_id = ? AND user_id = ? LIMIT 1'
        ).get(req.params.id, req.user.id));
        if (!parseCardDetailPreview(card.detail_preview)) {
            const rawDataRow = db.prepare('SELECT data FROM character_cards WHERE id = ?').get(req.params.id);
            markPerf(req, 'card-detail-preview-miss-read-data', {
                dataBytes: rawDataRow ? Buffer.byteLength(rawDataRow.data || '', 'utf8') : 0
            });
            const previewJson = buildCardDetailPreviewJson(rawDataRow?.data || null, {
                name: card.name,
                description: card.description || ''
            });
            db.prepare('UPDATE character_cards SET detail_preview = ? WHERE id = ?').run(previewJson, req.params.id);
            card.detail_preview = previewJson;
            markPerf(req, 'card-detail-preview-built', { previewBytes: Buffer.byteLength(previewJson, 'utf8') });
        }
        Object.assign(card, getCardMetrics(req.params.id, { viewer: { admin: req.admin, user: req.user } }));
        markPerf(req, 'card-detail-metrics');
        attachCardDetailPreview(card);
        markPerf(req, 'card-detail-preview-attached');
        attachUiTemplateSummary(card, { preferStoredSummary: true });
        markPerf(req, 'card-detail-summary');
        res.json(sanitizeCharacterCardForClient(card, { viewer: { admin: req.admin, user: req.user } }));
        markPerf(req, 'card-detail-response-json');
    } catch (err) {
        console.error('Fetch card detail error:', err);
        res.status(500).json({ error: '获取卡片详情失败' });
    }
});

app.post('/api/cards', requireUserOrAdmin, (req, res) => {
    try {
        const { name, description, avatar_url, data, creator_notes } = req.body;
        const publishMode = req.body.publish_mode === 'unreviewed' ? 'unreviewed' : 'reviewed';
        if (!name) {
            return res.status(400).json({ error: '卡片名称不能为空' });
        }

        if (!hasRpHubWatermark(data)) {
            return res.status(400).json({ error: NON_RPH_CARD_UPLOAD_MESSAGE });
        }

        // File size check: estimate original size from base64 avatar_url
        if (avatar_url && typeof avatar_url === 'string' && avatar_url.startsWith('data:')) {
            const base64Part = avatar_url.split(',')[1] || '';
            const estimatedBytes = Math.ceil(base64Part.length * 3 / 4);
            if (estimatedBytes > MAX_UPLOAD_SIZE_BYTES) {
                return res.status(400).json({ error: `文件大小超过 30MB 限制 (${(estimatedBytes / 1024 / 1024).toFixed(1)}MB)` });
            }
        }

        // Upload rate limiting (admin exempt)
        if (!req.admin) {
            const rateKey = req.user ? `user:${req.user.id}` : `ip:${getRequestIp(req)}`;
            if (!checkUploadRate(rateKey)) {
                return res.status(429).json({ error: '上传太频繁，每分钟最多上传 2 张角色卡，请稍后再试' });
            }
            recordUpload(rateKey);
        }

        const sanitizedCardData = sanitizeCardDataForStorage(data).value;

        // Duplicate detection via stable hash of card data (atomic via UNIQUE index)
        const dataHash = hashCardData(sanitizedCardData);
        if (dataHash) {
            const existing = db.prepare('SELECT id, name FROM character_cards WHERE data_hash = ?').get(dataHash);
            if (existing) {
                return res.status(409).json({ error: `已存在完全相同的角色卡「${existing.name}」，禁止重复上传` });
            }
        }

        const id = generateId();
        const now = new Date().toISOString();
        const dataStr = sanitizedCardData ? JSON.stringify(sanitizedCardData) : null;
        const uiSummary = buildCardUiTemplateSummary(dataStr);
        const detailPreview = buildCardDetailPreviewJson(dataStr, {
            name,
            description: description || ''
        });
        const uploaderUserId = req.user ? req.user.id : null;
        const safeAvatarUrl = sanitizeAvatarUrl(avatar_url, id);
        let reviewStatus = publishMode === 'unreviewed' ? 'ai_pending' : (req.admin ? 'approved' : 'pending');
        const reviewedBy = reviewStatus === 'approved' ? req.admin.id : null;
        const reviewedAt = reviewStatus === 'approved' ? now : null;
        const uploaderIp = getRequestIp(req);

        try {
            db.prepare(
                `INSERT INTO character_cards
                 (id, name, description, avatar_url, data, detail_preview, has_ui_templates, ui_template_count, ui_template_variable_count,
                  creator_notes, uploader_user_id, data_hash, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at, latest_rank_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(
                id, name, description || '', safeAvatarUrl, dataStr, detailPreview,
                uiSummary.has_ui_templates, uiSummary.ui_template_count, uiSummary.ui_template_variable_count,
                creator_notes || '', uploaderUserId, dataHash, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now, now, now
            );
        } catch (insertErr) {
            if (insertErr.message && insertErr.message.includes('UNIQUE constraint failed')) {
                const conflict = db.prepare('SELECT name FROM character_cards WHERE data_hash = ?').get(dataHash);
                return res.status(409).json({ error: `已存在完全相同的角色卡「${conflict?.name || '未知'}」，禁止重复上传` });
            }
            // If FOREIGN KEY fails (user doesn't exist in DB), retry without uploader_user_id
            if (insertErr.message && insertErr.message.includes('FOREIGN KEY')) {
                db.prepare(
                    `INSERT INTO character_cards
                      (id, name, description, avatar_url, data, detail_preview, has_ui_templates, ui_template_count, ui_template_variable_count,
                       creator_notes, uploader_user_id, data_hash, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at, latest_rank_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).run(
                    id, name, description || '', safeAvatarUrl, dataStr, detailPreview,
                    uiSummary.has_ui_templates, uiSummary.ui_template_count, uiSummary.ui_template_variable_count,
                    creator_notes || '', null, dataHash, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now, now, now
                );
            } else {
                throw insertErr;
            }
        }
        syncCardTags(id, creator_notes || '');

        if (reviewStatus === 'ai_pending') {
            try {
                enqueueAiCardReview(id);
            } catch (queueErr) {
                console.error('AI review enqueue error:', queueErr);
                db.prepare("UPDATE character_cards SET review_status = 'unreviewed' WHERE id = ?").run(id);
                reviewStatus = 'unreviewed';
            }
        }

        const card = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(id);
        attachCardDetailPreview(card);
        attachUiTemplateSummary(card, { preferStoredSummary: true });
        clearCardListCache('card-upload');
        logOperation({
            userType: req.user ? 'user' : 'admin',
            userId: uploaderUserId || req.admin?.id,
            username: req.user?.username || req.admin?.username,
            action: reviewStatus === 'ai_pending'
                ? 'upload_ai_review_pending'
                : (reviewStatus === 'unreviewed' ? 'upload_unreviewed' : (req.admin ? 'upload' : 'upload_pending')),
            targetType: 'card',
            targetId: id,
            ip: uploaderIp,
            details: { name, review_status: reviewStatus }
        });
        if (reviewStatus === 'pending') {
            sendAdminReviewPendingEmail({
                itemType: '角色卡',
                title: name,
                uploader: req.user?.username || '',
                ip: uploaderIp
            });
        }
        warmCardDownloadCache(id);

        res.json([
            sanitizeCharacterCardForClient(card, { viewer: { admin: req.admin, user: req.user } }),
            {
                pending_review: reviewStatus === 'pending',
                ai_review_pending: reviewStatus === 'ai_pending',
                unreviewed: reviewStatus === 'unreviewed'
            }
        ]);
    } catch (err) {
        console.error('Create card error:', err);
        res.status(500).json({ error: '创建卡片失败' });
    }
});

app.delete('/api/cards/:id', (req, res) => {
    const token = getRequestAuthToken(req);
    if (!token) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        let isAdmin = false;
        let isModerator = false;
        let userId = null;
        let username = '';
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'admin') {
                if (!isAdminCookieToken(req, token)) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
                const admin = validateAdminTokenPayload(decoded);
                if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
                isAdmin = true;
                userId = admin.id;
                username = admin.username || '';
            } else {
                const user = validateUserTokenPayload(decoded);
                if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
                if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
                userId = user.id;
                username = user.username || '';
                isModerator = isModeratorUser(user);
            }
        } catch {
            return res.status(401).json({ error: '认证失败' });
        }

        const { id } = req.params;
        const card = db.prepare(
            `SELECT name, uploader_user_id, review_status, views_count, downloads_count,
                    ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
             FROM character_cards WHERE id = ?`
        ).get(id);
        if (!card) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        // Only admin, front-end moderator, or card owner can delete.
        const ownerUserId = card.uploader_user_id == null ? null : Number(card.uploader_user_id);
        if (!isAdmin && !isModerator && (!userId || ownerUserId !== Number(userId))) {
            return res.status(403).json({ error: '无权删除此卡片' });
        }
        const isOwnerDelete = Boolean(!isAdmin && ownerUserId && userId && ownerUserId === Number(userId));
        const shouldPenaltyCookies = Boolean(card.uploader_user_id && card.review_status === 'approved' && !isOwnerDelete && (isAdmin || isModerator));
        const cookiePenalty = shouldPenaltyCookies ? getContentCookieValueFromHeatRow(card) : 0;

        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(id);
            // Reclaim upload credits (3) from uploader, minimum 0
            if (card.uploader_user_id && card.review_status === 'approved') {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
            if (cookiePenalty > 0) {
                addNewApiCookiePenalty(card.uploader_user_id, cookiePenalty);
            }
        });
        deleteAndReclaim();
        clearCardImageCaches(id);
        clearCardListCache('card-delete');

        logOperation({
            userType: isAdmin ? 'admin' : 'user',
            userId,
            username,
            action: isAdmin ? 'admin_delete_card' : (isModerator ? 'moderator_delete_card' : 'delete'),
            targetType: 'card',
            targetId: id,
            ip: getRequestIp(req),
            details: { name: card?.name, cookie_penalty: cookiePenalty }
        });
        res.json([{ id }]);
    } catch (err) {
        console.error('Delete card error:', err);
        res.status(500).json({ error: '删除卡片失败' });
    }
});

app.put('/api/cards/:id', (req, res) => {
    // Authenticate: card owner OR admin
    const token = getRequestAuthToken(req);
    if (!token) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const card = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        let userType, userId, username;
        if (decoded.role === 'admin') {
            if (!isAdminCookieToken(req, token)) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            userType = 'admin'; userId = admin.id; username = admin.username;
        } else if (decoded.role === 'user' && card.uploader_user_id === decoded.id) {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (isModeratorUser(user)) return res.status(403).json({ error: '审核员不能编辑角色卡' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            if (card.uploader_user_id !== user.id) return res.status(403).json({ error: '无权编辑此卡片' });
            userType = 'user'; userId = user.id; username = user.username;
        } else {
            return res.status(403).json({ error: '无权编辑此卡片' });
        }
        if (userType === 'user' && card.review_status === 'ai_pending') {
            return res.status(409).json({ error: 'AI 审核处理中，请稍后再编辑' });
        }

        const { name, description, avatar_url, data, creator_notes, created_at, reupload_replace } = req.body;
        const fields = [];
        const values = [];
        const hasDataUpdate = data !== undefined && data !== null;
        const hasReviewContentUpdate = hasDataUpdate || name !== undefined || description !== undefined;
        let needsAiReview = false;
        const shouldRefreshLatestRank = reupload_replace === true && hasDataUpdate;
        const nextName = name !== undefined ? name : card.name;
        const nextDescription = description !== undefined ? description : card.description;
        const nextCreatorNotes = creator_notes !== undefined ? creator_notes : card.creator_notes;
        let nextAvatarUrl = avatar_url !== undefined ? sanitizeAvatarUrl(avatar_url, req.params.id) : card.avatar_url;
        let detailPreviewDataSource = card.data || null;
        if (name !== undefined)          { fields.push('name = ?');          values.push(name); }
        if (description !== undefined)   { fields.push('description = ?');   values.push(description); }
        if (avatar_url !== undefined) {
            if (nextAvatarUrl) {
                fields.push('avatar_url = ?');
                values.push(nextAvatarUrl);
            }
        }
        if (hasDataUpdate) {
            let serializedData;
            let parsedData;
            try {
                serializedData = typeof data === 'string' ? data : JSON.stringify(data);
                parsedData = JSON.parse(serializedData);
            } catch (parseError) {
                return res.status(400).json({ error: '卡片数据格式无效' });
            }
            if (decoded.role === 'user' && !hasRpHubWatermark(parsedData)) {
                return res.status(400).json({ error: NON_RPH_CARD_UPLOAD_MESSAGE });
            }
            const sanitizedData = sanitizeCardDataForStorage(parsedData).value;
            serializedData = sanitizedData ? JSON.stringify(sanitizedData) : serializedData;
            fields.push('data = ?');
            values.push(serializedData);
            detailPreviewDataSource = serializedData;
            pushCardUiTemplateSummaryUpdate(fields, values, serializedData);
        }
        if (creator_notes !== undefined) { fields.push('creator_notes = ?'); values.push(creator_notes); }
        if (created_at !== undefined && decoded.role === 'admin') {
            if (isNaN(Date.parse(created_at))) return res.status(400).json({ error: '无效的时间格式' });
            fields.push('created_at = ?'); values.push(created_at);
        }
        if (decoded.role === 'user' && hasReviewContentUpdate) {
            const wasAiReviewed = Boolean(db.prepare('SELECT 1 FROM ai_review_queue WHERE card_id = ?').get(req.params.id));
            needsAiReview = card.review_status === 'unreviewed' || wasAiReviewed;
            fields.push(needsAiReview ? "review_status = 'ai_pending'" : "review_status = 'pending'");
            fields.push('reviewed_by_admin_id = NULL');
            fields.push('reviewed_at = NULL');
            fields.push('rejection_reason = NULL');
        }
        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        detailPreviewDataSource = syncCardEditableFieldsIntoData(detailPreviewDataSource, {
            name: nextName,
            description: nextDescription || '',
            creator_notes: nextCreatorNotes || '',
            avatar_url: nextAvatarUrl || ''
        });
        if (detailPreviewDataSource) {
            if (!hasDataUpdate) {
                fields.push('data = ?');
                values.push(detailPreviewDataSource);
                pushCardUiTemplateSummaryUpdate(fields, values, detailPreviewDataSource);
            } else {
                const dataFieldIndex = fields.findIndex(field => field === 'data = ?');
                let valueIndex = 0;
                for (let i = 0; i < dataFieldIndex; i++) {
                    valueIndex += fields[i].split('?').length - 1;
                }
                if (dataFieldIndex >= 0) values[valueIndex] = detailPreviewDataSource;
            }
            fields.push('data_hash = ?');
            values.push(hashCardData(parseStoredCardData(detailPreviewDataSource) || detailPreviewDataSource));
        }
        fields.push('detail_preview = ?');
        values.push(buildCardDetailPreviewJson(detailPreviewDataSource, {
            name: nextName,
            description: nextDescription || ''
        }));
        const editTime = new Date().toISOString();
        fields.push('updated_at = ?');
        values.push(editTime);
        if (shouldRefreshLatestRank) {
            fields.push('latest_rank_at = ?');
            values.push(editTime);
        }
        values.push(req.params.id);
        const updateCard = db.transaction(() => {
            db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        });
        updateCard();
        syncCardTags(req.params.id, nextCreatorNotes || '');
        if (needsAiReview) {
            try {
                enqueueAiCardReview(req.params.id);
            } catch (queueErr) {
                console.error('AI review requeue error:', queueErr);
                db.prepare("UPDATE character_cards SET review_status = 'unreviewed' WHERE id = ?").run(req.params.id);
            }
        }
        clearCardImageCaches(req.params.id);
        warmCardDownloadCache(req.params.id);
        clearCardListCache('card-edit');

        logOperation({
            userType,
            userId,
            username,
            action: 'edit',
            targetType: 'card',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { name: card.name, refreshed_latest_rank: shouldRefreshLatestRank }
        });

        const updated = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(req.params.id);
        attachCardDetailPreview(updated);
        attachUiTemplateSummary(updated, { preferStoredSummary: true });
        res.json([sanitizeCharacterCardForClient(updated, { viewer: { admin: req.admin, user: req.user } })]);
    } catch (err) {
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: '令牌无效或已过期' });
        }
        if (err.message && err.message.includes('UNIQUE constraint failed') && err.message.includes('data_hash')) {
            return res.status(409).json({ error: '已存在完全相同的角色卡，禁止重复上传' });
        }
        console.error('Update card error:', err);
        res.status(500).json({ error: '更新卡片失败' });
    }
});

// ============== Card Featured Toggle (Admin Only) ==============
app.put('/api/cards/:id/feature', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.is_featured, cc.review_status,
                    u.username, u.email, u.email_verified
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ?`
        ).get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        if (['unreviewed', 'ai_pending'].includes(card.review_status)) {
            return res.status(400).json({ error: '无收益专区角色卡不能设为精选' });
        }

        const newFeatured = card.is_featured ? 0 : 1;
        db.prepare('UPDATE character_cards SET is_featured = ? WHERE id = ?').run(newFeatured, id);
        clearCardListCache('card-feature');

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: newFeatured ? 'feature' : 'unfeature',
            targetType: 'card', targetId: id, ip: getRequestIp(req),
            details: { name: card.name }
        });
        if (newFeatured && userEmailBound(card)) {
            sendFeaturedNotificationEmail({
                to: card.email,
                username: card.username,
                itemType: '角色卡',
                title: card.name
            });
        }

        res.json({ id, is_featured: newFeatured });
    } catch (err) {
        console.error('Feature card error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

// ============== Card Heat Adjustment (Admin or Moderator) ==============
app.put('/api/cards/:id/heat', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare(
            `SELECT id, name, views_count, downloads_count,
                    ${cardCommentCountExpr('character_cards')} AS comment_count,
                    ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
             FROM character_cards WHERE id = ?`
        ).get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        const { views_count, downloads_count } = req.body;
        const commentHeatCount = req.body.comment_heat_count ?? req.body.comment_count;
        const fields = [];
        const values = [];

        if (views_count !== undefined) {
            const v = parseInt(views_count);
            if (!Number.isInteger(v) || v < 0) return res.status(400).json({ error: '浏览量必须是非负整数' });
            fields.push('views_count = ?');
            values.push(v);
        }
        if (downloads_count !== undefined) {
            const d = parseInt(downloads_count);
            if (!Number.isInteger(d) || d < 0) return res.status(400).json({ error: '下载量必须是非负整数' });
            fields.push('downloads_count = ?');
            values.push(d);
        }
        if (commentHeatCount !== undefined) {
            const c = parseInt(commentHeatCount);
            if (!Number.isInteger(c) || c < 0) return res.status(400).json({ error: '评论用户数必须是非负整数' });
            fields.push('comment_count_override = ?');
            values.push(c);
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });

        values.push(id);
        db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        clearCardListCache('card-heat');

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: 'admin_adjust_heat', targetType: 'card', targetId: id, ip: getRequestIp(req),
            details: { name: card.name, views_count, downloads_count, comment_heat_count: commentHeatCount }
        });

        const updated = db.prepare(
            `SELECT views_count, downloads_count,
                    ${cardCommentCountExpr('character_cards')} AS comment_count,
                    ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
             FROM character_cards WHERE id = ?`
        ).get(id);
        maybeSendCardHeatMilestoneEmail(id, req);
        res.json({
            success: true,
            views_count: updated.views_count,
            downloads_count: updated.downloads_count,
            comment_count: updated.comment_count,
            comment_heat_count: updated.comment_heat_count,
            heat_score: computeCardHeatFromRow(updated)
        });
    } catch (err) {
        console.error('Admin adjust heat error:', err);
        res.status(500).json({ error: '调整热度失败' });
    }
});

app.put('/api/ui-templates/:id/heat', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const template = db.prepare(
            `SELECT id, title, views_count, downloads_count,
                    ${templateCommentCountExpr('ui_templates')} AS comment_count,
                    ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
             FROM ui_templates WHERE id = ?`
        ).get(id);
        if (!template) return res.status(404).json({ error: '模板不存在' });

        const { views_count, downloads_count } = req.body;
        const commentHeatCount = req.body.comment_heat_count ?? req.body.comment_count;
        const fields = [];
        const values = [];
        if (views_count !== undefined) {
            const v = parseInt(views_count);
            if (!Number.isInteger(v) || v < 0) return res.status(400).json({ error: '浏览量必须是非负整数' });
            fields.push('views_count = ?');
            values.push(v);
        }
        if (downloads_count !== undefined) {
            const d = parseInt(downloads_count);
            if (!Number.isInteger(d) || d < 0) return res.status(400).json({ error: '下载量必须是非负整数' });
            fields.push('downloads_count = ?');
            values.push(d);
        }
        if (commentHeatCount !== undefined) {
            const c = parseInt(commentHeatCount);
            if (!Number.isInteger(c) || c < 0) return res.status(400).json({ error: '评论用户数必须是非负整数' });
            fields.push('comment_count_override = ?');
            values.push(c);
        }
        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });

        values.push(id);
        db.prepare(`UPDATE ui_templates SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_adjust_ui_template_heat',
            targetType: 'ui_template',
            targetId: id,
            ip: getRequestIp(req),
            details: { title: template.title, views_count, downloads_count, comment_heat_count: commentHeatCount }
        });

        const updated = db.prepare(
            `SELECT views_count, downloads_count,
                    ${templateCommentCountExpr('ui_templates')} AS comment_count,
                    ${templateCommentHeatCountExpr('ui_templates')} AS comment_heat_count
             FROM ui_templates WHERE id = ?`
        ).get(id);
        res.json({
            success: true,
            views_count: updated.views_count,
            downloads_count: updated.downloads_count,
            comment_count: updated.comment_count,
            comment_heat_count: updated.comment_heat_count,
            heat_score: computeTemplateHeatFromRow(updated)
        });
    } catch (err) {
        console.error('Admin adjust UI template heat error:', err);
        res.status(500).json({ error: '调整模板热度失败' });
    }
});

app.post('/api/cards/:id/download', requireUserOrAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.uploader_user_id, cc.review_status, cc.downloads_count,
                    u.username, u.email, u.email_verified
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ?`
        ).get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const isOwner = req.user && card.uploader_user_id === req.user.id;
        const isModerator = isModeratorUser(req.user);
        if (!isPublicCardStatus(card.review_status) && !req.admin && !isModerator && !isOwner) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        const isFreeDownload = card.review_status === 'unreviewed';
        let newCredits = null;
        let downloadCounted = false;
        let previouslyDownloaded = false;
        const recordDownload = db.transaction(() => {
            if (req.user && !isOwner && !isModerator) {
                previouslyDownloaded = Boolean(db.prepare(
                    'SELECT 1 FROM card_downloads WHERE card_id = ? AND user_id = ? LIMIT 1'
                ).get(id, req.user.id));
            }
            if (!req.admin && !isModerator) {
                if (!isOwner && !isFreeDownload && !previouslyDownloaded) {
                    const result = db.prepare('UPDATE users SET download_credits = download_credits - 1 WHERE id = ? AND download_credits > 0').run(req.user.id);
                    if (result.changes === 0) {
                        const error = new Error('下载次数不足');
                        error.statusCode = 403;
                        throw error;
                    }
                }
                newCredits = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(req.user.id)?.download_credits ?? null;
            }

            // One regular account can add download heat to the same card only once.
            if (!isOwner && !req.admin && !isModerator && !previouslyDownloaded) {
                const inserted = db.prepare(
                    `INSERT OR IGNORE INTO card_downloads (card_id, user_id)
                     VALUES (?, ?)`
                ).run(id, req.user.id);
                if (inserted.changes > 0) {
                    db.prepare('UPDATE character_cards SET downloads_count = downloads_count + 1 WHERE id = ?').run(id);
                    downloadCounted = true;
                }
            }
        });

        recordDownload();
        const latestDownloads = db.prepare('SELECT downloads_count FROM character_cards WHERE id = ?').get(id)?.downloads_count ?? card.downloads_count ?? 0;
        if (downloadCounted) {
            maybeSendCardHeatMilestoneEmail(id, req);
        }
        logOperation({ userType: req.user ? 'user' : 'admin', userId: req.user?.id || req.admin?.id, username: req.user?.username || req.admin?.username, action: 'download', targetType: 'card', targetId: id, ip: getRequestIp(req) });

        res.json({
            success: true,
            new_credits: newCredits,
            download_counted: downloadCounted,
            downloads_count: latestDownloads,
            free_download: isFreeDownload,
            previously_downloaded: previouslyDownloaded,
            download_url: `/api/cards/${encodeURIComponent(id)}/download/file`
        });
    } catch (err) {
        if (err.statusCode) {
            return res.status(err.statusCode).json({ error: err.message });
        }
        console.error('Download count error:', err);
        res.status(500).json({ error: '更新下载次数失败' });
    }
});

app.get('/api/cards/:id/download/file', optionalUserAuth, async (req, res) => {
    try {
        const card = db.prepare('SELECT id, name, avatar_url, data, review_status, uploader_user_id FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) {
            return res.status(404).json({ error: '卡片不存在' });
        }
        const canView = isPublicCardStatus(card.review_status)
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && card.uploader_user_id === req.user.id);
        if (!canView) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        try {
            card.data = card.data ? JSON.parse(card.data) : null;
        } catch {
            card.data = null;
        }

        const fileBuffer = await getCardDownloadFile(card);
        const fileName = sanitizeDownloadFilename(card.name);
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'private, max-age=3600');
        res.set('Content-Disposition', createAttachmentDisposition(fileName));
        res.send(fileBuffer);
    } catch (err) {
        console.error('Download file error:', err);
        res.status(500).json({ error: '生成下载文件失败' });
    }
});

// ============== Card Like Routes ==============
app.post('/api/cards/:id/like', authenticateUser, (req, res) => {
    try {
        const cardId = req.params.id;
        const userId = req.user.id;

        const card = db.prepare("SELECT id FROM character_cards WHERE id = ? AND review_status IN ('approved', 'unreviewed')").get(cardId);
        if (!card) return res.status(404).json({ error: '角色卡不存在' });

        const existing = db.prepare('SELECT id FROM card_likes WHERE card_id = ? AND user_id = ?').get(cardId, userId);

        if (existing) {
            // Unlike
            const unlikeTransaction = db.transaction(() => {
                db.prepare('DELETE FROM card_likes WHERE card_id = ? AND user_id = ?').run(cardId, userId);
                db.prepare('UPDATE character_cards SET likes_count = CASE WHEN likes_count > 0 THEN likes_count - 1 ELSE 0 END WHERE id = ?').run(cardId);
            });
            unlikeTransaction();

            const updated = db.prepare('SELECT likes_count FROM character_cards WHERE id = ?').get(cardId);
            return res.json({ liked: false, likes_count: updated.likes_count });
        } else {
            // Like
            const likeTransaction = db.transaction(() => {
                db.prepare('INSERT INTO card_likes (card_id, user_id) VALUES (?, ?)').run(cardId, userId);
                db.prepare('UPDATE character_cards SET likes_count = likes_count + 1 WHERE id = ?').run(cardId);
            });
            likeTransaction();

            const updated = db.prepare('SELECT likes_count FROM character_cards WHERE id = ?').get(cardId);
            return res.json({ liked: true, likes_count: updated.likes_count });
        }
    } catch (err) {
        console.error('Card like error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

function countTodayCreditComments(userId, todayStr) {
    const cardCount = db.prepare(
        `SELECT COUNT(*) as count
         FROM character_comments c
         JOIN character_cards cc ON cc.id = c.card_id
         WHERE c.user_id = ? AND cc.review_status != 'unreviewed'
           AND c.created_at >= ? AND c.created_at < date(?, '+1 day')`
    ).get(userId, todayStr, todayStr).count;
    const templateCount = db.prepare(
        "SELECT COUNT(*) as count FROM ui_template_comments WHERE user_id = ? AND created_at >= ? AND created_at < date(?, '+1 day')"
    ).get(userId, todayStr, todayStr).count;
    return (cardCount || 0) + (templateCount || 0);
}

function getCommentRateRetryAfter(userId) {
    const now = Date.now();
    const recentTimes = [
        ...db.prepare('SELECT created_at FROM character_comments WHERE user_id = ? ORDER BY created_at DESC LIMIT ?')
            .all(userId, COMMENT_RATE_MAX_PER_WINDOW),
        ...db.prepare('SELECT created_at FROM ui_template_comments WHERE user_id = ? ORDER BY created_at DESC LIMIT ?')
            .all(userId, COMMENT_RATE_MAX_PER_WINDOW)
    ]
        .map((row) => {
            const value = String(row.created_at || '');
            return new Date(value.includes('T') ? value : `${value.replace(' ', 'T')}Z`).getTime();
        })
        .filter(time => Number.isFinite(time) && now - time < COMMENT_RATE_WINDOW_MS)
        .sort((a, b) => a - b);
    if (recentTimes.length < COMMENT_RATE_MAX_PER_WINDOW) return 0;
    return Math.max(1, Math.ceil((recentTimes[0] + COMMENT_RATE_WINDOW_MS - now) / 1000));
}

// ============== Comment Routes ==============
async function getVisibleComments(req, options) {
    const {
        commentTable, likesTable, targetColumn, targetId,
        ownerTable, ownerAlias, userId
    } = options;
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const blockWords = getCommentEmailBlockWords();
    const blockWordsJson = JSON.stringify(blockWords);
    const pageRoots = await sqliteReadPool.all(
        `SELECT c.id
         FROM ${commentTable} c
         WHERE c.${targetColumn} = ? AND c.reply_to_id IS NULL
           AND comment_is_hidden(c.content, ?) = 0
         ORDER BY c.created_at DESC, c.id DESC
         LIMIT ? OFFSET ?`,
        [targetId, blockWordsJson, limit, offset]
    );
    const rootIds = pageRoots.map(row => row.id);
    let pageTree = [];
    if (rootIds.length > 0) {
        const rootPlaceholders = rootIds.map(() => '?').join(', ');
        pageTree = await sqliteReadPool.all(
            `WITH RECURSIVE comment_tree(id) AS (
                SELECT id FROM ${commentTable} WHERE id IN (${rootPlaceholders})
                UNION ALL
                SELECT child.id
                FROM ${commentTable} child
                JOIN comment_tree parent ON child.reply_to_id = parent.id
                WHERE child.${targetColumn} = ?
             )
             SELECT c.*, u.username AS author_name, owner.uploader_user_id AS ${ownerAlias}
             FROM comment_tree tree
             JOIN ${commentTable} c ON c.id = tree.id
             LEFT JOIN users u ON c.user_id = u.id
             LEFT JOIN ${ownerTable} owner ON owner.id = c.${targetColumn}
             ORDER BY c.created_at DESC, c.id DESC`,
            [...rootIds, targetId]
        );
    }

    const hiddenIds = new Set(pageTree.filter(comment => isCommentHiddenFromDisplay(comment.content, blockWords)).map(comment => comment.id));
    const byId = new Map(pageTree.map(comment => [comment.id, comment]));
    const pageComments = pageTree
        .filter(comment => !hiddenIds.has(comment.id))
        .map(comment => {
            if (!comment.reply_to_id || !hiddenIds.has(comment.reply_to_id)) return comment;
            let parent = byId.get(comment.reply_to_id);
            while (parent && hiddenIds.has(parent.id)) parent = byId.get(parent.reply_to_id);
            return { ...comment, reply_to_id: parent?.id || null };
        });

    const rootTotalQuery = sqliteReadPool.get(
        `SELECT COUNT(*) AS count FROM ${commentTable} c
         WHERE c.${targetColumn} = ? AND c.reply_to_id IS NULL
           AND comment_is_hidden(c.content, ?) = 0`,
        [targetId, blockWordsJson]
    );
    const visibleTreeSql = `
        WITH RECURSIVE visible_tree(id) AS (
            SELECT c.id FROM ${commentTable} c
            WHERE c.${targetColumn} = ? AND c.reply_to_id IS NULL
              AND comment_is_hidden(c.content, ?) = 0
            UNION ALL
            SELECT child.id
            FROM ${commentTable} child
            JOIN visible_tree parent ON child.reply_to_id = parent.id
            WHERE child.${targetColumn} = ?
        )`;
    const totalQuery = sqliteReadPool.get(
        `SELECT COUNT(*) AS count FROM ${commentTable} WHERE ${targetColumn} = ?`,
        [targetId]
    );
    const hotCommentQuery = sqliteReadPool.get(
        `${visibleTreeSql}
         SELECT c.id
         FROM visible_tree tree
         JOIN ${commentTable} c ON c.id = tree.id
         WHERE comment_is_hidden(c.content, ?) = 0 AND c.likes_count >= 5
         ORDER BY c.likes_count DESC, c.created_at DESC
         LIMIT 1`,
        [targetId, blockWordsJson, targetId, blockWordsJson]
    );
    let likedQuery = Promise.resolve([]);
    if (userId && pageComments.length > 0) {
        const commentPlaceholders = pageComments.map(() => '?').join(', ');
        likedQuery = sqliteReadPool.all(
            `SELECT comment_id FROM ${likesTable}
             WHERE user_id = ? AND comment_id IN (${commentPlaceholders})`,
            [userId, ...pageComments.map(comment => comment.id)]
        );
    }
    const [rootTotalRow, totalRow, hotComment, liked] = await Promise.all([
        rootTotalQuery, totalQuery, hotCommentQuery, likedQuery
    ]);
    const rootTotal = rootTotalRow.count;
    const total = totalRow.count;
    const likedCommentIds = new Set(liked.map(row => row.comment_id));

    const result = pageComments.map(comment => ({
        ...comment,
        user_liked: likedCommentIds.has(comment.id),
        is_hot: Boolean(hotComment && hotComment.id === comment.id)
    }));
    return {
        comments: result,
        total,
        root_total: rootTotal,
        has_more: offset + pageRoots.length < rootTotal,
        next_offset: offset + pageRoots.length
    };
}

app.get('/api/cards/:cardId/comments', optionalUserAuth, async (req, res) => {
    try {
        const cardId = req.params.cardId;
        const userId = req.user ? req.user.id : null;
        markPerf(req, 'comments-start', { cardId, userId: userId || null });
        const card = await sqliteReadPool.get('SELECT id, uploader_user_id, review_status FROM character_cards WHERE id = ?', [cardId]);
        markPerf(req, 'comments-card-read', { found: Boolean(card), reviewStatus: card?.review_status || null });
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const canView = isPublicCardStatus(card.review_status)
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && card.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '卡片不存在' });

        const result = await getVisibleComments(req, {
            commentTable: 'character_comments',
            likesTable: 'comment_likes',
            targetColumn: 'card_id',
            targetId: cardId,
            ownerTable: 'character_cards',
            ownerAlias: 'card_uploader_id',
            userId
        });
        markPerf(req, 'comments-visible', { rows: Array.isArray(result) ? result.length : result.comments.length, total: result.total });
        res.json(result);
    } catch (err) {
        console.error('Fetch comments error:', err);
        res.status(500).json({ error: '获取评论失败' });
    }
});

app.post('/api/cards/:cardId/comments', authenticateUser, (req, res) => {
    try {
        const { content, reply_to_id } = req.body;
        if (!content || !content.trim()) {
            return res.status(400).json({ error: '评论内容不能为空' });
        }
        if (content.trim().length < 5) {
            return res.status(400).json({ error: '评论内容不能少于5个字' });
        }
        if (content.length > 5000) {
            return res.status(400).json({ error: '评论内容过长（最多5000字）' });
        }

        // Anti-spam: block 5+ consecutive identical characters
        const repeatedCharRegex = /(.)\1{4,}/;
        if (repeatedCharRegex.test(content.trim())) {
            return res.status(400).json({ error: '评论内容包含过多连续重复字符，请修改后再提交' });
        }
        
        const userId = req.user.id;
        const user = db.prepare('SELECT username, download_credits FROM users WHERE id = ?').get(userId);
        if (!user) return res.status(401).json({ error: '用户不存在' });
        const commentRetryAfter = getCommentRateRetryAfter(userId);
        if (commentRetryAfter > 0) {
            res.set('Retry-After', String(commentRetryAfter));
            return res.status(429).json({
                error: `评论太频繁，请 ${commentRetryAfter} 秒后再试`,
                retry_after_seconds: commentRetryAfter
            });
        }
        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.uploader_user_id, cc.review_status,
                    u.username, u.email, u.email_verified, u.comment_email_notifications
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ? AND cc.review_status IN ('approved', 'unreviewed')`
        ).get(req.params.cardId);
        if (!card) return res.status(404).json({ error: '卡片不存在或尚未通过审核' });
        if (hasDuplicateCommentContent({
            table: 'character_comments',
            itemColumn: 'card_id',
            itemId: req.params.cardId,
            userId,
            content
        })) {
            return res.status(409).json({ error: '你已经在这张卡下发布过相同内容的评论' });
        }

        const id = generateId();
        const now = new Date().toISOString();

        // Resolve reply info
        let replyToName = null;
        let replyCommentAuthor = null;
        if (reply_to_id) {
            const replyComment = db.prepare(
                `SELECT c.id, c.user_id, u.username, u.email, u.email_verified, u.comment_email_notifications
                 FROM character_comments c
                 LEFT JOIN users u ON c.user_id = u.id
                 WHERE c.id = ? AND c.card_id = ?`
            ).get(reply_to_id, req.params.cardId);
            if (replyComment) {
                replyToName = replyComment.username || '匿名用户';
                replyCommentAuthor = replyComment;
            }
        }

        // The first three eligible comments each day earn download credits.
        const todayStr = now.slice(0, 10); // YYYY-MM-DD
        const todayCommentCount = countTodayCreditComments(userId, todayStr);
        const canEarnCredits = card.review_status === 'approved' && todayCommentCount < DAILY_CREDIT_COMMENT_LIMIT;
        const hadHeatComment = Boolean(db.prepare(
            'SELECT 1 FROM character_comments WHERE card_id = ? AND user_id = ? LIMIT 1'
        ).get(req.params.cardId, userId));

        // Insert comment and optionally add credits
        const insertComment = db.transaction(() => {
            const storedReplyToId = replyCommentAuthor ? reply_to_id : null;
            db.prepare(
                'INSERT INTO character_comments (id, card_id, user_id, nickname, content, reply_to_id, reply_to_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.cardId, userId, user.username, content.trim(), storedReplyToId, replyToName, now);
            if (!hadHeatComment) {
                db.prepare(
                    'UPDATE character_cards SET comment_count_override = comment_count_override + 1 WHERE id = ? AND comment_count_override IS NOT NULL'
                ).run(req.params.cardId);
            }

            if (canEarnCredits) {
                db.prepare('UPDATE users SET download_credits = download_credits + ? WHERE id = ?').run(COMMENT_REWARD_CREDITS, userId);
            }
        });
        insertComment();

        const comment = db.prepare('SELECT * FROM character_comments WHERE id = ?').get(id);
        comment.author_name = user.username;
        comment.user_liked = false;
        comment.is_hot = false;
        comment.card_uploader_id = db.prepare('SELECT uploader_user_id FROM character_cards WHERE id = ?').get(req.params.cardId)?.uploader_user_id || null;

        const updatedUser = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId);
        maybeSendCardHeatMilestoneEmail(req.params.cardId, req);
        let ownerNotifiedUserId = null;
        if (card.uploader_user_id && card.uploader_user_id !== userId && userEmailBound(card) && userCommentEmailNotificationsEnabled(card)) {
            sendCommentNotificationEmail({
                to: card.email,
                ownerName: card.username,
                commenterName: user.username,
                itemType: '角色卡',
                title: card.name,
                content: content.trim()
            });
            ownerNotifiedUserId = card.uploader_user_id;
        }
        if (
            replyCommentAuthor?.user_id
            && replyCommentAuthor.user_id !== userId
            && replyCommentAuthor.user_id !== ownerNotifiedUserId
            && userEmailBound(replyCommentAuthor)
            && userCommentEmailNotificationsEnabled(replyCommentAuthor)
        ) {
            sendCommentReplyNotificationEmail({
                to: replyCommentAuthor.email,
                ownerName: replyCommentAuthor.username,
                commenterName: user.username,
                itemType: '角色卡',
                title: card.name,
                content: content.trim()
            });
        }
        res.json({
            comment,
            comment_hidden: isCommentHiddenFromDisplay(comment.content),
            new_credits: updatedUser.download_credits,
            credits_earned: canEarnCredits,
            card_metrics: getCardMetrics(req.params.cardId, { viewer: { user: req.user } })
        });
    } catch (err) {
        console.error('Create comment error:', err);
        res.status(500).json({ error: '发布评论失败' });
    }
});

app.get('/api/ui-templates/:templateId/comments', optionalUserAuth, async (req, res) => {
    try {
        const templateId = req.params.templateId;
        const userId = req.user ? req.user.id : null;
        markPerf(req, 'ui-comments-start', { templateId, userId: userId || null });
        const template = await sqliteReadPool.get('SELECT id, uploader_user_id, review_status FROM ui_templates WHERE id = ?', [templateId]);
        markPerf(req, 'ui-comments-template-read', { found: Boolean(template), reviewStatus: template?.review_status || null });
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });

        const result = await getVisibleComments(req, {
            commentTable: 'ui_template_comments',
            likesTable: 'ui_template_comment_likes',
            targetColumn: 'template_id',
            targetId: templateId,
            ownerTable: 'ui_templates',
            ownerAlias: 'template_uploader_id',
            userId
        });
        markPerf(req, 'ui-comments-visible', { rows: Array.isArray(result) ? result.length : result.comments.length, total: result.total });
        res.json(result);
    } catch (err) {
        console.error('Fetch UI template comments error:', err);
        res.status(500).json({ error: '获取评论失败' });
    }
});

app.post('/api/ui-templates/:templateId/comments', authenticateUser, (req, res) => {
    try {
        const { content, reply_to_id } = req.body;
        if (!content || !content.trim()) {
            return res.status(400).json({ error: '评论内容不能为空' });
        }
        if (content.trim().length < 5) {
            return res.status(400).json({ error: '评论内容不能少于5个字' });
        }
        if (content.length > 5000) {
            return res.status(400).json({ error: '评论内容过长（最多5000字）' });
        }
        if (/(.)\1{4,}/.test(content.trim())) {
            return res.status(400).json({ error: '评论内容包含过多连续重复字符，请修改后再提交' });
        }

        const userId = req.user.id;
        const user = db.prepare('SELECT username, download_credits FROM users WHERE id = ?').get(userId);
        if (!user) return res.status(401).json({ error: '用户不存在' });
        const commentRetryAfter = getCommentRateRetryAfter(userId);
        if (commentRetryAfter > 0) {
            res.set('Retry-After', String(commentRetryAfter));
            return res.status(429).json({
                error: `评论太频繁，请 ${commentRetryAfter} 秒后再试`,
                retry_after_seconds: commentRetryAfter
            });
        }
        const template = db.prepare(
            `SELECT ut.id, ut.title, ut.uploader_user_id,
                    u.username, u.email, u.email_verified, u.comment_email_notifications
             FROM ui_templates ut
             LEFT JOIN users u ON ut.uploader_user_id = u.id
             WHERE ut.id = ? AND ut.review_status = 'approved'`
        ).get(req.params.templateId);
        if (!template) return res.status(404).json({ error: '模板不存在或尚未通过审核' });
        if (hasDuplicateCommentContent({
            table: 'ui_template_comments',
            itemColumn: 'template_id',
            itemId: req.params.templateId,
            userId,
            content
        })) {
            return res.status(409).json({ error: '你已经在这个模板下发布过相同内容的评论' });
        }

        const id = generateId();
        const now = new Date().toISOString();

        let replyToName = null;
        let replyCommentAuthor = null;
        if (reply_to_id) {
            const replyComment = db.prepare(
                `SELECT c.id, c.user_id, u.username, u.email, u.email_verified, u.comment_email_notifications
                 FROM ui_template_comments c
                 LEFT JOIN users u ON c.user_id = u.id
                 WHERE c.id = ? AND c.template_id = ?`
            ).get(reply_to_id, req.params.templateId);
            if (replyComment) {
                replyToName = replyComment.username || '匿名用户';
                replyCommentAuthor = replyComment;
            }
        }

        const todayStr = now.slice(0, 10);
        const canEarnCredits = countTodayCreditComments(userId, todayStr) < DAILY_CREDIT_COMMENT_LIMIT;
        const hadHeatComment = Boolean(db.prepare(
            'SELECT 1 FROM ui_template_comments WHERE template_id = ? AND user_id = ? LIMIT 1'
        ).get(req.params.templateId, userId));

        const insertComment = db.transaction(() => {
            const storedReplyToId = replyCommentAuthor ? reply_to_id : null;
            db.prepare(
                'INSERT INTO ui_template_comments (id, template_id, user_id, nickname, content, reply_to_id, reply_to_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.templateId, userId, user.username, content.trim(), storedReplyToId, replyToName, now);
            if (!hadHeatComment) {
                db.prepare(
                    'UPDATE ui_templates SET comment_count_override = comment_count_override + 1 WHERE id = ? AND comment_count_override IS NOT NULL'
                ).run(req.params.templateId);
            }

            if (canEarnCredits) {
                db.prepare('UPDATE users SET download_credits = download_credits + ? WHERE id = ?').run(COMMENT_REWARD_CREDITS, userId);
            }
        });
        insertComment();

        const comment = db.prepare('SELECT * FROM ui_template_comments WHERE id = ?').get(id);
        comment.author_name = user.username;
        comment.user_liked = false;
        comment.is_hot = false;
        comment.template_uploader_id = template.uploader_user_id || null;

        const updatedUser = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId);
        let ownerNotifiedUserId = null;
        if (template.uploader_user_id && template.uploader_user_id !== userId && userEmailBound(template) && userCommentEmailNotificationsEnabled(template)) {
            sendCommentNotificationEmail({
                to: template.email,
                ownerName: template.username,
                commenterName: user.username,
                itemType: 'UI模板',
                title: template.title,
                content: content.trim()
            });
            ownerNotifiedUserId = template.uploader_user_id;
        }
        if (
            replyCommentAuthor?.user_id
            && replyCommentAuthor.user_id !== userId
            && replyCommentAuthor.user_id !== ownerNotifiedUserId
            && userEmailBound(replyCommentAuthor)
            && userCommentEmailNotificationsEnabled(replyCommentAuthor)
        ) {
            sendCommentReplyNotificationEmail({
                to: replyCommentAuthor.email,
                ownerName: replyCommentAuthor.username,
                commenterName: user.username,
                itemType: 'UI模板',
                title: template.title,
                content: content.trim()
            });
        }
        res.json({
            comment,
            comment_hidden: isCommentHiddenFromDisplay(comment.content),
            new_credits: updatedUser.download_credits,
            credits_earned: canEarnCredits,
            template_metrics: getUiTemplateMetrics(req.params.templateId, { viewer: { user: req.user } })
        });
    } catch (err) {
        console.error('Create UI template comment error:', err);
        res.status(500).json({ error: '发布评论失败' });
    }
});

app.post('/api/ui-template-comments/:id/like', authenticateUser, (req, res) => {
    try {
        const commentId = req.params.id;
        const userId = req.user.id;
        const comment = db.prepare('SELECT id, template_id FROM ui_template_comments WHERE id = ?').get(commentId);
        if (!comment) return res.status(404).json({ error: '评论不存在' });

        const existing = db.prepare('SELECT id FROM ui_template_comment_likes WHERE comment_id = ? AND user_id = ?').get(commentId, userId);
        if (existing) {
            const unlikeTransaction = db.transaction(() => {
                db.prepare('DELETE FROM ui_template_comment_likes WHERE comment_id = ? AND user_id = ?').run(commentId, userId);
                db.prepare('UPDATE ui_template_comments SET likes_count = CASE WHEN likes_count > 0 THEN likes_count - 1 ELSE 0 END WHERE id = ?').run(commentId);
            });
            unlikeTransaction();
            const updated = db.prepare('SELECT likes_count FROM ui_template_comments WHERE id = ?').get(commentId);
            return res.json({ liked: false, likes_count: updated.likes_count });
        }

        const likeTransaction = db.transaction(() => {
            db.prepare('INSERT INTO ui_template_comment_likes (comment_id, user_id) VALUES (?, ?)').run(commentId, userId);
            db.prepare('UPDATE ui_template_comments SET likes_count = likes_count + 1 WHERE id = ?').run(commentId);
        });
        likeTransaction();
        const updated = db.prepare('SELECT likes_count FROM ui_template_comments WHERE id = ?').get(commentId);
        return res.json({ liked: true, likes_count: updated.likes_count });
    } catch (err) {
        console.error('UI template comment like error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

app.delete('/api/ui-template-comments/:id', requireUserOrAdmin, (req, res) => {
    try {
        const comment = db.prepare('SELECT id, template_id, user_id, content FROM ui_template_comments WHERE id = ?').get(req.params.id);
        if (!comment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        if (!req.admin && (!req.user || comment.user_id !== req.user.id)) {
            return res.status(403).json({ error: '只能删除自己发布的评论' });
        }
        const deleteComment = db.transaction(() => {
            const result = db.prepare('DELETE FROM ui_template_comments WHERE id = ?').run(req.params.id);
            if (result.changes > 0) {
                const stillHasHeatComment = comment.user_id
                    ? db.prepare('SELECT 1 FROM ui_template_comments WHERE template_id = ? AND user_id = ? LIMIT 1').get(comment.template_id, comment.user_id)
                    : null;
                if (!stillHasHeatComment) {
                    db.prepare(
                        `UPDATE ui_templates
                         SET comment_count_override = CASE
                            WHEN comment_count_override > 0 THEN comment_count_override - 1
                            ELSE 0
                         END
                         WHERE id = ? AND comment_count_override IS NOT NULL`
                    ).run(comment.template_id);
                }
            }
            return result;
        });
        const result = deleteComment();
        if (result.changes === 0) {
            return res.status(404).json({ error: '评论不存在' });
        }
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: req.admin ? 'admin_delete_ui_template_comment' : 'delete_own_ui_template_comment',
            targetType: 'ui_template_comment',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { content: comment.content?.substring(0, 50) }
        });
        res.json({
            success: true,
            template_metrics: getUiTemplateMetrics(comment.template_id, { viewer: { admin: req.admin, user: req.user } })
        });
    } catch (err) {
        console.error('Delete UI template comment error:', err);
        res.status(500).json({ error: '删除评论失败' });
    }
});

// ============== Comment Like Routes ==============
app.post('/api/comments/:id/like', authenticateUser, (req, res) => {
    try {
        const commentId = req.params.id;
        const userId = req.user.id;

        // Check if comment exists
        const comment = db.prepare('SELECT id, card_id FROM character_comments WHERE id = ?').get(commentId);
        if (!comment) return res.status(404).json({ error: '评论不存在' });

        // Check if already liked
        const existing = db.prepare('SELECT id FROM comment_likes WHERE comment_id = ? AND user_id = ?').get(commentId, userId);

        if (existing) {
            // Unlike: remove like and deduct credit
            const unlikeTransaction = db.transaction(() => {
                db.prepare('DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?').run(commentId, userId);
                db.prepare('UPDATE character_comments SET likes_count = CASE WHEN likes_count > 0 THEN likes_count - 1 ELSE 0 END WHERE id = ?').run(commentId);
                // Don't deduct credits on unlike (credit was already earned)
            });
            unlikeTransaction();

            const updated = db.prepare('SELECT likes_count FROM character_comments WHERE id = ?').get(commentId);
            return res.json({ liked: false, likes_count: updated.likes_count });
        } else {
            // Like: add like
            const likeTransaction = db.transaction(() => {
                db.prepare('INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)').run(commentId, userId);
                db.prepare('UPDATE character_comments SET likes_count = likes_count + 1 WHERE id = ?').run(commentId);
            });
            likeTransaction();

            const updated = db.prepare('SELECT likes_count FROM character_comments WHERE id = ?').get(commentId);
            return res.json({ liked: true, likes_count: updated.likes_count });
        }
    } catch (err) {
        console.error('Like error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

app.delete('/api/comments/:id', requireUserOrAdmin, (req, res) => {
    try {
        const comment = db.prepare('SELECT id, card_id, user_id, content FROM character_comments WHERE id = ?').get(req.params.id);
        if (!comment) {
            return res.status(404).json({ error: '评论不存在' });
        }
        if (!req.admin && (!req.user || comment.user_id !== req.user.id)) {
            return res.status(403).json({ error: '只能删除自己发布的评论' });
        }
        const deleteComment = db.transaction(() => {
            const result = db.prepare('DELETE FROM character_comments WHERE id = ?').run(req.params.id);
            if (result.changes > 0) {
                const stillHasHeatComment = comment.user_id
                    ? db.prepare('SELECT 1 FROM character_comments WHERE card_id = ? AND user_id = ? LIMIT 1').get(comment.card_id, comment.user_id)
                    : null;
                if (!stillHasHeatComment) {
                    db.prepare(
                        `UPDATE character_cards
                         SET comment_count_override = CASE
                            WHEN comment_count_override > 0 THEN comment_count_override - 1
                            ELSE 0
                         END
                         WHERE id = ? AND comment_count_override IS NOT NULL`
                    ).run(comment.card_id);
                }
            }
            return result;
        });
        const result = deleteComment();
        if (result.changes === 0) {
            return res.status(404).json({ error: '评论不存在' });
        }
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: req.admin ? 'admin_delete_comment' : 'delete_own_comment',
            targetType: 'comment',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { content: comment.content?.substring(0, 50) }
        });
        res.json({
            success: true,
            card_metrics: getCardMetrics(comment.card_id, { viewer: { admin: req.admin, user: req.user } })
        });
    } catch (err) {
        console.error('Delete comment error:', err);
        res.status(500).json({ error: '删除评论失败' });
    }
});

// ============== Admin Routes ==============
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    try {
        markPerf(req, 'admin-stats-start');
        const totalCards = db.prepare('SELECT COUNT(*) as count FROM character_cards').get().count;
        const totalComments = db.prepare('SELECT COUNT(*) as count FROM character_comments').get().count;
        const totalDownloads = db.prepare('SELECT COALESCE(SUM(downloads_count), 0) as count FROM character_cards').get().count;
        const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
        const totalLikes = db.prepare('SELECT COALESCE(SUM(likes_count), 0) as count FROM character_comments').get().count;
        const totalVisits = db.prepare('SELECT COUNT(*) as count FROM page_views').get().count;
        const pendingCards = db.prepare("SELECT COUNT(*) as count FROM character_cards WHERE review_status = 'pending'").get().count;
        markPerf(req, 'admin-stats-base-counts', { totalCards, totalComments, totalUsers, totalVisits, pendingCards });
        const bannedIpCount = db.prepare(
            "SELECT COUNT(*) as count FROM ip_bans WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).get().count;
        const recentCards = db.prepare(
            "SELECT COUNT(*) as count FROM character_cards WHERE created_at > datetime('now', '-7 days')"
        ).get().count;
        const recentComments = db.prepare(
            "SELECT COUNT(*) as count FROM character_comments WHERE created_at > datetime('now', '-7 days')"
        ).get().count;
        const todayNewUsers = db.prepare("SELECT COUNT(*) as count FROM users WHERE created_at >= date('now')").get().count;
        const todayNewCards = db.prepare("SELECT COUNT(*) as count FROM character_cards WHERE created_at >= date('now')").get().count;
        const todayNewComments = db.prepare("SELECT COUNT(*) as count FROM character_comments WHERE created_at >= date('now')").get().count;
        const loginAttempts = db.prepare(
            "SELECT COUNT(*) as count FROM login_attempts WHERE success = 0 AND attempt_time > datetime('now', '-24 hours')"
        ).get().count;
        const topCards = db.prepare(
            'SELECT id, name, downloads_count FROM character_cards ORDER BY downloads_count DESC LIMIT 10'
        ).all();
        markPerf(req, 'admin-stats-recent-counts', { bannedIpCount, recentCards, recentComments, todayNewUsers, topCards: topCards.length });

        // 7-day daily activity from operation_logs
        const dailyActivity = db.prepare(`
            SELECT date(created_at) as day,
                SUM(CASE WHEN action='upload' THEN 1 ELSE 0 END) as uploads,
                SUM(CASE WHEN action='download' THEN 1 ELSE 0 END) as downloads,
                SUM(CASE WHEN action='register' THEN 1 ELSE 0 END) as registers,
                SUM(CASE WHEN action='login' THEN 1 ELSE 0 END) as logins
            FROM operation_logs
            WHERE created_at >= date('now', '-6 days')
            GROUP BY date(created_at)
            ORDER BY day ASC
        `).all();
        markPerf(req, 'admin-stats-daily-activity', { rows: dailyActivity.length });

        // 7-day daily comments
        const dailyComments = db.prepare(`
            SELECT date(created_at) as day, COUNT(*) as comments
            FROM character_comments
            WHERE created_at >= date('now', '-6 days')
            GROUP BY date(created_at)
        `).all();
        markPerf(req, 'admin-stats-daily-comments', { rows: dailyComments.length });

        // 7-day daily visits
        const dailyVisits = db.prepare(`
            SELECT date(created_at) as day, COUNT(*) as visits
            FROM page_views
            WHERE created_at >= date('now', '-6 days')
            GROUP BY date(created_at)
        `).all();
        markPerf(req, 'admin-stats-daily-visits', { rows: dailyVisits.length });

        res.json({
            totalCards, totalComments, totalDownloads, totalUsers, totalLikes, totalVisits,
            recentCards, recentComments, todayNewUsers, todayNewCards, todayNewComments,
            loginAttempts, pendingCards, bannedIpCount, topCards, dailyActivity, dailyComments, dailyVisits
        });
        markPerf(req, 'admin-stats-response-json');
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({ error: '获取统计失败' });
    }
});

app.get('/api/admin/cards', authenticateAdmin, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const search = req.query.search || '';
        const status = req.query.status || '';
        markPerf(req, 'admin-cards-start', { page, limit, hasSearch: Boolean(search), status });

        let query = `SELECT cc.id, cc.name, cc.description, cc.creator_notes, cc.downloads_count,
                            cc.uploader_user_id, u.username AS uploader_username,
                            cc.review_status, cc.reviewed_at, cc.rejection_reason, cc.uploader_ip_address,
                            cc.created_at, cc.latest_rank_at, cc.updated_at
                     FROM character_cards cc
                     LEFT JOIN users u ON cc.uploader_user_id = u.id`;
        let countQuery = 'SELECT COUNT(*) as count FROM character_cards cc LEFT JOIN users u ON cc.uploader_user_id = u.id';
        const params = [];
        const countParams = [];
        const whereParts = [];
        if (status && ['pending', 'approved', 'rejected', 'unreviewed', 'ai_pending'].includes(status)) {
            whereParts.push('cc.review_status = ?');
            params.push(status);
            countParams.push(status);
        }

        if (search) {
            const searchParam = `%${search}%`;
            whereParts.push('(cc.name LIKE ? OR cc.description LIKE ? OR cc.creator_notes LIKE ? OR u.username LIKE ?)');
            params.push(searchParam, searchParam, searchParam, searchParam);
            countParams.push(searchParam, searchParam, searchParam, searchParam);
        }

        if (whereParts.length) {
            const where = ` WHERE ${whereParts.join(' AND ')}`;
            query += where;
            countQuery += where;
        }
        markPerf(req, 'admin-cards-query-built', { whereParts: whereParts.length });

        const total = db.prepare(countQuery).get(...countParams).count;
        markPerf(req, 'admin-cards-count', { total });
        query += ' ORDER BY cc.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const cards = db.prepare(query).all(...params);
        markPerf(req, 'admin-cards-list', { rows: cards.length });
        res.json({ cards, total, page, limit, totalPages: Math.ceil(total / limit) });
        markPerf(req, 'admin-cards-response-json', { rows: cards.length });
    } catch (err) {
        console.error('Admin cards error:', err);
        res.status(500).json({ error: '获取卡片列表失败' });
    }
});

app.put('/api/admin/cards/:id/review', requireModeration, (req, res) => {
    try {
        const { id } = req.params;
        const status = String(req.body.status || '').trim();
        const reason = String(req.body.reason || '').trim().slice(0, 500);
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: '审核状态无效' });
        }

        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.uploader_user_id, cc.review_status,
                    u.username, u.email, u.email_verified
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ?`
        ).get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        if (card.review_status === 'unreviewed') {
            return res.status(400).json({ error: '无收益专区角色卡无需审核' });
        }
        if (card.review_status === 'ai_pending') {
            return res.status(400).json({ error: '角色卡正在等待 AI 审核' });
        }

        const now = new Date().toISOString();
        const reviewAndReward = db.transaction(() => {
            db.prepare(
                `UPDATE character_cards
                 SET review_status = ?, reviewed_by_admin_id = ?, reviewed_at = ?, rejection_reason = ?
                 WHERE id = ?`
            ).run(status, req.admin?.id || null, now, status === 'rejected' ? reason : null, id);

            if (status === 'approved' && card.review_status !== 'approved' && card.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = download_credits + 3 WHERE id = ?').run(card.uploader_user_id);
            }
            if (status !== 'approved' && card.review_status === 'approved' && card.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
        });
        reviewAndReward();

        clearCardImageCaches(id);
        clearCardListCache('card-review');
        const updated = db.prepare(
            'SELECT id, name, description, creator_notes, downloads_count, uploader_user_id, review_status, reviewed_at, rejection_reason, uploader_ip_address, created_at, latest_rank_at, updated_at FROM character_cards WHERE id = ?'
        ).get(id);
        attachUiTemplateSummary(updated);

        const actor = getModerationActor(req);
        logOperation({
            userType: actor.userType,
            userId: actor.userId,
            username: actor.username,
            action: req.admin
                ? (status === 'approved' ? 'admin_approve_card' : 'admin_reject_card')
                : (status === 'approved' ? 'moderator_approve_card' : 'moderator_reject_card'),
            targetType: 'card',
            targetId: id,
            ip: getRequestIp(req),
            details: {
                name: card.name,
                reason: status === 'rejected' ? reason : undefined,
                reviewer_type: actor.reviewerType,
                reviewer_id: actor.userId,
                reviewer_username: actor.username
            }
        });
        if (userEmailBound(card)) {
            sendReviewResultEmail({
                to: card.email,
                username: card.username,
                itemType: '角色卡',
                title: card.name,
                status,
                reason: status === 'rejected' ? reason : ''
            });
        }
        res.json({ success: true, card: sanitizeCharacterCardForClient(updated, { viewer: { admin: req.admin, user: req.user } }) });
    } catch (err) {
        console.error('Admin review card error:', err);
        res.status(500).json({ error: '审核失败' });
    }
});

app.delete('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    try {
        const card = db.prepare(
            `SELECT name, uploader_user_id, review_status, views_count, downloads_count,
                    ${cardCommentHeatCountExpr('character_cards')} AS comment_heat_count
             FROM character_cards WHERE id = ?`
        ).get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const cookiePenalty = card.uploader_user_id && card.review_status === 'approved'
            ? getContentCookieValueFromHeatRow(card)
            : 0;
        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(req.params.id);
            if (card.uploader_user_id && card.review_status === 'approved') {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
            if (cookiePenalty > 0) {
                addNewApiCookiePenalty(card.uploader_user_id, cookiePenalty);
            }
        });
        deleteAndReclaim();
        clearCardImageCaches(req.params.id);
        clearCardListCache('admin-card-delete');
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'admin_delete_card', targetType: 'card', targetId: req.params.id, ip: getRequestIp(req), details: { name: card?.name, cookie_penalty: cookiePenalty } });
        res.json({ success: true });
    } catch (err) {
        console.error('Admin delete card error:', err);
        res.status(500).json({ error: '删除失败' });
    }
});

app.get('/api/admin/comments', authenticateAdmin, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        const total = db.prepare('SELECT COUNT(*) as count FROM character_comments').get().count;
        const comments = db.prepare(
            `SELECT c.*, cc.name as card_name 
             FROM character_comments c 
             LEFT JOIN character_cards cc ON c.card_id = cc.id 
             ORDER BY c.created_at DESC LIMIT ? OFFSET ?`
        ).all(limit, offset);

        res.json({ comments, total, page, limit, totalPages: Math.ceil(total / limit) });
    } catch (err) {
        console.error('Admin comments error:', err);
        res.status(500).json({ error: '获取评论列表失败' });
    }
});

app.delete('/api/admin/comments/:id', authenticateAdmin, (req, res) => {
    try {
        const comment = db.prepare('SELECT card_id, user_id, content FROM character_comments WHERE id = ?').get(req.params.id);
        const deleteComment = db.transaction(() => {
            const result = db.prepare('DELETE FROM character_comments WHERE id = ?').run(req.params.id);
            if (result.changes > 0 && comment?.card_id) {
                const stillHasHeatComment = comment.user_id
                    ? db.prepare('SELECT 1 FROM character_comments WHERE card_id = ? AND user_id = ? LIMIT 1').get(comment.card_id, comment.user_id)
                    : null;
                if (!stillHasHeatComment) {
                    db.prepare(
                        `UPDATE character_cards
                         SET comment_count_override = CASE
                            WHEN comment_count_override > 0 THEN comment_count_override - 1
                            ELSE 0
                         END
                         WHERE id = ? AND comment_count_override IS NOT NULL`
                    ).run(comment.card_id);
                }
            }
            return result;
        });
        const result = deleteComment();
        if (result.changes === 0) return res.status(404).json({ error: '评论不存在' });
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'admin_delete_comment', targetType: 'comment', targetId: req.params.id, ip: getRequestIp(req), details: { content: comment?.content?.substring(0, 50) } });
        res.json({ success: true });
    } catch (err) {
        console.error('Admin delete comment error:', err);
        res.status(500).json({ error: '删除失败' });
    }
});

app.get('/api/admin/settings', authenticateAdmin, (req, res) => {
    try {
        const settings = db.prepare('SELECT key, value FROM settings').all();
        const result = {};
        settings.forEach((setting) => {
            if (setting.key !== 'turnstile_secret_key') result[setting.key] = setting.value;
        });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: '获取设置失败' });
    }
});

app.get('/api/admin/turnstile-settings', authenticateAdmin, (req, res) => {
    try {
        const dbSecretKey = getSettingValue('turnstile_secret_key');
        const config = getTurnstileConfig();
        res.json({
            configured: Boolean(config.siteKey && config.secretKey),
            site_key: config.siteKey || '',
            secret_key_configured: Boolean(config.secretKey),
            secret_key_masked: maskSecret(config.secretKey),
            secret_key_source: dbSecretKey ? 'admin' : (TURNSTILE_SECRET_KEY ? 'environment' : 'none')
        });
    } catch (err) {
        console.error('Turnstile settings load error:', err);
        res.status(500).json({ error: '获取 Turnstile 设置失败' });
    }
});

app.put('/api/admin/turnstile-settings', authenticateAdmin, (req, res) => {
    try {
        const siteKey = String(req.body.site_key || '').trim();
        const secretKey = typeof req.body.secret_key === 'string' ? req.body.secret_key.trim() : '';
        const clearSecretKey = req.body.clear_secret_key === true || req.body.clear_secret_key === 'true';
        if (siteKey.length > 100 || (siteKey && siteKey.length < 8)) {
            return res.status(400).json({ error: 'Turnstile 站点密钥格式不正确' });
        }
        if (secretKey.length > 100 || (secretKey && secretKey.length < 8)) {
            return res.status(400).json({ error: 'Turnstile 私密密钥格式不正确' });
        }
        const effectiveSecretKey = clearSecretKey
            ? TURNSTILE_SECRET_KEY
            : (secretKey || getSettingValue('turnstile_secret_key') || TURNSTILE_SECRET_KEY);
        if (siteKey && !effectiveSecretKey) {
            return res.status(400).json({ error: '填写站点密钥时也需要填写私密密钥' });
        }

        if (clearSecretKey) db.prepare('DELETE FROM settings WHERE key = ?').run('turnstile_secret_key');
        else if (secretKey) setSettingValue('turnstile_secret_key', secretKey);
        setSettingValue('turnstile_site_key', siteKey);

        const config = getTurnstileConfig();

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_turnstile_settings',
            targetType: 'settings',
            targetId: 'turnstile',
            ip: getRequestIp(req),
            details: {
                configured: Boolean(config.siteKey && config.secretKey),
                secret_key_updated: Boolean(secretKey),
                secret_key_cleared: clearSecretKey
            }
        });

        const dbSecretKey = getSettingValue('turnstile_secret_key');
        res.json({
            success: true,
            configured: Boolean(config.siteKey && config.secretKey),
            site_key: config.siteKey || '',
            secret_key_configured: Boolean(config.secretKey),
            secret_key_masked: maskSecret(config.secretKey),
            secret_key_source: dbSecretKey ? 'admin' : (TURNSTILE_SECRET_KEY ? 'environment' : 'none')
        });
    } catch (err) {
        console.error('Turnstile settings save error:', err);
        res.status(500).json({ error: '保存 Turnstile 设置失败' });
    }
});

app.get('/api/admin/email-settings', authenticateAdmin, (req, res) => {
    try {
        const dbApiKey = getSettingValue('resend_api_key');
        const config = getEmailConfig();
        res.json({
            configured: Boolean(config.apiKey && config.from),
            api_key_configured: Boolean(config.apiKey),
            api_key_masked: maskSecret(config.apiKey),
            api_key_source: dbApiKey ? 'admin' : (RESEND_API_KEY ? 'environment' : 'none'),
            from: config.from || '',
            public_base_url: getSettingValue('public_base_url') || process.env.PUBLIC_BASE_URL || process.env.SITE_URL || '',
            admin_emails: getAdminNotificationEmails().join('\n'),
            admin_emails_source: getSettingValue('admin_notification_emails') ? 'admin' : (ADMIN_NOTIFICATION_EMAILS ? 'environment' : 'none'),
            comment_block_words: getCommentEmailBlockWords().join('\n')
        });
    } catch (err) {
        console.error('Email settings load error:', err);
        res.status(500).json({ error: '获取邮件设置失败' });
    }
});

app.put('/api/admin/email-settings', authenticateAdmin, (req, res) => {
    try {
        const apiKey = typeof req.body.api_key === 'string' ? req.body.api_key.trim() : '';
        const clearApiKey = req.body.clear_api_key === true || req.body.clear_api_key === 'true';
        const from = normalizeEmail(req.body.from);
        const publicBaseUrl = String(req.body.public_base_url || '').trim().replace(/\/+$/, '');
        const adminEmailsRaw = String(req.body.admin_emails || '').trim();
        const commentBlockWordsRaw = String(req.body.comment_block_words ?? '').trim();
        const invalidAdminEmails = findInvalidEmails(adminEmailsRaw);
        const nonQqAdminEmails = findNonQqEmails(adminEmailsRaw);

        if (!from) return res.status(400).json({ error: '请输入有效的发件邮箱' });
        if (publicBaseUrl && !/^https?:\/\//i.test(publicBaseUrl)) {
            return res.status(400).json({ error: '站点公网地址必须以 http:// 或 https:// 开头' });
        }
        if (apiKey && apiKey.length < 12) return res.status(400).json({ error: 'API Key 看起来太短了' });
        if (invalidAdminEmails.length > 0) {
            return res.status(400).json({ error: `管理员通知邮箱格式不正确：${invalidAdminEmails.slice(0, 3).join('、')}` });
        }
        if (nonQqAdminEmails.length > 0) {
            return res.status(400).json({ error: `管理员通知邮箱仅支持 QQ 邮箱：${nonQqAdminEmails.slice(0, 3).join('、')}` });
        }
        if (commentBlockWordsRaw.length > 5000) {
            return res.status(400).json({ error: '评论邮件屏蔽词太多了，请删减后再保存' });
        }

        if (clearApiKey) {
            db.prepare('DELETE FROM settings WHERE key = ?').run('resend_api_key');
        } else if (apiKey) {
            setSettingValue('resend_api_key', apiKey);
        }
        const adminEmails = parseEmailList(adminEmailsRaw);
        setSettingValue('resend_from', from);
        db.prepare("DELETE FROM settings WHERE key IN ('zeabur_email_api_key', 'zeabur_email_from', 'zeabur_email_endpoint')").run();
        setSettingValue('public_base_url', publicBaseUrl);
        setSettingValue('admin_notification_emails', adminEmails.join('\n'));
        setSettingValue('comment_email_block_words', parseCommentEmailBlockWords(commentBlockWordsRaw).join('\n'));

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_email_settings',
            targetType: 'settings',
            targetId: 'email',
            ip: getRequestIp(req),
            details: {
                from,
                api_key_updated: Boolean(apiKey),
                api_key_cleared: clearApiKey,
                admin_email_count: adminEmails.length,
                comment_block_word_count: parseCommentEmailBlockWords(commentBlockWordsRaw).length
            }
        });

        const dbApiKey = getSettingValue('resend_api_key');
        const config = getEmailConfig();
        res.json({
            success: true,
            configured: Boolean(config.apiKey && config.from),
            api_key_configured: Boolean(config.apiKey),
            api_key_masked: maskSecret(config.apiKey),
            api_key_source: dbApiKey ? 'admin' : (RESEND_API_KEY ? 'environment' : 'none'),
            from: config.from || '',
            public_base_url: publicBaseUrl,
            admin_emails: getAdminNotificationEmails().join('\n'),
            admin_emails_source: getSettingValue('admin_notification_emails') ? 'admin' : (ADMIN_NOTIFICATION_EMAILS ? 'environment' : 'none'),
            comment_block_words: getCommentEmailBlockWords().join('\n')
        });
    } catch (err) {
        console.error('Email settings save error:', err);
        res.status(500).json({ error: '保存邮件设置失败' });
    }
});

app.get('/api/admin/newapi-settings', authenticateAdmin, (req, res) => {
    try {
        const dbToken = getSettingValue('newapi_admin_token');
        const config = getNewApiConfig();
        res.json({
            configured: isNewApiConfigured(),
            base_url: config.baseUrl || '',
            admin_user_id: config.adminUserId || '',
            admin_token_configured: Boolean(config.adminToken),
            admin_token_masked: maskSecret(config.adminToken),
            admin_token_source: dbToken ? 'admin' : (NEWAPI_ADMIN_TOKEN ? 'environment' : 'none'),
            heat_per_cookie: NEWAPI_HEAT_PER_COOKIE,
            quota_per_cookie: NEWAPI_QUOTA_PER_COOKIE
        });
    } catch (err) {
        console.error('New API settings load error:', err);
        res.status(500).json({ error: '获取 STA1N API 设置失败' });
    }
});

app.put('/api/admin/newapi-settings', authenticateAdmin, (req, res) => {
    try {
        const baseUrl = normalizeBaseUrl(req.body.base_url);
        const adminUserId = String(req.body.admin_user_id || '').trim();
        const adminToken = typeof req.body.admin_token === 'string' ? req.body.admin_token.trim() : '';
        const clearAdminToken = req.body.clear_admin_token === true || req.body.clear_admin_token === 'true';

        if (baseUrl && !/^https?:\/\//i.test(baseUrl)) {
            return res.status(400).json({ error: 'STA1N API 地址必须以 http:// 或 https:// 开头' });
        }
        if (adminUserId && !/^\d{1,18}$/.test(adminUserId)) {
            return res.status(400).json({ error: '管理用户 ID 必须是数字' });
        }
        if (adminToken && adminToken.length < 8) {
            return res.status(400).json({ error: '管理员 Token 看起来太短了' });
        }

        setSettingValue('newapi_base_url', baseUrl);
        setSettingValue('newapi_admin_user_id', adminUserId);
        if (clearAdminToken) {
            db.prepare('DELETE FROM settings WHERE key = ?').run('newapi_admin_token');
        } else if (adminToken) {
            setSettingValue('newapi_admin_token', adminToken);
        }

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_newapi_settings',
            targetType: 'settings',
            targetId: 'newapi',
            ip: getRequestIp(req),
            details: { base_url: baseUrl, admin_user_id: adminUserId, token_updated: Boolean(adminToken), token_cleared: clearAdminToken }
        });

        const dbToken = getSettingValue('newapi_admin_token');
        const config = getNewApiConfig();
        res.json({
            success: true,
            configured: isNewApiConfigured(),
            base_url: config.baseUrl || '',
            admin_user_id: config.adminUserId || '',
            admin_token_configured: Boolean(config.adminToken),
            admin_token_masked: maskSecret(config.adminToken),
            admin_token_source: dbToken ? 'admin' : (NEWAPI_ADMIN_TOKEN ? 'environment' : 'none'),
            heat_per_cookie: NEWAPI_HEAT_PER_COOKIE,
            quota_per_cookie: NEWAPI_QUOTA_PER_COOKIE
        });
    } catch (err) {
        console.error('New API settings save error:', err);
        res.status(500).json({ error: '保存 STA1N API 设置失败' });
    }
});

function getAiReviewQueueStats() {
    const stats = { pending: 0, processing: 0, allowed: 0, rejected: 0, skipped: 0 };
    db.prepare('SELECT status, COUNT(*) AS count FROM ai_review_queue GROUP BY status').all().forEach(row => {
        stats[row.status] = Number(row.count || 0);
    });
    return stats;
}

function buildAiReviewSettingsResponse() {
    const dbApiKey = getSettingValue('ai_review_api_key');
    const config = getAiReviewConfig();
    return {
        configured: isAiReviewConfigured(),
        base_url: config.baseUrl,
        model: config.model,
        vision_model: config.visionModel,
        text_prompt: config.textPrompt,
        cover_prompt: config.coverPrompt,
        api_key_configured: Boolean(config.apiKey),
        api_key_masked: maskSecret(config.apiKey),
        api_key_source: dbApiKey ? 'admin' : (AI_REVIEW_API_KEY ? 'environment' : 'none'),
        queue: getAiReviewQueueStats()
    };
}

app.get('/api/admin/ai-review-settings', authenticateAdmin, (req, res) => {
    try {
        res.json(buildAiReviewSettingsResponse());
    } catch (err) {
        console.error('AI review settings load error:', err);
        res.status(500).json({ error: '获取 AI 审核设置失败' });
    }
});

app.put('/api/admin/ai-review-settings', authenticateAdmin, (req, res) => {
    try {
        const baseUrl = normalizeBaseUrl(req.body.base_url || AI_REVIEW_DEFAULT_BASE_URL);
        const model = String(req.body.model || '').trim();
        const visionModel = String(req.body.vision_model || '').trim();
        const textPrompt = String(req.body.text_prompt || req.body.prompt || '').trim();
        const coverPrompt = String(req.body.cover_prompt || '').trim();
        const apiKey = typeof req.body.api_key === 'string' ? req.body.api_key.trim() : '';
        const clearApiKey = req.body.clear_api_key === true || req.body.clear_api_key === 'true';

        if (!/^https?:\/\//i.test(baseUrl)) {
            return res.status(400).json({ error: 'AI API 地址必须以 http:// 或 https:// 开头' });
        }
        if (model.length > 200) return res.status(400).json({ error: '模型名称过长' });
        if (visionModel.length > 200) return res.status(400).json({ error: '封面模型名称过长' });
        if (!textPrompt) return res.status(400).json({ error: '内容审核提示词不能为空' });
        if (!coverPrompt) return res.status(400).json({ error: '封面审核提示词不能为空' });
        if (textPrompt.length > 10000) return res.status(400).json({ error: '内容审核提示词不能超过 10000 字' });
        if (coverPrompt.length > 10000) return res.status(400).json({ error: '封面审核提示词不能超过 10000 字' });
        if (apiKey && apiKey.length < 8) return res.status(400).json({ error: 'API 密钥看起来太短了' });

        setSettingValue('ai_review_base_url', baseUrl);
        setSettingValue('ai_review_model', model);
        setSettingValue('ai_review_vision_model', visionModel);
        setSettingValue('ai_review_prompt', textPrompt);
        setSettingValue('ai_review_cover_prompt', coverPrompt);
        if (clearApiKey) {
            db.prepare('DELETE FROM settings WHERE key = ?').run('ai_review_api_key');
        } else if (apiKey) {
            setSettingValue('ai_review_api_key', apiKey);
        }

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_ai_review_settings',
            targetType: 'settings',
            targetId: 'ai_review',
            ip: getRequestIp(req),
            details: {
                base_url: baseUrl,
                model,
                vision_model: visionModel,
                text_prompt_updated: true,
                cover_prompt_updated: true,
                api_key_updated: Boolean(apiKey),
                api_key_cleared: clearApiKey
            }
        });
        scheduleAiReviewQueue();
        res.json({ success: true, ...buildAiReviewSettingsResponse() });
    } catch (err) {
        console.error('AI review settings save error:', err);
        res.status(500).json({ error: '保存 AI 审核设置失败' });
    }
});

app.get('/api/admin/ai-review-models', authenticateAdmin, async (req, res) => {
    const config = getAiReviewConfig();
    if (!config.apiKey) return res.status(400).json({ error: '请先保存 API 密钥' });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), AI_REVIEW_TIMEOUT_MS);
    try {
        const response = await fetch(`${config.baseUrl}/models`, {
            signal: controller.signal,
            headers: { 'Authorization': `Bearer ${config.apiKey}` }
        });
        const body = await response.text();
        if (!response.ok) throw new Error(`模型接口返回 ${response.status}: ${body.slice(0, 200)}`);
        const payload = JSON.parse(body);
        const source = Array.isArray(payload?.data) ? payload.data : (Array.isArray(payload?.models) ? payload.models : []);
        const models = [...new Set(source.map(item => typeof item === 'string' ? item : item?.id).filter(Boolean))]
            .sort((a, b) => a.localeCompare(b))
            .slice(0, 500);
        res.json({ models });
    } catch (err) {
        console.error('AI review models load error:', err);
        res.status(502).json({ error: err.name === 'AbortError' ? '获取模型超时' : `获取模型失败：${err.message}` });
    } finally {
        clearTimeout(timeout);
    }
});

app.get('/api/admin/ai-reviews', authenticateAdmin, (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page || '1', 10));
        const limit = 30;
        const offset = (page - 1) * limit;
        const status = String(req.query.status || '').trim();
        const search = String(req.query.search || '').trim().slice(0, 120);
        const whereParts = [];
        const params = [];
        if (['pending', 'processing', 'allowed', 'rejected', 'skipped'].includes(status)) {
            whereParts.push('q.status = ?');
            params.push(status);
        }
        if (search) {
            const value = `%${search}%`;
            whereParts.push('(COALESCE(c.name, q.card_name) LIKE ? OR COALESCE(u.username, q.uploader_username) LIKE ? OR q.reason LIKE ? OR q.error LIKE ?)');
            params.push(value, value, value, value);
        }
        const where = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
        const baseFrom = `FROM ai_review_queue q
            LEFT JOIN character_cards c ON c.id = q.card_id
            LEFT JOIN users u ON u.id = COALESCE(c.uploader_user_id, q.uploader_user_id)`;
        const total = Number(db.prepare(`SELECT COUNT(*) AS count ${baseFrom} ${where}`).get(...params).count || 0);
        const reviews = db.prepare(
            `SELECT q.id, q.card_id, q.status, q.decision, q.reason, q.error, q.model,
                    q.text_decision, q.text_reason, q.text_error, q.text_model,
                    q.cover_decision, q.cover_reason, q.cover_error, q.cover_model,
                    q.attempts, q.created_at, q.started_at, q.completed_at,
                    COALESCE(c.name, q.card_name) AS card_name,
                    COALESCE(c.review_status, 'deleted') AS card_status,
                    COALESCE(u.username, q.uploader_username) AS uploader_username
             ${baseFrom}
             ${where}
             ORDER BY q.id DESC
             LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);
        res.json({ reviews, total, page, totalPages: Math.ceil(total / limit), summary: getAiReviewQueueStats() });
    } catch (err) {
        console.error('AI review history load error:', err);
        res.status(500).json({ error: '获取 AI 审核记录失败' });
    }
});

app.get('/api/admin/newapi-redemptions', authenticateAdmin, (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
        const offset = (page - 1) * limit;
        const status = String(req.query.status || '').trim();
        const search = String(req.query.search || '').trim().slice(0, 120);
        markPerf(req, 'admin-redemptions-start', { page, limit, status, hasSearch: Boolean(search) });

        const whereParts = [];
        const params = [];
        if (status && ['pending', 'success', 'failed'].includes(status)) {
            whereParts.push('nr.status = ?');
            params.push(status);
        }
        if (search) {
            const keyword = `%${search.toLowerCase()}%`;
            whereParts.push(`(
                LOWER(COALESCE(nr.id, '')) LIKE ?
                OR LOWER(COALESCE(CAST(nr.user_id AS TEXT), '')) LIKE ?
                OR LOWER(COALESCE(nr.newapi_user_id, '')) LIKE ?
                OR LOWER(COALESCE(u.username, '')) LIKE ?
                OR LOWER(COALESCE(u.email, '')) LIKE ?
            )`);
            params.push(keyword, keyword, keyword, keyword, keyword);
        }
        const where = whereParts.length ? ` WHERE ${whereParts.join(' AND ')}` : '';
        const baseFrom = `FROM newapi_redemptions nr LEFT JOIN users u ON nr.user_id = u.id${where}`;
        markPerf(req, 'admin-redemptions-query-built', { whereParts: whereParts.length, params: params.length });

        const total = db.prepare(`SELECT COUNT(*) as count ${baseFrom}`).get(...params).count;
        markPerf(req, 'admin-redemptions-count', { total });
        const summary = db.prepare(
            `SELECT
                COALESCE(SUM(nr.cookies), 0) as cookies_total,
                COALESCE(SUM(CASE WHEN nr.status = 'success' THEN nr.cookies ELSE 0 END), 0) as cookies_success,
                SUM(CASE WHEN nr.status = 'success' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN nr.status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN nr.status = 'failed' THEN 1 ELSE 0 END) as failed_count
             ${baseFrom}`
        ).get(...params);
        markPerf(req, 'admin-redemptions-summary', {
            success: Number(summary.success_count || 0),
            pending: Number(summary.pending_count || 0),
            failed: Number(summary.failed_count || 0)
        });

        const redemptionRows = db.prepare(
            `SELECT
                nr.id, nr.user_id, nr.newapi_user_id, nr.cookies, nr.heat_used,
                nr.status, nr.error, nr.created_at, nr.completed_at,
                u.username, u.email, u.newapi_redeemed_cookies
             ${baseFrom}
             ORDER BY nr.created_at DESC
             LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);
        markPerf(req, 'admin-redemptions-list', { rows: redemptionRows.length });
        const rewardStatsByUser = getUsersNewApiRewardStatsMap(redemptionRows.map((row) => row.user_id));
        markPerf(req, 'admin-redemptions-reward-stats', { users: rewardStatsByUser.size });
        const redemptions = redemptionRows.map((row) => {
            const reward = rewardStatsByUser.get(Number(row.user_id)) || null;
            return {
                ...row,
                cookies: floorToTwoDecimals(row.cookies),
                heat_used: floorToTwoDecimals(row.heat_used),
                total_cookies: reward?.total_cookies ?? null,
                redeemed_cookies: reward?.redeemed_cookies ?? floorToTwoDecimals(row.newapi_redeemed_cookies || 0),
                available_cookies: reward?.available_cookies ?? null
            };
        });
        markPerf(req, 'admin-redemptions-map', { rows: redemptions.length });

        res.json({
            redemptions,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
            summary: {
                cookies_total: floorToTwoDecimals(summary.cookies_total || 0),
                cookies_success: floorToTwoDecimals(summary.cookies_success || 0),
                success_count: Number(summary.success_count || 0),
                pending_count: Number(summary.pending_count || 0),
                failed_count: Number(summary.failed_count || 0)
            }
        });
        markPerf(req, 'admin-redemptions-response-json', { rows: redemptions.length });
    } catch (err) {
        console.error('Admin New API redemptions error:', err);
        res.status(500).json({ error: '获取提现记录失败' });
    }
});

const PUBLIC_SETTINGS_KEYS = new Set([
    'site_name',
    'site_description',
    'allow_anonymous_upload',
    'allow_anonymous_comment',
    'popular_tags',
    'tag_library',
    'hidden_popular_tags',
    'hidden_tag_library',
    'announcement_title',
    'announcement_content',
    'announcement_enabled',
    'announcement_version',
    'turnstile_site_key'
]);

app.get('/api/settings', (req, res) => {
    try {
        markPerf(req, 'settings-start');
        const settings = db.prepare('SELECT key, value FROM settings').all();
        markPerf(req, 'settings-db-read', { rows: settings.length });
        const result = {};
        settings.forEach((setting) => {
            if (PUBLIC_SETTINGS_KEYS.has(setting.key)) {
                result[setting.key] = setting.value;
            }
        });
        const turnstile = getTurnstileConfig();
        result.turnstile_site_key = turnstile.siteKey && turnstile.secretKey ? turnstile.siteKey : '';
        markPerf(req, 'settings-filter', { publicKeys: Object.keys(result).length });
        res.json(result);
        markPerf(req, 'settings-response-json');
    } catch (err) {
        console.error('Public settings error:', err);
        res.status(500).json({ error: '获取站点设置失败' });
    }
});

const ALLOWED_SETTINGS_KEYS = new Set([
    'site_name', 'site_description', 'allow_anonymous_upload',
    'allow_anonymous_comment', 'max_upload_size_mb',
    'popular_tags', 'tag_library',
    'hidden_popular_tags', 'hidden_tag_library',
    'announcement_title', 'announcement_content', 'announcement_enabled', 'announcement_version'
]);

const TAG_SETTING_KEYS = new Set([
    'popular_tags',
    'tag_library',
    'hidden_popular_tags',
    'hidden_tag_library'
]);

const MAX_TAG_SETTING_LENGTH = 5000;
const MAX_TAG_COUNT = 300;
const MAX_TAG_LENGTH = 40;
const MAX_ANNOUNCEMENT_TITLE_LENGTH = 80;
const MAX_ANNOUNCEMENT_CONTENT_LENGTH = 5000;

function parseTagSettingValue(value) {
    return String(value || '')
        .split(/[\n,，]/)
        .map(item => item.trim())
        .filter(Boolean)
        .filter((item, index, array) => array.indexOf(item) === index);
}

function validateTagSettingValue(key, value) {
    const raw = String(value || '');
    if (raw.length > MAX_TAG_SETTING_LENGTH) {
        return `${key} 内容过长`;
    }
    const tags = parseTagSettingValue(raw);
    if (tags.length > MAX_TAG_COUNT) {
        return `${key} 标签数量过多`;
    }
    if (tags.some(tag => tag.length > MAX_TAG_LENGTH)) {
        return `${key} 中存在过长标签`;
    }
    return '';
}

app.put('/api/admin/settings', authenticateAdmin, (req, res) => {
    try {
        const updates = req.body;
        for (const [key, value] of Object.entries(updates)) {
            if (!ALLOWED_SETTINGS_KEYS.has(key)) continue;
            if (!TAG_SETTING_KEYS.has(key)) continue;
            const error = validateTagSettingValue(key, value);
            if (error) {
                return res.status(400).json({ error });
            }
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'announcement_title')
            && String(updates.announcement_title || '').length > MAX_ANNOUNCEMENT_TITLE_LENGTH) {
            return res.status(400).json({ error: `公告标题最多 ${MAX_ANNOUNCEMENT_TITLE_LENGTH} 个字` });
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'announcement_content')
            && String(updates.announcement_content || '').length > MAX_ANNOUNCEMENT_CONTENT_LENGTH) {
            return res.status(400).json({ error: `公告内容最多 ${MAX_ANNOUNCEMENT_CONTENT_LENGTH} 个字` });
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'announcement_enabled')) {
            updates.announcement_enabled = updates.announcement_enabled === true || String(updates.announcement_enabled) === 'true' ? 'true' : 'false';
        }
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)');
        const now = new Date().toISOString();
        for (const [key, value] of Object.entries(updates)) {
            if (!ALLOWED_SETTINGS_KEYS.has(key)) continue;
            stmt.run(key, String(value), now);
        }
        if (Object.keys(updates).some(key => TAG_SETTING_KEYS.has(key))) clearCardListCache('tag-settings');
        const hasAnnouncementUpdate = Object.prototype.hasOwnProperty.call(updates, 'announcement_title')
            || Object.prototype.hasOwnProperty.call(updates, 'announcement_content')
            || Object.prototype.hasOwnProperty.call(updates, 'announcement_enabled')
            || Object.prototype.hasOwnProperty.call(updates, 'announcement_version');
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: hasAnnouncementUpdate ? 'admin_update_announcement' : 'admin_update_tag_settings',
            targetType: 'settings',
            targetId: hasAnnouncementUpdate ? 'announcement' : 'tag-management',
            ip: getRequestIp(req),
            details: {
                popular_tags_count: parseTagSettingValue(updates.popular_tags).length,
                tag_library_count: parseTagSettingValue(updates.tag_library).length,
                hidden_popular_tags_count: parseTagSettingValue(updates.hidden_popular_tags).length,
                hidden_tag_library_count: parseTagSettingValue(updates.hidden_tag_library).length,
                announcement_enabled: updates.announcement_enabled,
                announcement_version: updates.announcement_version || ''
            }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: '更新设置失败' });
    }
});

app.get('/api/admin/logs', authenticateAdmin, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        const action = String(req.query.action || '').trim();
        const search = String(req.query.search || '').trim().slice(0, 120);

        const whereParts = [];
        const params = [];
        if (action) {
            whereParts.push('action = ?');
            params.push(action);
        }
        if (search) {
            const keyword = `%${search.toLowerCase()}%`;
            whereParts.push(`(
                LOWER(COALESCE(username, '')) LIKE ?
                OR LOWER(COALESCE(action, '')) LIKE ?
                OR LOWER(COALESCE(user_type, '')) LIKE ?
                OR LOWER(COALESCE(target_type, '')) LIKE ?
                OR LOWER(COALESCE(target_id, '')) LIKE ?
                OR LOWER(COALESCE(ip_address, '')) LIKE ?
                OR LOWER(COALESCE(details, '')) LIKE ?
                OR EXISTS (
                    SELECT 1 FROM character_cards cc
                    WHERE operation_logs.target_type = 'card'
                      AND cc.id = operation_logs.target_id
                      AND LOWER(cc.name) LIKE ?
                )
                OR EXISTS (
                    SELECT 1 FROM ui_templates ut
                    WHERE operation_logs.target_type = 'ui_template'
                      AND ut.id = operation_logs.target_id
                      AND LOWER(ut.title) LIKE ?
                )
            )`);
            params.push(keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword, keyword);
        }
        const where = whereParts.length ? ` WHERE ${whereParts.join(' AND ')}` : '';
        
        const total = db.prepare(`SELECT COUNT(*) as count FROM operation_logs${where}`).get(...params).count;
        const logs = db.prepare(
            `SELECT * FROM operation_logs${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(...params, limit, offset).map((log) => {
            let details = {};
            try { details = log.details ? JSON.parse(log.details) : {}; } catch {}
            let targetLabel = '';
            if (log.target_type === 'card' && log.target_id) {
                targetLabel = db.prepare('SELECT name FROM character_cards WHERE id = ?').get(log.target_id)?.name || details.name || '';
            } else if (log.target_type === 'ui_template' && log.target_id) {
                targetLabel = db.prepare('SELECT title FROM ui_templates WHERE id = ?').get(log.target_id)?.title || details.title || '';
            } else if (log.target_type === 'user') {
                targetLabel = details.username || log.username || '';
            } else if (log.target_type === 'comment') {
                targetLabel = details.content || '';
            }
            const reviewerType = details.reviewer_type || '';
            const reviewerName = details.reviewer_username || '';
            const reviewerId = details.reviewer_id || '';
            const actorLabel = reviewerName
                ? `${reviewerType === 'moderator' ? '审核员' : '管理员'}：${reviewerName}${reviewerId ? ` (#${reviewerId})` : ''}`
                : (log.username || '');
            return {
                ...log,
                details_json: details,
                actor_label: actorLabel,
                target_label: targetLabel || ''
            };
        });

        res.json({ logs, total, page, limit, totalPages: Math.ceil(total / limit) });
    } catch (err) {
        res.status(500).json({ error: '获取日志失败' });
    }
});

// ============== Admin IP Ban Management ==============
app.get('/api/admin/ip-bans', authenticateAdmin, (req, res) => {
    try {
        const bans = db.prepare(
            `SELECT * FROM ip_bans
             ORDER BY is_active DESC, created_at DESC`
        ).all();
        res.json({ bans, current_ip: getRequestIp(req) });
    } catch (err) {
        console.error('IP ban list error:', err);
        res.status(500).json({ error: '获取 IP 封禁列表失败' });
    }
});

app.post('/api/admin/ip-bans', authenticateAdmin, (req, res) => {
    try {
        const ipPattern = String(req.body.ip_pattern || '').trim();
        const reason = String(req.body.reason || '').trim().slice(0, 500);
        const expiresAtRaw = String(req.body.expires_at || '').trim();
        if (!ipPattern) return res.status(400).json({ error: '请输入要封禁的 IP 或 IPv4 CIDR' });
        if (ipPattern.includes('/')) {
            const [base, bitsRaw] = ipPattern.split('/');
            const bits = Number(bitsRaw);
            if (net.isIP(normalizeIp(base)) !== 4 || !Number.isInteger(bits) || bits < 0 || bits > 32) {
                return res.status(400).json({ error: 'CIDR 仅支持 IPv4，例如 203.0.113.0/24' });
            }
        } else if (!normalizeIp(ipPattern)) {
            return res.status(400).json({ error: 'IP 格式无效' });
        }
        if (ipMatchesPattern(getRequestIp(req), ipPattern)) {
            return res.status(400).json({ error: '不能封禁当前管理员正在使用的 IP' });
        }

        let expiresAt = null;
        if (expiresAtRaw) {
            const parsed = new Date(expiresAtRaw);
            if (Number.isNaN(parsed.getTime())) return res.status(400).json({ error: '过期时间格式无效' });
            expiresAt = parsed.toISOString();
        }

        db.prepare(
            `INSERT INTO ip_bans (ip_pattern, reason, created_by_admin_id, expires_at, is_active)
             VALUES (?, ?, ?, ?, 1)
             ON CONFLICT(ip_pattern) DO UPDATE SET
                reason = excluded.reason,
                created_by_admin_id = excluded.created_by_admin_id,
                expires_at = excluded.expires_at,
                is_active = 1,
                created_at = CURRENT_TIMESTAMP`
        ).run(ipPattern, reason || null, req.admin.id, expiresAt);

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_ban_ip',
            targetType: 'ip',
            targetId: ipPattern,
            ip: getRequestIp(req),
            details: { reason, expires_at: expiresAt }
        });

        res.json({ success: true });
    } catch (err) {
        console.error('Create IP ban error:', err);
        res.status(500).json({ error: '封禁 IP 失败' });
    }
});

app.delete('/api/admin/ip-bans/:id', authenticateAdmin, (req, res) => {
    try {
        const ban = db.prepare('SELECT * FROM ip_bans WHERE id = ?').get(req.params.id);
        if (!ban) return res.status(404).json({ error: '封禁记录不存在' });
        db.prepare('UPDATE ip_bans SET is_active = 0 WHERE id = ?').run(req.params.id);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_unban_ip',
            targetType: 'ip',
            targetId: ban.ip_pattern,
            ip: getRequestIp(req)
        });
        res.json({ success: true });
    } catch (err) {
        console.error('Remove IP ban error:', err);
        res.status(500).json({ error: '解除封禁失败' });
    }
});

// ============== Admin User Management ==============
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const search = req.query.search || '';
        markPerf(req, 'admin-users-start', { page, limit, hasSearch: Boolean(search) });

        let where = '';
        const params = [];
        if (search) {
            where = ' WHERE username LIKE ? OR email LIKE ? OR newapi_user_id LIKE ?';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        markPerf(req, 'admin-users-query-built', { hasWhere: Boolean(where), params: params.length });
        const total = db.prepare(`SELECT COUNT(*) as count FROM users${where}`).get(...params).count;
        markPerf(req, 'admin-users-count', { total });
        const users = db.prepare(
            `SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, is_banned, ban_reason, banned_at, created_at, last_login FROM users${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);
        markPerf(req, 'admin-users-list', { rows: users.length });

        res.json({ users, total, page, limit, totalPages: Math.ceil(total / limit) });
        markPerf(req, 'admin-users-response-json', { rows: users.length });
    } catch (err) {
        console.error('Admin users error:', err);
        res.status(500).json({ error: '获取用户列表失败' });
    }
});

app.put('/api/admin/users/:id/credits', authenticateAdmin, (req, res) => {
    try {
        const userId = Number(req.params.id);
        const credits = Number(req.body.download_credits);
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: '无效的用户 ID' });
        }
        if (!Number.isInteger(credits) || credits < 0) {
            return res.status(400).json({ error: '下载次数必须是大于等于 0 的整数' });
        }

        const result = db.prepare('UPDATE users SET download_credits = ? WHERE id = ?').run(credits, userId);
        if (result.changes === 0) {
            return res.status(404).json({ error: '用户不存在' });
        }

        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, is_banned, ban_reason, banned_at, created_at, last_login FROM users WHERE id = ?').get(userId);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_user_credits',
            targetType: 'user',
            targetId: String(userId),
            ip: getRequestIp(req),
            details: { download_credits: credits, username: user?.username }
        });

        res.json({ success: true, user });
    } catch (err) {
        console.error('Admin update credits error:', err);
        res.status(500).json({ error: '更新下载次数失败' });
    }
});

app.put('/api/admin/users/:id/moderator', authenticateAdmin, (req, res) => {
    try {
        const userId = Number(req.params.id);
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: '无效的用户 ID' });
        }
        const isModerator = req.body.is_moderator === true || req.body.is_moderator === 1 || req.body.is_moderator === 'true';
        const user = db.prepare('SELECT id, username, is_moderator FROM users WHERE id = ?').get(userId);
        if (!user) return res.status(404).json({ error: '用户不存在' });

        const oldModerator = Number(user.is_moderator || 0) === 1;
        db.prepare(
            `UPDATE users
             SET is_moderator = ?,
                 token_version = token_version + ?
             WHERE id = ?`
        ).run(isModerator ? 1 : 0, oldModerator === isModerator ? 0 : 1, userId);
        const updated = db.prepare(
            'SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, is_banned, ban_reason, banned_at, created_at, last_login FROM users WHERE id = ?'
        ).get(userId);

        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: isModerator ? 'admin_grant_moderator' : 'admin_revoke_moderator',
            targetType: 'user',
            targetId: String(userId),
            ip: getRequestIp(req),
            details: { username: user.username }
        });

        res.json({ success: true, user: updated });
    } catch (err) {
        console.error('Admin update moderator error:', err);
        res.status(500).json({ error: '更新前台审核员状态失败' });
    }
});

app.put('/api/admin/users/:id/ban', authenticateAdmin, (req, res) => {
    try {
        const userId = Number(req.params.id);
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: '无效的用户 ID' });
        }
        const banned = req.body.banned === true || req.body.banned === 1 || req.body.banned === 'true';
        const reason = String(req.body.reason || '').trim().slice(0, 500);
        const user = db.prepare('SELECT id, username, is_banned FROM users WHERE id = ?').get(userId);
        if (!user) return res.status(404).json({ error: '用户不存在' });

        if (banned) {
            db.prepare(
                `UPDATE users
                 SET is_banned = 1, ban_reason = ?, banned_at = ?, banned_by_admin_id = ?, token_version = token_version + 1
                 WHERE id = ?`
            ).run(reason || null, new Date().toISOString(), req.admin.id, userId);
        } else {
            db.prepare(
                `UPDATE users
                 SET is_banned = 0, ban_reason = NULL, banned_at = NULL, banned_by_admin_id = NULL, token_version = token_version + 1
                 WHERE id = ?`
            ).run(userId);
        }

        const updated = db.prepare(
            'SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, is_banned, ban_reason, banned_at, created_at, last_login FROM users WHERE id = ?'
        ).get(userId);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: banned ? 'admin_ban_user' : 'admin_unban_user',
            targetType: 'user',
            targetId: String(userId),
            ip: getRequestIp(req),
            details: { username: user.username, reason: banned ? reason : undefined }
        });
        res.json({ success: true, user: updated });
    } catch (err) {
        console.error('Admin ban user error:', err);
        res.status(500).json({ error: '更新用户封禁状态失败' });
    }
});

// ============== Visit Tracking ==============
app.post('/api/track/visit', (req, res) => {
    try {
        markPerf(req, 'track-visit-start');
        const visitPath = req.body.path || '/';
        const ip = getRequestIp(req);
        const ua = (req.headers['user-agent'] || '').substring(0, 512);
        db.prepare('INSERT INTO page_views (path, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?)').run(visitPath, ip, ua, new Date().toISOString());
        markPerf(req, 'track-visit-db-insert', { path: visitPath });
        res.json({ success: true });
        markPerf(req, 'track-visit-response-json');
    } catch (err) {
        res.status(500).json({ error: '记录失败' });
    }
});

// Card view count tracking (skip for card owner to prevent self-inflating heat)
app.post('/api/cards/:id/view', optionalUserAuth, (req, res) => {
    try {
        const { id } = req.params;
        markPerf(req, 'card-view-start', { id });
        const card = db.prepare('SELECT id, uploader_user_id, review_status FROM character_cards WHERE id = ?').get(id);
        markPerf(req, 'card-view-db-card', { found: Boolean(card), reviewStatus: card?.review_status || null });
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        if (!isPublicCardStatus(card.review_status) && !req.admin && !isModeratorUser(req.user) && !(req.user && card.uploader_user_id === req.user.id)) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        // Skip view count increment for admins and card owners.
        const isOwner = req.user && card.uploader_user_id === req.user.id;
        if (req.admin || isModeratorUser(req.user) || isOwner) {
            const current = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
            return res.json({ success: true, views_count: current.views_count, counted: false });
        }

        const viewLimit = recordAccountViewHeat(req, 'card', id);
        markPerf(req, 'card-view-limit', viewLimit);
        if (!viewLimit.counted) {
            const current = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
            markPerf(req, 'card-view-current-count', { viewsCount: current?.views_count ?? null });
            return res.json({
                success: true,
                views_count: current.views_count,
                counted: false,
                account_limit: {
                    max_per_item: VIEW_HEAT_ACCOUNT_MAX_PER_ITEM,
                    window_hours: VIEW_HEAT_ACCOUNT_WINDOW_HOURS
                }
            });
        }

        db.prepare('UPDATE character_cards SET views_count = views_count + 1 WHERE id = ?').run(id);
        const updated = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
        markPerf(req, 'card-view-incremented', { viewsCount: updated?.views_count ?? null });
        maybeSendCardHeatMilestoneEmail(id, req);
        res.json({ success: true, views_count: updated.views_count, counted: true });
        markPerf(req, 'card-view-response-json');
    } catch (err) {
        console.error('Card view count error:', err);
        res.status(500).json({ error: '记录浏览量失败' });
    }
});

app.get('/api/stats/visits', (req, res) => {
    try {
        markPerf(req, 'visits-start');
        const total = db.prepare('SELECT COUNT(*) as count FROM page_views').get().count;
        markPerf(req, 'visits-db-count', { total });
        res.json({ totalVisits: total });
        markPerf(req, 'visits-response-json');
    } catch (err) {
        res.status(500).json({ error: '获取访问量失败' });
    }
});

function getForumDbPath() {
    return path.join(SERVER_DATA_DIR, 'forum.db');
}

function getBackupTempDir() {
    const dir = path.join(SERVER_DATA_DIR, 'backup-downloads');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function getBackupStats(database = db) {
    const count = (table) => {
        try {
            return Number(database.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get()?.c || 0);
        } catch {
            return 0;
        }
    };
    return {
        users: count('users'),
        cards: count('character_cards'),
        comments: count('character_comments'),
        ui_templates: count('ui_templates'),
        ui_template_comments: count('ui_template_comments'),
        settings: count('settings'),
        redemptions: count('newapi_redemptions'),
        ai_reviews: count('ai_review_queue')
    };
}

async function createAdminBackupSnapshot() {
    // Checkpoint WAL so recent writes are included in the downloaded DB file.
    db.pragma('wal_checkpoint(TRUNCATE)');

    const dbPath = getForumDbPath();
    if (!fs.existsSync(dbPath)) {
        throw new Error('数据库文件不存在');
    }

    const quickCheck = db.pragma('quick_check', { simple: true });
    if (quickCheck !== 'ok') {
        throw new Error(`数据库自检未通过 (${quickCheck})`);
    }

    const stats = getBackupStats(db);
    const filename = `rph-forum-backup-${new Date().toISOString().slice(0, 10)}.db`;
    const snapshotPath = path.join(
        getBackupTempDir(),
        `rph-forum-export-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.db`
    );

    await db.backup(snapshotPath);
    const size = fs.statSync(snapshotPath).size;
    return { path: snapshotPath, filename, size, stats };
}

function setAdminBackupDownloadHeaders(res, snapshot) {
    res.setHeader('Content-Type', 'application/x-sqlite3');
    res.setHeader('Content-Disposition', createAttachmentDisposition(snapshot.filename));
    res.setHeader('Content-Length', String(snapshot.size));
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Accept-Ranges', 'none');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-RPH-Backup-Source', 'snapshot');
    res.setHeader('X-RPH-Backup-Size', String(snapshot.size));
    res.setHeader('X-RPH-Backup-Users', String(snapshot.stats.users));
    res.setHeader('X-RPH-Backup-Cards', String(snapshot.stats.cards));
    res.setHeader('X-RPH-Backup-Comments', String(snapshot.stats.comments));
    res.setHeader('X-RPH-Backup-Ui-Templates', String(snapshot.stats.ui_templates));
    res.setHeader('X-RPH-Backup-Redemptions', String(snapshot.stats.redemptions));
}

function streamAdminBackupSnapshot(req, res, snapshot, cleanup) {
    let fileStream = null;
    let cleaned = false;
    const cleanupOnce = () => {
        if (cleaned) return;
        cleaned = true;
        cleanup?.();
    };

    setAdminBackupDownloadHeaders(res, snapshot);
    console.info(`[Backup] export ${snapshot.filename} size=${snapshot.size} source=snapshot stats=${JSON.stringify(snapshot.stats)}`);

    fileStream = fs.createReadStream(snapshot.path);
    fileStream.on('error', (streamErr) => {
        console.error('Export stream error:', streamErr);
        if (!res.headersSent) {
            res.status(500).json({ error: '导出失败: ' + streamErr.message });
        } else {
            res.destroy(streamErr);
        }
        cleanupOnce();
    });
    fileStream.on('close', cleanupOnce);

    res.on('close', () => {
        if (!res.writableEnded && fileStream) {
            fileStream.destroy();
        }
    });

    fileStream.pipe(res);
}

// ============== Data Export/Import (SQLite DB File) ==============
app.post('/api/admin/export-token', authenticateAdmin, async (req, res) => {
    try {
        const snapshot = await createAdminBackupSnapshot();
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + ADMIN_EXPORT_DOWNLOAD_TTL_MS;
        adminExportDownloads.set(token, {
            ...snapshot,
            token,
            adminId: req.admin.id,
            username: req.admin.username,
            expiresAt
        });
        res.cookie('rph_admin_export_token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: IS_PRODUCTION,
            maxAge: ADMIN_EXPORT_DOWNLOAD_TTL_MS,
            path: '/api/admin/export/file'
        });
        res.json({
            success: true,
            filename: snapshot.filename,
            size: snapshot.size,
            stats: snapshot.stats,
            expires_in_seconds: Math.floor(ADMIN_EXPORT_DOWNLOAD_TTL_MS / 1000),
            download_url: '/api/admin/export/file'
        });
    } catch (err) {
        console.error('Export prepare error:', err);
        res.status(500).json({ error: '导出失败: ' + err.message });
    }
});

app.get('/api/admin/export/file', (req, res) => {
    const token = String(req.cookies?.rph_admin_export_token || '');
    const snapshot = adminExportDownloads.get(token);
    if (!snapshot || snapshot.expiresAt <= Date.now() || !snapshot.path || !fs.existsSync(snapshot.path)) {
        cleanupAdminExportDownload(token);
        res.clearCookie('rph_admin_export_token', { path: '/api/admin/export/file' });
        return res.status(410).json({ error: '下载链接已过期，请重新点击导出' });
    }

    res.clearCookie('rph_admin_export_token', { path: '/api/admin/export/file' });
    streamAdminBackupSnapshot(req, res, snapshot, () => cleanupAdminExportDownload(token));
});

app.get('/api/admin/export', authenticateAdmin, async (req, res) => {
    let snapshot = null;
    try {
        snapshot = await createAdminBackupSnapshot();
        streamAdminBackupSnapshot(req, res, snapshot, () => {
            if (!snapshot?.path) return;
            fs.unlink(snapshot.path, (err) => {
                if (err && err.code !== 'ENOENT') {
                    console.warn('[Backup] temp cleanup failed:', err.message);
                }
            });
        });
    } catch (err) {
        console.error('Export error:', err);
        if (snapshot?.path) {
            fs.unlink(snapshot.path, () => {});
        }
        if (!res.headersSent) {
            res.status(500).json({ error: '导出失败: ' + err.message });
        } else {
            res.destroy(err);
        }
    }
});

app.post('/api/admin/import', authenticateAdmin, (req, res) => {
    try {
        // Accept raw binary upload of a .db file
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            try {
                const buffer = Buffer.concat(chunks);

                // Validate it looks like a SQLite file (magic header: "SQLite format 3\0")
                if (buffer.length < 16 || buffer.toString('ascii', 0, 15) !== 'SQLite format 3') {
                    return res.status(400).json({ error: '无效的数据库文件，请上传 .db 格式的备份文件' });
                }

                const dbPath = getForumDbPath();
                const backupPath = path.join(SERVER_DATA_DIR, `forum-pre-import-${Date.now()}.db.bak`);

                // Checkpoint WAL before backup
                db.pragma('wal_checkpoint(TRUNCATE)');

                // Backup current database
                fs.copyFileSync(dbPath, backupPath);

                // Close current DB connection, write new file, then re-open
                db.close();
                fs.writeFileSync(dbPath, buffer);

                // Re-initialize the database module's connection
                const Database = require('better-sqlite3');
                const newDb = new Database(dbPath);
                newDb.pragma('journal_mode = WAL');
                newDb.pragma('busy_timeout = 30000');
                newDb.pragma('foreign_keys = ON');

                // Replace the exported db reference
                // We patch the module-level db object so all subsequent queries use the new connection
                const dbModule = require('./database');
                Object.defineProperty(dbModule, 'db', { value: newDb, writable: true, configurable: true });

                // Also update our local reference
                // Since we imported db at the top-level, we need to update it
                // The safest approach is to restart the process after import
                const stats = {
                    users: newDb.prepare('SELECT COUNT(*) as c FROM users').get().c,
                    cards: newDb.prepare('SELECT COUNT(*) as c FROM character_cards').get().c,
                    comments: newDb.prepare('SELECT COUNT(*) as c FROM character_comments').get().c,
                };

                newDb.close();

                res.json({
                    success: true,
                    message: '数据库导入成功，服务将自动重启以加载新数据',
                    stats,
                    restart: true
                });

                // Auto-restart the process to pick up the new database
                setTimeout(() => process.exit(0), 500);
            } catch (innerErr) {
                console.error('Import processing error:', innerErr);
                res.status(500).json({ error: '导入失败: ' + innerErr.message });
            }
        });
    } catch (err) {
        console.error('Import error:', err);
        res.status(500).json({ error: '导入失败: ' + err.message });
    }
});

// ============== SPA fallback ==============
// Root and admin HTML are handled by the cached HTML routes above static assets.

function getFileSizeSafe(filePath) {
    try {
        return fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;
    } catch {
        return 0;
    }
}

function logDatabaseHealth() {
    const started = performance.now();
    const dbPath = path.join(SERVER_DATA_DIR, 'forum.db');
    const tables = [
        'users',
        'character_cards',
        'character_comments',
        'ui_templates',
        'ui_template_comments',
        'page_views',
        'operation_logs',
        'account_view_limits',
        'card_downloads',
        'ui_template_downloads',
        'newapi_redemptions',
        'ai_review_queue',
        'ip_bans'
    ];
    const counts = {};
    const tableTimings = {};

    for (const table of tables) {
        const tableStart = performance.now();
        try {
            counts[table] = db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count;
            tableTimings[table] = formatDuration(performance.now() - tableStart);
        } catch (err) {
            counts[table] = `ERR:${err.message}`;
            tableTimings[table] = formatDuration(performance.now() - tableStart);
        }
    }

    let quickCheck = DB_HEALTH_QUICK_CHECK ? 'pending' : 'disabled';
    let quickMs = 0;
    if (DB_HEALTH_QUICK_CHECK) {
        const quickStart = performance.now();
        try {
            const row = db.prepare('PRAGMA quick_check').get();
            quickCheck = row ? Object.values(row)[0] : 'empty';
        } catch (err) {
            quickCheck = `ERR:${err.message}`;
        }
        quickMs = performance.now() - quickStart;
    }

    console.info(`[DB] health total=${formatDuration(performance.now() - started)} dbSize=${getFileSizeSafe(dbPath)} walSize=${getFileSizeSafe(`${dbPath}-wal`)} shmSize=${getFileSizeSafe(`${dbPath}-shm`)} quickCheck=${quickCheck} quickCheckTime=${formatDuration(quickMs)} counts=${JSON.stringify(counts)} countTimes=${JSON.stringify(tableTimings)}`);
}

// ============== Initialize & Start ==============
initDatabase();
sqliteReadPool = new SqliteReadPool(DB_PATH);
console.log(`[DB] SQLite read pool started with ${sqliteReadPool.size} workers (${sqliteReadPool.fastSize} reserved for homepage)`);
getAiReviewConfig();
recoverAiReviewQueue();

// Cleanup old login attempts every hour
setInterval(cleanupLoginAttempts, 60 * 60 * 1000);
setInterval(cleanupEmailCodes, 60 * 60 * 1000);
setInterval(cleanupOldLogs, 24 * 60 * 60 * 1000);

const server = app.listen(PORT, HOST, () => {
    console.log(`[Server] RP Forum running at http://${HOST}:${PORT}`);
    console.log(`[Server] Admin panel at http://${HOST}:${PORT}/admin`);
    setTimeout(() => {
        warmPublicAssetCache();
        logDatabaseHealth();
        cleanupOutdatedImageCaches();
        scheduleCardUiSummaryBackfill();
        scheduleCardDetailPreviewBackfill();
        scheduleCardDataAvatarCleanup();
    }, 1000);
});

// Graceful shutdown for Docker
function gracefulShutdown(signal) {
    console.log(`[Server] ${signal} received, shutting down...`);
    server.close(() => {
        sqliteReadPool.close().finally(() => {
            db.close();
            console.log('[Server] Database closed, exiting.');
            process.exit(0);
        });
    });
    setTimeout(() => { process.exit(1); }, 5000);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
