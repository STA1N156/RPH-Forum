const express = require('express');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
let sharp = null;
try {
    sharp = require('sharp');
} catch (err) {
    console.warn('[Server] sharp unavailable, image compression disabled:', err.message);
}
const { db, initDatabase, cleanupLoginAttempts, cleanupOldLogs } = require('./database');

const app = express();
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT) || 9191;
const HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY_SETTING = process.env.TRUST_PROXY === 'false'
    ? false
    : (process.env.TRUST_PROXY === 'true' || !process.env.TRUST_PROXY ? true : process.env.TRUST_PROXY);
const EXPLICIT_JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const DERIVED_JWT_SECRET = process.env.ADMIN_PASSWORD
    ? crypto.createHash('sha256').update(`rp-forum:${process.env.ADMIN_PASSWORD}`).digest('hex')
    : '';
const JWT_SECRET = EXPLICIT_JWT_SECRET || DERIVED_JWT_SECRET || (IS_PRODUCTION ? '' : crypto.randomBytes(32).toString('hex'));
const ZEABUR_EMAIL_API_KEY = (process.env.ZEABUR_EMAIL_API_KEY || '').trim();
const ZEABUR_EMAIL_FROM = (process.env.ZEABUR_EMAIL_FROM || process.env.EMAIL_FROM || '').trim();
const ZEABUR_EMAIL_ENDPOINT = (process.env.ZEABUR_EMAIL_ENDPOINT || 'https://api.zeabur.com/api/v1/zsend/emails').trim();
const ADMIN_NOTIFICATION_EMAILS = (process.env.ADMIN_NOTIFICATION_EMAILS || process.env.ADMIN_EMAILS || '').trim();
const NEWAPI_BASE_URL = (process.env.NEWAPI_BASE_URL || '').trim();
const NEWAPI_ADMIN_TOKEN = (process.env.NEWAPI_ADMIN_TOKEN || process.env.NEWAPI_ACCESS_TOKEN || '').trim();
const NEWAPI_ADMIN_USER_ID = (process.env.NEWAPI_ADMIN_USER_ID || process.env.NEWAPI_USER_ID || '').trim();
const EMAIL_CODE_TTL_MINUTES = Math.max(1, parseInt(process.env.EMAIL_CODE_TTL_MINUTES || '10', 10));
const EMAIL_CODE_MAX_ATTEMPTS = 5;
const EMAIL_CODE_COOLDOWN_SECONDS = Math.max(1, parseInt(process.env.EMAIL_CODE_COOLDOWN_SECONDS || '30', 10));
const HEAT_EMAIL_STEP = 500;
const NEWAPI_HEAT_PER_COOKIE = Math.max(1, parseInt(process.env.NEWAPI_HEAT_PER_COOKIE || '8', 10));
const NEWAPI_QUOTA_PER_COOKIE = Math.max(1, parseInt(process.env.NEWAPI_QUOTA_PER_COOKIE || '50000', 10));
const VIEW_HEAT_ACCOUNT_WINDOW_HOURS = Math.max(1, parseInt(process.env.VIEW_HEAT_ACCOUNT_WINDOW_HOURS || '24', 10) || 24);
const VIEW_HEAT_ACCOUNT_MAX_PER_ITEM = Math.max(1, parseInt(process.env.VIEW_HEAT_ACCOUNT_MAX_PER_ITEM || '1', 10) || 1);
const NEWAPI_USER_STATUS_ENABLED = 1;
const DEFAULT_COMMENT_EMAIL_BLOCK_WORDS = ['已严肃', '严肃'];

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

// ============== Captcha Store ==============
const captchaTokens = new Map(); // token -> { createdAt, used }

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
    if (ban) {
        return res.status(403).json({ error: '当前 IP 已被封禁', reason: ban.reason || '' });
    }
    next();
});


// Serve static files (no cache for HTML, allow cache for assets)
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
        } else {
            res.set('Cache-Control', 'public, max-age=86400');
        }
    }
}));

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
    const user = db.prepare('SELECT id, username, email, email_verified, download_credits, token_version, is_moderator, is_banned, ban_reason FROM users WHERE id = ?').get(decoded.id);
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
        role: 'user',
        token_version: user.token_version || 0
    };
}

function isModeratorUser(user) {
    return Number(user?.is_moderator || 0) === 1;
}

function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '未授权' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = validateAdminTokenPayload(decoded);
        if (!admin) return res.status(403).json({ error: '权限不足或登录状态已失效' });
        req.admin = admin;
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function authenticateUser(req, res, next) {
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
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function authenticateUserAllowUnbound(req, res, next) {
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
        next();
    } catch (err) {
        if (err.code === 'USER_BANNED') return res.status(403).json({ error: err.message });
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

function optionalUserAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.user = null;
        return next();
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'user') {
            req.user = validateUserTokenPayload(decoded);
        }
        else if (decoded.role === 'admin') { req.admin = validateAdminTokenPayload(decoded); req.user = null; }
        else req.user = null;
        next();
    } catch (err) {
        req.user = null;
        next();
    }
}

function requireUserOrAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录后再操作' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'user') {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            req.user = user;
        } else if (decoded.role === 'admin') {
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            req.admin = admin;
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
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') {
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            req.admin = admin;
            return next();
        }
        if (decoded.role === 'user') {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            if (!isModeratorUser(user)) return res.status(403).json({ error: '权限不足' });
            req.user = user;
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
        apiKey: getSettingValue('zeabur_email_api_key') || ZEABUR_EMAIL_API_KEY,
        from: getSettingValue('zeabur_email_from') || ZEABUR_EMAIL_FROM,
        endpoint: getSettingValue('zeabur_email_endpoint') || ZEABUR_EMAIL_ENDPOINT
    };
}

function getAdminNotificationEmails() {
    return parseEmailList(getSettingValue('admin_notification_emails') || ADMIN_NOTIFICATION_EMAILS);
}

function normalizeCommentEmailBlockText(value) {
    return String(value ?? '').normalize('NFKC').toLowerCase();
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
    if (saved === null) return DEFAULT_COMMENT_EMAIL_BLOCK_WORDS;
    return parseCommentEmailBlockWords(saved);
}

function isCommentEmailBlocked(content) {
    const text = normalizeCommentEmailBlockText(content);
    if (!text) return false;
    return getCommentEmailBlockWords().some(word => text.includes(normalizeCommentEmailBlockText(word)));
}

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

async function sendZeaburEmail({ to, subject, html, text }) {
    const normalizedTo = normalizeEmail(to);
    if (!normalizedTo) throw new Error('收件邮箱格式无效');
    if (!isQqEmail(normalizedTo)) throw new Error('目前仅支持 QQ 邮箱（@qq.com）');
    const config = getEmailConfig();
    if (!config.apiKey || !config.from) {
        throw new Error('邮件服务未配置，请在后台或环境变量里设置 Zeabur API Key 和发件邮箱');
    }

    const response = await fetch(config.endpoint || ZEABUR_EMAIL_ENDPOINT, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${config.apiKey}`
        },
        body: JSON.stringify({
            from: config.from,
            to: [normalizedTo],
            subject,
            html,
            text
        })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        const detail = data?.message || data?.error || `HTTP ${response.status}`;
        throw new Error(`邮件发送失败：${detail}`);
    }
    return data;
}

function sendZeaburEmailQuietly(payload) {
    sendZeaburEmail(payload).catch((err) => {
        console.error('[Email] Notification send failed:', err.message);
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
    const cutoff = new Date(Date.now() - EMAIL_CODE_COOLDOWN_SECONDS * 1000).toISOString();
    const recent = db.prepare(
        `SELECT created_at FROM email_verification_codes
         WHERE email = ? AND purpose = ? AND COALESCE(user_id, 0) = COALESCE(?, 0)
           AND created_at > ?
         ORDER BY created_at DESC LIMIT 1`
    ).get(normalizedEmail, purpose, userId || null, cutoff);
    if (!recent) return 0;
    const elapsed = Math.floor((Date.now() - new Date(recent.created_at).getTime()) / 1000);
    return Math.max(1, EMAIL_CODE_COOLDOWN_SECONDS - elapsed);
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
    return sendZeaburEmail({
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
    sendZeaburEmailQuietly({
        to,
        subject: `你的${itemType}审核${resultText}`,
        html: `<p>${escapeHtml(username || '你好')}，你的${escapeHtml(itemType)}「${escapeHtml(title)}」审核${escapeHtml(resultText)}。</p>${reason ? `<p>原因：${escapeHtml(reason)}</p>` : ''}`,
        text: `${username || '你好'}，你的${itemType}「${title}」审核${resultText}。${reasonText}`
    });
}

function sendAdminReviewPendingEmail({ itemType, title, uploader, ip }) {
    const recipients = getAdminNotificationEmails();
    if (recipients.length === 0) return;
    const uploaderText = uploader || '未知用户';
    const html = `<p>有新的${escapeHtml(itemType)}进入待审核。</p><p>名称：${escapeHtml(title)}</p><p>上传者：${escapeHtml(uploaderText)}</p>${ip ? `<p>上传 IP：${escapeHtml(ip)}</p>` : ''}`;
    const text = `有新的${itemType}进入待审核。\n名称：${title}\n上传者：${uploaderText}${ip ? `\n上传 IP：${ip}` : ''}`;
    recipients.forEach((to) => {
        sendZeaburEmailQuietly({
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
    sendZeaburEmailQuietly({
        to,
        subject: `你的${itemType}「${title}」有新评论`,
        html: `<p>${escapeHtml(ownerName || '你好')}，你的${escapeHtml(itemType)}「${escapeHtml(title)}」收到了来自 ${escapeHtml(commenterName || '用户')} 的新评论。</p><p>评论内容：</p><blockquote style="margin:12px 0;padding:12px;border-left:4px solid #dbeafe;background:#f8fafc;">${htmlContent}</blockquote>`,
        text: `${ownerName || '你好'}，你的${itemType}「${title}」收到了来自 ${commenterName || '用户'} 的新评论。\n评论内容：\n${commentText}`
    });
}

function computeCardHeatFromRow(row) {
    return Math.round((row.views_count || 0) * 1.0 + (row.comment_count || 0) * 1.5 + (row.downloads_count || 0) * 2.5);
}

function computeTemplateHeatFromRow(row) {
    return Math.round((row.views_count || 0) * 1.0 + (row.comment_count || 0) * 1.5 + (row.downloads_count || 0) * 2.5);
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
    if (!userId) return { counted: true, limited: false };

    const now = new Date().toISOString();
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
        return { counted: true, limited: false };
    }

    if (Number(row.expired || 0) === 1) {
        db.prepare(
            `UPDATE account_view_limits
             SET view_count = 1, window_started_at = ?, last_view_at = ?
             WHERE id = ?`
        ).run(now, now, row.id);
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
    return { counted: true, limited: false };
}

function getUserNewApiRewardStats(userId) {
    const user = db.prepare('SELECT newapi_user_id, newapi_redeemed_cookies FROM users WHERE id = ?').get(userId);
    const cardRows = db.prepare(
        `SELECT views_count, downloads_count,
                COALESCE(comment_count_override, (SELECT COUNT(*) FROM character_comments WHERE card_id = character_cards.id)) AS comment_count
         FROM character_cards
         WHERE uploader_user_id = ? AND review_status = 'approved'`
    ).all(userId);
    const templateRows = db.prepare(
        `SELECT views_count, downloads_count,
                COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ui_templates.id)) AS comment_count
         FROM ui_templates
         WHERE uploader_user_id = ? AND review_status = 'approved'`
    ).all(userId);
    const cardHeat = cardRows.reduce((sum, row) => sum + computeCardHeatFromRow(row), 0);
    const templateHeat = templateRows.reduce((sum, row) => sum + computeTemplateHeatFromRow(row), 0);
    const totalHeat = cardHeat + templateHeat;
    const totalCookies = floorToTwoDecimals(totalHeat / NEWAPI_HEAT_PER_COOKIE);
    const redeemedCookies = floorToTwoDecimals(Math.max(0, Number(user?.newapi_redeemed_cookies || 0)));
    const availableCookies = floorToTwoDecimals(totalCookies - redeemedCookies);
    return {
        newapi_user_id: user?.newapi_user_id || '',
        card_heat: cardHeat,
        template_heat: templateHeat,
        total_heat: totalHeat,
        total_cookies: totalCookies,
        redeemed_cookies: redeemedCookies,
        available_cookies: availableCookies,
        available_quota: Math.round(availableCookies * NEWAPI_QUOTA_PER_COOKIE),
        heat_per_cookie: NEWAPI_HEAT_PER_COOKIE,
        quota_per_cookie: NEWAPI_QUOTA_PER_COOKIE,
        min_redeem_cookies: 1,
        newapi_configured: isNewApiConfigured()
    };
}

function maybeSendCardHeatMilestoneEmail(cardId, req) {
    try {
        const row = db.prepare(
            `SELECT cc.id, cc.name, cc.views_count, cc.downloads_count, cc.heat_email_milestone,
                    u.username, u.email, u.email_verified,
                    COALESCE(cc.comment_count_override, (SELECT COUNT(*) FROM character_comments WHERE card_id = cc.id)) AS comment_count
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

        sendZeaburEmailQuietly({
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
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const ip = getRequestIp(req);

    // Brute force protection for admin login
    const bruteCheck = checkBruteForce(ip, username);
    if (bruteCheck.blocked) {
        return res.status(429).json({ error: bruteCheck.reason });
    }

    const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
    if (!user) {
        recordLoginAttempt(ip, username, false);
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
        recordLoginAttempt(ip, username, false);
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Success
    recordLoginAttempt(ip, username, true);
    db.prepare('UPDATE admin_users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
    logOperation({ userType: 'admin', userId: user.id, username: user.username, action: 'admin_login', targetType: 'user', targetId: String(user.id), ip, details: { role: 'admin' } });

    const token = generateAdminToken(user);
    res.json({ token, user: { id: user.id, username: user.username } });
});

app.get('/api/auth/me', authenticateAdmin, (req, res) => {
    res.json({ user: req.admin });
});

// ============== Captcha ==============
app.get('/api/captcha/generate', (req, res) => {
    const sliderX = 40 + Math.floor(Math.random() * 160); // target position 40-200
    const token = crypto.randomUUID();
    captchaTokens.set(token, { sliderX, createdAt: Date.now(), used: false });
    // Cleanup old tokens (> 5min)
    for (const [k, v] of captchaTokens) {
        if (Date.now() - v.createdAt > 5 * 60 * 1000) captchaTokens.delete(k);
    }
    res.json({ token, sliderX });
});

app.post('/api/captcha/verify', (req, res) => {
    const { token, x } = req.body;
    const record = captchaTokens.get(token);
    if (!record) return res.status(400).json({ error: '验证码已过期，请重试', valid: false });
    if (record.used) return res.status(400).json({ error: '验证码已使用，请重试', valid: false });
    if (Date.now() - record.createdAt > 60000) {
        captchaTokens.delete(token);
        return res.status(400).json({ error: '验证码已过期，请重试', valid: false });
    }
    const tolerance = 5;
    if (Math.abs(Number(x) - record.sliderX) <= tolerance) {
        record.used = true;
        res.json({ valid: true });
    } else {
        captchaTokens.delete(token);
        res.json({ valid: false, error: '验证失败，请重试' });
    }
});

// ============== User Registration & Login ==============
app.post('/api/email/send-code', async (req, res) => {
    try {
        cleanupEmailCodes();
        const purpose = String(req.body.purpose || '').trim();
        const emailCheck = validateQqEmail(req.body.email);
        const email = emailCheck.email;
        const captchaToken = String(req.body.captchaToken || '').trim();
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

        if (!captchaToken) {
            return res.status(400).json({ error: '请先完成滑块验证' });
        }
        const captchaRecord = captchaTokens.get(captchaToken);
        if (!captchaRecord || !captchaRecord.used) {
            return res.status(400).json({ error: '滑块验证未通过，请重试' });
        }
        captchaTokens.delete(captchaToken);

        const { code } = createEmailCode({ email, purpose, userId, ip: getRequestIp(req) });
        await sendVerificationCodeEmail({ email, code, purpose });
        res.json({
            success: true,
            message: `验证码已发送到 ${maskEmail(email)}，${EMAIL_CODE_TTL_MINUTES} 分钟内有效`,
            cooldown_seconds: EMAIL_CODE_COOLDOWN_SECONDS
        });
    } catch (err) {
        console.error('Send email code error:', err);
        res.status(500).json({ error: err.message || '发送验证码失败' });
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
            'INSERT INTO users (username, email, email_verified, password_hash, download_credits, last_login) VALUES (?, ?, 1, ?, 1, ?)'
        ).run(normalizedUsername, email, hash, now);

        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, token_version, is_moderator, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
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
    const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json({ user: buildUserResponse(user) });
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
        const updated = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
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
        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
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
            const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
            return res.json({ success: true, user: buildUserResponse(user), reward: getUserNewApiRewardStats(req.user.id) });
        }
        db.prepare("UPDATE users SET newapi_user_id = '' WHERE id = ?").run(req.user.id);
        const user = db.prepare('SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, token_version, is_moderator, created_at, is_banned, ban_reason FROM users WHERE id = ?').get(req.user.id);
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

function attachUiTemplateSummary(card, { keepData = false } = {}) {
    if (!card) return card;
    const uiTemplateCount = getUiTemplateCount(card.data);
    card.has_ui_templates = uiTemplateCount > 0 ? 1 : 0;
    card.ui_template_count = uiTemplateCount;
    card.ui_template_variable_count = getEmbeddedUiTemplateVariableCount(card.data);
    if (!keepData) delete card.data;
    return card;
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

function sanitizeUiTemplateRow(row, { includeContent = false, viewer = {} } = {}) {
    if (!row) return row;
    const result = { ...row };
    const commentCount = Number(row.comment_count || 0);
    const downloadsCount = Number(row.downloads_count || 0);
    const viewsCount = Number(row.views_count || 0);
    const canViewDownloads = Boolean(viewer.admin || (viewer.user && row.uploader_user_id === viewer.user.id));
    result.content_preview = String(row.content || '').slice(0, 600);
    result.variable_count = getUiTemplateVariableCount(row.content);
    result.comment_count = commentCount;
    result.heat_score = Math.round(viewsCount * 1.0 + commentCount * 1.5 + downloadsCount * 2.5);
    result.can_view_downloads = canViewDownloads;
    if (!canViewDownloads) result.downloads_count = null;
    if (!includeContent) delete result.content;
    return result;
}

function getUiTemplateMetrics(templateId, { viewer = {} } = {}) {
    const row = db.prepare(
        `SELECT id, uploader_user_id, views_count, downloads_count,
                COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments utc WHERE utc.template_id = ui_templates.id)) AS comment_count
         FROM ui_templates
         WHERE id = ?`
    ).get(templateId);
    if (!row) return null;
    const commentCount = Number(row.comment_count || 0);
    const downloadsCount = Number(row.downloads_count || 0);
    const viewsCount = Number(row.views_count || 0);
    const canViewDownloads = Boolean(viewer.admin || (viewer.user && row.uploader_user_id === viewer.user.id));
    const metrics = {
        comment_count: commentCount,
        views_count: viewsCount,
        heat_score: Math.round(viewsCount * 1.0 + commentCount * 1.5 + downloadsCount * 2.5)
    };
    if (canViewDownloads) {
        metrics.downloads_count = downloadsCount;
    }
    return metrics;
}

app.get('/api/cards', optionalUserAuth, (req, res) => {
    try {
        const sortMode = req.query.sort || 'latest';
        const commentCountExpr = 'COALESCE(cc.comment_count_override, (SELECT COUNT(*) FROM character_comments cmt WHERE cmt.card_id = cc.id))';
        const heatExpr = `((IFNULL(cc.views_count, 0) * 1.0) + (IFNULL(${commentCountExpr}, 0) * 1.5) + (IFNULL(cc.downloads_count, 0) * 2.5))`;
        const whereParts = [];
        const params = [];
        let orderByClause = 'cc.created_at DESC';

        if (req.admin || isModeratorUser(req.user)) {
            // Admins and front-end moderators can review every status.
        } else if (req.user) {
            whereParts.push("(cc.review_status = 'approved' OR cc.uploader_user_id = ?)");
            params.push(req.user.id);
        } else {
            whereParts.push("cc.review_status = 'approved'");
        }

        if (sortMode === 'hot') {
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        } else if (sortMode === 'daily') {
            whereParts.push("cc.created_at >= datetime('now', '-1 day')");
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        } else if (sortMode === 'weekly') {
            whereParts.push("cc.created_at >= datetime('now', '-7 days')");
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
        const cards = db.prepare(
            `SELECT cc.id, cc.name, cc.description, cc.creator_notes, cc.data,
                    cc.downloads_count, cc.uploader_user_id, cc.created_at,
                    cc.views_count, cc.is_featured, cc.review_status,
                    cc.reviewed_at, cc.rejection_reason, cc.uploader_ip_address,
                    ${commentCountExpr} AS comment_count
             FROM character_cards cc
             ${whereClause}
             ORDER BY ${orderByClause}`
        ).all(...params).map(card => attachUiTemplateSummary(card));
        res.json(cards);
    } catch (err) {
        console.error('Fetch cards error:', err);
        res.status(500).json({ error: '获取卡片失败' });
    }
});

// ============== UI Template Routes ==============
app.get('/api/ui-templates', optionalUserAuth, (req, res) => {
    try {
        const sortMode = req.query.sort || 'latest';
        const whereParts = [];
        const params = [];
        let orderByClause = 'created_at DESC';

        if (req.admin || isModeratorUser(req.user)) {
            // Admins and front-end moderators can review every status.
        } else if (req.user) {
            whereParts.push("(review_status = 'approved' OR uploader_user_id = ?)");
            params.push(req.user.id);
        } else {
            whereParts.push("review_status = 'approved'");
        }

        const templateCommentCountExpr = `COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments utc WHERE utc.template_id = ui_templates.id))`;
        const heatExpr = `((IFNULL(views_count, 0) * 1.0)
            + (${templateCommentCountExpr} * 1.5)
            + (IFNULL(downloads_count, 0) * 2.5))`;
        if (sortMode === 'featured') {
            whereParts.push('is_featured = 1');
            orderByClause = 'created_at DESC';
        } else if (sortMode === 'hot') {
            orderByClause = `${heatExpr} DESC, downloads_count DESC, created_at DESC`;
        } else if (sortMode === 'daily') {
            whereParts.push("created_at >= datetime('now', '-1 day')");
            orderByClause = `${heatExpr} DESC, downloads_count DESC, created_at DESC`;
        } else if (sortMode === 'weekly') {
            whereParts.push("created_at >= datetime('now', '-7 days')");
            orderByClause = `${heatExpr} DESC, downloads_count DESC, created_at DESC`;
        }

        const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
        const templates = db.prepare(
            `SELECT id, title, description, file_name, file_ext, mime_type, content, file_size,
                    downloads_count, views_count, is_featured, uploader_user_id, review_status, reviewed_at,
                    rejection_reason, uploader_ip_address, created_at,
                    ${templateCommentCountExpr} AS comment_count
             FROM ui_templates
             ${whereClause}
             ORDER BY ${orderByClause}`
        ).all(...params).map(row => sanitizeUiTemplateRow(row, { viewer: { admin: req.admin, user: req.user } }));
        res.json(templates);
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
              uploader_user_id, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
            id, normalizedTitle, String(description || '').trim().slice(0, 1000), safeFileName,
            fileExt, String(mime_type || 'application/json').slice(0, 120), normalizedContent, fileSize,
            uploaderUserId, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now
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
        db.prepare(
            `UPDATE ui_templates
             SET review_status = ?, reviewed_by_admin_id = ?, reviewed_at = ?, rejection_reason = ?
             WHERE id = ?`
        ).run(status, req.admin?.id || null, now, status === 'rejected' ? reason : null, req.params.id);

        const updated = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user.id,
            username: req.admin?.username || req.user.username,
            action: req.admin
                ? (status === 'approved' ? 'admin_approve_ui_template' : 'admin_reject_ui_template')
                : (status === 'approved' ? 'moderator_approve_ui_template' : 'moderator_reject_ui_template'),
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { title: template.title, reason: status === 'rejected' ? reason : undefined }
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
        updated.comment_count = db.prepare('SELECT COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ?)) as count FROM ui_templates WHERE id = ?').get(req.params.id, req.params.id).count;
        res.json({ template: sanitizeUiTemplateRow(updated, { viewer: { admin: req.admin, user: req.user } }) });
    } catch (err) {
        console.error('Review UI template error:', err);
        res.status(500).json({ error: '审核模板失败' });
    }
});

app.put('/api/ui-templates/:id/feature', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const template = db.prepare('SELECT id, title, is_featured FROM ui_templates WHERE id = ?').get(id);
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

        if (!req.admin && fields.length > 0) {
            setField('review_status', 'pending');
            setField('reviewed_by_admin_id', null);
            setField('reviewed_at', null);
            setField('rejection_reason', null);
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        values.push(req.params.id);
        db.prepare(`UPDATE ui_templates SET ${fields.join(', ')} WHERE id = ?`).run(...values);

        const updated = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        updated.comment_count = db.prepare('SELECT COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ?)) as count FROM ui_templates WHERE id = ?').get(req.params.id, req.params.id).count;
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'edit_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { title: updated.title }
        });
        res.json({ template: sanitizeUiTemplateRow(updated, { viewer: { admin: req.admin, user: req.user }, includeContent: true }) });
    } catch (err) {
        console.error('Update UI template error:', err);
        res.status(500).json({ error: '更新 UI 模板失败' });
    }
});

app.delete('/api/ui-templates/:id', requireUserOrAdmin, (req, res) => {
    try {
        const template = db.prepare('SELECT id, title, uploader_user_id FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const isOwner = req.user && template.uploader_user_id === req.user.id;
        if (!req.admin && !isOwner) return res.status(403).json({ error: '无权删除此模板' });

        db.prepare('DELETE FROM ui_templates WHERE id = ?').run(req.params.id);
        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'delete_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req),
            details: { title: template.title }
        });
        res.json([{ id: req.params.id }]);
    } catch (err) {
        console.error('Delete UI template error:', err);
        res.status(500).json({ error: '删除模板失败' });
    }
});

app.get('/api/ui-templates/:id', optionalUserAuth, (req, res) => {
    try {
        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });

        if (!req.admin && !isModeratorUser(req.user) && !(req.user && template.uploader_user_id === req.user.id)) {
            const viewLimit = recordAccountViewHeat(req, 'ui_template', req.params.id);
            if (viewLimit.counted) {
                db.prepare('UPDATE ui_templates SET views_count = views_count + 1 WHERE id = ?').run(req.params.id);
                template.views_count = (template.views_count || 0) + 1;
            }
        }
        template.comment_count = db.prepare('SELECT COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ?)) as count FROM ui_templates WHERE id = ?').get(req.params.id, req.params.id).count;

        res.json(sanitizeUiTemplateRow(template, { includeContent: true, viewer: { admin: req.admin, user: req.user } }));
    } catch (err) {
        console.error('Fetch UI template detail error:', err);
        res.status(500).json({ error: '获取 UI 模板详情失败' });
    }
});

app.get('/api/ui-templates/:id/download', optionalUserAuth, (req, res) => {
    try {
        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });

        const isOwner = req.user && template.uploader_user_id === req.user.id;
        if (!req.admin && !isModeratorUser(req.user) && !isOwner) {
            db.prepare('UPDATE ui_templates SET downloads_count = downloads_count + 1 WHERE id = ?').run(req.params.id);
        }
        logOperation({
            userType: req.admin ? 'admin' : (req.user ? 'user' : 'anonymous'),
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
        console.error('Download UI template error:', err);
        res.status(500).json({ error: '下载模板失败' });
    }
});

app.post('/api/ui-templates/:id/download', optionalUserAuth, (req, res) => {
    try {
        const template = db.prepare('SELECT * FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });

        const isOwner = req.user && template.uploader_user_id === req.user.id;
        if (!req.admin && !isModeratorUser(req.user) && !isOwner) {
            db.prepare('UPDATE ui_templates SET downloads_count = downloads_count + 1 WHERE id = ?').run(req.params.id);
        }
        logOperation({
            userType: req.admin ? 'admin' : (req.user ? 'user' : 'anonymous'),
            userId: req.admin?.id || req.user?.id,
            username: req.admin?.username || req.user?.username,
            action: 'download_ui_template',
            targetType: 'ui_template',
            targetId: req.params.id,
            ip: getRequestIp(req)
        });

        const fileName = sanitizeUiTemplateFileName(template.file_name || `${template.title}.ui`);
        const downloadToken = createUiTemplateDownloadToken(req.params.id, fileName);
        res.json({
            success: true,
            download_url: `/api/ui-templates/${req.params.id}/download/file?token=${encodeURIComponent(downloadToken)}`
        });
    } catch (err) {
        console.error('Prepare UI template download error:', err);
        res.status(500).json({ error: '下载模板失败' });
    }
});

app.get('/api/ui-templates/:id/download/file', (req, res) => {
    try {
        const token = typeof req.query.token === 'string' ? req.query.token : '';
        if (!token) {
            return res.status(401).json({ error: '下载链接无效或已过期' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'ui-template-download' || decoded.templateId !== req.params.id) {
            return res.status(403).json({ error: '下载链接无效或已过期' });
        }

        const template = db.prepare('SELECT id, title, file_name, mime_type, content FROM ui_templates WHERE id = ?').get(req.params.id);
        if (!template) return res.status(404).json({ error: '模板不存在' });

        const fileName = typeof decoded.fileName === 'string' && decoded.fileName.trim()
            ? sanitizeUiTemplateFileName(decoded.fileName)
            : sanitizeUiTemplateFileName(template.file_name || `${template.title}.ui`);
        res.set('Content-Type', template.mime_type || 'text/plain; charset=utf-8');
        res.set('Cache-Control', 'no-store');
        res.set('Content-Disposition', createAttachmentDisposition(fileName));
        res.send(template.content);
    } catch (err) {
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: '下载链接无效或已过期' });
        }
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
    return new RegExp(`/api/cards/${cardId}/(?:avatar|thumbnail)$`, 'i').test(normalized);
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

const DOWNLOAD_LINK_TTL_SECONDS = 60;
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

function createCardDownloadToken(cardId, fileName) {
    return jwt.sign(
        { role: 'card-download', cardId, fileName },
        JWT_SECRET,
        { expiresIn: `${DOWNLOAD_LINK_TTL_SECONDS}s` }
    );
}

function createUiTemplateDownloadToken(templateId, fileName) {
    return jwt.sign(
        { role: 'ui-template-download', templateId, fileName },
        JWT_SECRET,
        { expiresIn: `${DOWNLOAD_LINK_TTL_SECONDS}s` }
    );
}

function buildCardMetadataChunk(cardData) {
    const payload = Buffer.from(JSON.stringify(cardData ?? null), 'utf8').toString('base64');
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

function injectCardMetadataIntoPng(pngBuffer, cardData) {
    const source = Buffer.isBuffer(pngBuffer) ? pngBuffer : Buffer.from(pngBuffer);
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
        if (sharp) {
            pngBuffer = await sharp(asset.buffer).png().toBuffer();
        } else if (contentType.includes('png')) {
            pngBuffer = Buffer.from(asset.buffer);
        } else {
            throw new Error('sharp 不可用，无法转换下载卡图片');
        }
    }

    return injectCardMetadataIntoPng(pngBuffer, card.data);
}

function cacheThumbnail(cardId, body, contentType, cacheControl) {
    if (thumbnailCache.size >= THUMBNAIL_MAX_CACHE) {
        const firstKey = thumbnailCache.keys().next().value;
        thumbnailCache.delete(firstKey);
    }
    thumbnailCache.set(cardId, { body, contentType, cacheControl });
}

app.get('/api/cards/:id/avatar', async (req, res) => {
    try {
        const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(req.params.id);
        if (!row) return res.status(404).end();

        const safeAvatarUrl = sanitizeAvatarUrl(row.avatar_url, req.params.id);

        // No avatar data — generate placeholder
        if (!safeAvatarUrl) {
            const svg = buildPlaceholderSvg(row.name, req.params.id, 800, 1067, 320);
            if (!sharp) {
                res.set('Content-Type', 'image/svg+xml');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(svg);
            }
            const placeholder = await sharp(Buffer.from(svg)).png().toBuffer();
            res.set('Content-Type', 'image/png');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(placeholder);
        }

        const asset = await resolveAvatarAsset(safeAvatarUrl);
        res.set('Content-Type', asset.contentType);
        res.set('Cache-Control', asset.cacheControl);
        res.send(asset.buffer);
    } catch (err) {
        console.error('Avatar fetch error:', err);
        try {
            const row = db.prepare('SELECT name FROM character_cards WHERE id = ?').get(req.params.id);
            if (!row) {
                return res.status(404).end();
            }
            const svg = buildPlaceholderSvg(row.name, req.params.id, 800, 1067, 320);
            if (!sharp) {
                res.set('Content-Type', 'image/svg+xml');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(svg);
            }
            const placeholder = await sharp(Buffer.from(svg)).png().toBuffer();
            res.set('Content-Type', 'image/png');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(placeholder);
        } catch (fallbackError) {
            console.error('Avatar placeholder fallback error:', fallbackError);
            res.status(500).end();
        }
    }
});

// Thumbnail endpoint - compressed preview for card listing
const thumbnailCache = new Map();
const THUMBNAIL_MAX_CACHE = 500;
const REMOTE_FETCH_TIMEOUT_MS = 5000;
const MAX_REMOTE_IMAGE_BYTES = 20 * 1024 * 1024;
const MAX_REMOTE_FETCH_RETRIES = 2;

app.get('/api/cards/:id/thumbnail', async (req, res) => {
    try {
        const cardId = req.params.id;
        
        // Check memory cache
        if (thumbnailCache.has(cardId)) {
            const cached = thumbnailCache.get(cardId);
            res.set('Content-Type', cached.contentType);
            res.set('Cache-Control', cached.cacheControl);
            return res.send(cached.body);
        }

        const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(cardId);
        if (!row) return res.status(404).end();
        const safeAvatarUrl = sanitizeAvatarUrl(row.avatar_url, cardId);

        // No avatar data — generate placeholder thumbnail with first character
        if (!safeAvatarUrl) {
            const svg = buildPlaceholderSvg(row.name, cardId, 400, 533, 160);
            if (!sharp) {
                res.set('Content-Type', 'image/svg+xml');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(svg);
            }
            const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 75 }).toBuffer();
            cacheThumbnail(cardId, placeholder, 'image/webp', 'public, max-age=86400');
            res.set('Content-Type', 'image/webp');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(placeholder);
        }

        const asset = await resolveAvatarAsset(safeAvatarUrl);

        if (!sharp) {
            res.set('Content-Type', asset.contentType);
            res.set('Cache-Control', asset.cacheControl);
            return res.send(asset.buffer);
        }

        const thumbnail = await sharp(asset.buffer)
            .resize(400, null, { withoutEnlargement: true })
            .webp({ quality: 75 })
            .toBuffer();

        cacheThumbnail(cardId, thumbnail, 'image/webp', 'public, max-age=2592000, immutable');

        res.set('Content-Type', 'image/webp');
        res.set('Cache-Control', 'public, max-age=2592000, immutable');
        res.send(thumbnail);
    } catch (err) {
        console.error('Thumbnail generation error:', err);
        // Fallback to full avatar bytes
        try {
            const row = db.prepare('SELECT avatar_url, name FROM character_cards WHERE id = ?').get(req.params.id);
            const safeAvatarUrl = row ? sanitizeAvatarUrl(row.avatar_url, req.params.id) : '';
            if (safeAvatarUrl) {
                const asset = await resolveAvatarAsset(safeAvatarUrl);
                res.set('Content-Type', asset.contentType);
                res.set('Cache-Control', asset.cacheControl);
                return res.send(asset.buffer);
            }
            if (row) {
                const svg = buildPlaceholderSvg(row.name, req.params.id, 400, 533, 160);
                if (!sharp) {
                    res.set('Content-Type', 'image/svg+xml');
                    res.set('Cache-Control', 'public, max-age=86400');
                    return res.send(svg);
                }
                const placeholder = await sharp(Buffer.from(svg)).webp({ quality: 75 }).toBuffer();
                res.set('Content-Type', 'image/webp');
                res.set('Cache-Control', 'public, max-age=86400');
                return res.send(placeholder);
            }
        } catch {}
        res.status(500).end();
    }
});

app.get('/api/cards/:id', optionalUserAuth, (req, res) => {
    try {
        const card = db.prepare(
            `SELECT cc.*
             FROM character_cards cc
             WHERE cc.id = ?`
        ).get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const canView = card.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && card.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '卡片不存在' });
        try { card.data = card.data ? JSON.parse(card.data) : null; } catch (e) { card.data = null; }
        attachUiTemplateSummary(card, { keepData: true });
        res.json(card);
    } catch (err) {
        console.error('Fetch card detail error:', err);
        res.status(500).json({ error: '获取卡片详情失败' });
    }
});

app.post('/api/cards', requireUserOrAdmin, (req, res) => {
    try {
        const { name, description, avatar_url, data, creator_notes } = req.body;
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

        // Duplicate detection via stable hash of card data (atomic via UNIQUE index)
        const dataHash = hashCardData(data);
        if (dataHash) {
            const existing = db.prepare('SELECT id, name FROM character_cards WHERE data_hash = ?').get(dataHash);
            if (existing) {
                return res.status(409).json({ error: `已存在完全相同的角色卡「${existing.name}」，禁止重复上传` });
            }
        }

        const id = generateId();
        const now = new Date().toISOString();
        const dataStr = data ? JSON.stringify(data) : null;
        const uploaderUserId = req.user ? req.user.id : null;
        const safeAvatarUrl = sanitizeAvatarUrl(avatar_url, id);
        const reviewStatus = req.admin ? 'approved' : 'pending';
        const reviewedBy = req.admin ? req.admin.id : null;
        const reviewedAt = req.admin ? now : null;
        const uploaderIp = getRequestIp(req);

        try {
            db.prepare(
                `INSERT INTO character_cards
                 (id, name, description, avatar_url, data, creator_notes, uploader_user_id, data_hash, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(id, name, description || '', safeAvatarUrl, dataStr, creator_notes || '', uploaderUserId, dataHash, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now);
        } catch (insertErr) {
            if (insertErr.message && insertErr.message.includes('UNIQUE constraint failed')) {
                const conflict = db.prepare('SELECT name FROM character_cards WHERE data_hash = ?').get(dataHash);
                return res.status(409).json({ error: `已存在完全相同的角色卡「${conflict?.name || '未知'}」，禁止重复上传` });
            }
            // If FOREIGN KEY fails (user doesn't exist in DB), retry without uploader_user_id
            if (insertErr.message && insertErr.message.includes('FOREIGN KEY')) {
                db.prepare(
                    `INSERT INTO character_cards
                     (id, name, description, avatar_url, data, creator_notes, uploader_user_id, data_hash, review_status, reviewed_by_admin_id, reviewed_at, uploader_ip_address, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).run(id, name, description || '', safeAvatarUrl, dataStr, creator_notes || '', null, dataHash, reviewStatus, reviewedBy, reviewedAt, uploaderIp, now);
            } else {
                throw insertErr;
            }
        }

        const card = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(id);
        try { card.data = card.data ? JSON.parse(card.data) : null; } catch (e) { card.data = null; }
        attachUiTemplateSummary(card, { keepData: true });
        logOperation({
            userType: req.user ? 'user' : 'admin',
            userId: uploaderUserId || req.admin?.id,
            username: req.user?.username || req.admin?.username,
            action: req.admin ? 'upload' : 'upload_pending',
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

        res.json([card, { pending_review: reviewStatus === 'pending' }]);
    } catch (err) {
        console.error('Create card error:', err);
        res.status(500).json({ error: '创建卡片失败' });
    }
});

app.delete('/api/cards/:id', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        let isAdmin = false;
        let isModerator = false;
        let userId = null;
        let username = '';
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'admin') {
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
        const card = db.prepare('SELECT name, uploader_user_id, review_status FROM character_cards WHERE id = ?').get(id);
        if (!card) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        // Only admin, front-end moderator, or card owner can delete.
        const ownerUserId = card.uploader_user_id == null ? null : Number(card.uploader_user_id);
        if (!isAdmin && !isModerator && (!userId || ownerUserId !== Number(userId))) {
            return res.status(403).json({ error: '无权删除此卡片' });
        }

        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(id);
            // Reclaim upload credits (3) from uploader, minimum 0
            if (card.uploader_user_id && card.review_status === 'approved') {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
        });
        deleteAndReclaim();
        thumbnailCache.delete(id);

        logOperation({
            userType: isAdmin ? 'admin' : 'user',
            userId,
            username,
            action: isAdmin ? 'admin_delete_card' : (isModerator ? 'moderator_delete_card' : 'delete'),
            targetType: 'card',
            targetId: id,
            ip: getRequestIp(req),
            details: { name: card?.name }
        });
        res.json([{ id }]);
    } catch (err) {
        console.error('Delete card error:', err);
        res.status(500).json({ error: '删除卡片失败' });
    }
});

app.put('/api/cards/:id', (req, res) => {
    // Authenticate: card owner OR admin
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const card = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        let userType, userId, username;
        if (decoded.role === 'admin') {
            const admin = validateAdminTokenPayload(decoded);
            if (!admin) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            userType = 'admin'; userId = admin.id; username = admin.username;
        } else if (decoded.role === 'user' && card.uploader_user_id === decoded.id) {
            const user = validateUserTokenPayload(decoded);
            if (!user) return res.status(401).json({ error: '登录状态已失效，请重新登录' });
            if (!userEmailBound(user)) return rejectUnboundEmail(req, res);
            if (card.uploader_user_id !== user.id) return res.status(403).json({ error: '无权编辑此卡片' });
            userType = 'user'; userId = user.id; username = user.username;
        } else {
            return res.status(403).json({ error: '无权编辑此卡片' });
        }

        const { name, description, avatar_url, data, creator_notes, created_at, reupload_replace } = req.body;
        const fields = [];
        const values = [];
        if (name !== undefined)          { fields.push('name = ?');          values.push(name); }
        if (description !== undefined)   { fields.push('description = ?');   values.push(description); }
        if (avatar_url !== undefined) {
            const safeAvatarUrl = sanitizeAvatarUrl(avatar_url, req.params.id);
            if (safeAvatarUrl) {
                fields.push('avatar_url = ?');
                values.push(safeAvatarUrl);
            }
        }
        if (data !== undefined) {
            let serializedData;
            try {
                serializedData = typeof data === 'string' ? data : JSON.stringify(data);
                JSON.parse(serializedData);
            } catch (parseError) {
                return res.status(400).json({ error: '卡片数据格式无效' });
            }
            fields.push('data = ?');
            values.push(serializedData);
        }
        if (creator_notes !== undefined) { fields.push('creator_notes = ?'); values.push(creator_notes); }
        if (created_at !== undefined && decoded.role === 'admin') {
            if (isNaN(Date.parse(created_at))) return res.status(400).json({ error: '无效的时间格式' });
            fields.push('created_at = ?'); values.push(created_at);
        }
        if (decoded.role === 'user') {
            fields.push("review_status = 'approved'");
            fields.push('reviewed_by_admin_id = NULL');
            fields.push('reviewed_at = ?');
            values.push(new Date().toISOString());
            fields.push('rejection_reason = NULL');
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        values.push(req.params.id);
        const updateCard = db.transaction(() => {
            db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);
            if (decoded.role === 'user' && card.review_status !== 'approved' && card.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = download_credits + 3 WHERE id = ?').run(card.uploader_user_id);
            }
        });
        updateCard();
        thumbnailCache.delete(req.params.id);

        logOperation({ userType, userId, username, action: 'edit', targetType: 'card', targetId: req.params.id, ip: getRequestIp(req), details: { name: card.name } });

        const updated = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(req.params.id);
        try { updated.data = updated.data ? JSON.parse(updated.data) : null; } catch (e) { updated.data = null; }
        attachUiTemplateSummary(updated, { keepData: true });
        res.json([updated]);
    } catch (err) {
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: '令牌无效或已过期' });
        }
        console.error('Update card error:', err);
        res.status(500).json({ error: '更新卡片失败' });
    }
});

// ============== Card Featured Toggle (Admin Only) ==============
app.put('/api/cards/:id/feature', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare('SELECT id, name, is_featured FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        const newFeatured = card.is_featured ? 0 : 1;
        db.prepare('UPDATE character_cards SET is_featured = ? WHERE id = ?').run(newFeatured, id);

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: newFeatured ? 'feature' : 'unfeature',
            targetType: 'card', targetId: id, ip: getRequestIp(req),
            details: { name: card.name }
        });

        res.json({ id, is_featured: newFeatured });
    } catch (err) {
        console.error('Feature card error:', err);
        res.status(500).json({ error: '操作失败' });
    }
});

// ============== Card Heat Adjustment (Admin Only) ==============
app.put('/api/cards/:id/heat', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare(
            `SELECT id, name, views_count, downloads_count,
                    COALESCE(comment_count_override, (SELECT COUNT(*) FROM character_comments WHERE card_id = character_cards.id)) AS comment_count
             FROM character_cards WHERE id = ?`
        ).get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        const { views_count, downloads_count, comment_count } = req.body;
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
        if (comment_count !== undefined) {
            const c = parseInt(comment_count);
            if (!Number.isInteger(c) || c < 0) return res.status(400).json({ error: '评论数必须是非负整数' });
            fields.push('comment_count_override = ?');
            values.push(c);
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });

        values.push(id);
        db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: 'admin_adjust_heat', targetType: 'card', targetId: id, ip: getRequestIp(req),
            details: { name: card.name, views_count, downloads_count, comment_count }
        });

        const updated = db.prepare(
            `SELECT views_count, downloads_count,
                    COALESCE(comment_count_override, (SELECT COUNT(*) FROM character_comments WHERE card_id = character_cards.id)) AS comment_count
             FROM character_cards WHERE id = ?`
        ).get(id);
        maybeSendCardHeatMilestoneEmail(id, req);
        res.json({
            success: true,
            views_count: updated.views_count,
            downloads_count: updated.downloads_count,
            comment_count: updated.comment_count,
            heat_score: Math.round((updated.views_count || 0) * 1.0 + (updated.comment_count || 0) * 1.5 + (updated.downloads_count || 0) * 2.5)
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
                    COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ui_templates.id)) AS comment_count
             FROM ui_templates WHERE id = ?`
        ).get(id);
        if (!template) return res.status(404).json({ error: '模板不存在' });

        const { views_count, downloads_count, comment_count } = req.body;
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
        if (comment_count !== undefined) {
            const c = parseInt(comment_count);
            if (!Number.isInteger(c) || c < 0) return res.status(400).json({ error: '评论数必须是非负整数' });
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
            details: { title: template.title, views_count, downloads_count, comment_count }
        });

        const updated = db.prepare(
            `SELECT views_count, downloads_count,
                    COALESCE(comment_count_override, (SELECT COUNT(*) FROM ui_template_comments WHERE template_id = ui_templates.id)) AS comment_count
             FROM ui_templates WHERE id = ?`
        ).get(id);
        res.json({
            success: true,
            views_count: updated.views_count,
            downloads_count: updated.downloads_count,
            comment_count: updated.comment_count,
            heat_score: Math.round((updated.views_count || 0) * 1.0 + (updated.comment_count || 0) * 1.5 + (updated.downloads_count || 0) * 2.5)
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
        if (card.review_status !== 'approved' && !req.admin && !isModerator && !isOwner) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        let newCredits = null;
        let downloadCounted = false;
        const recordDownload = db.transaction(() => {
            if (!req.admin && !isModerator) {
                if (!isOwner) {
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
            if (!isOwner && !req.admin && !isModerator) {
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
        if (downloadCounted) maybeSendCardHeatMilestoneEmail(id, req);
        logOperation({ userType: req.user ? 'user' : 'admin', userId: req.user?.id || req.admin?.id, username: req.user?.username || req.admin?.username, action: 'download', targetType: 'card', targetId: id, ip: getRequestIp(req) });

        const fileName = sanitizeDownloadFilename(card.name);
        const downloadToken = createCardDownloadToken(id, fileName);
        res.json({
            success: true,
            new_credits: newCredits,
            download_counted: downloadCounted,
            downloads_count: latestDownloads,
            download_url: `/api/cards/${id}/download/file?token=${encodeURIComponent(downloadToken)}`
        });
    } catch (err) {
        if (err.statusCode) {
            return res.status(err.statusCode).json({ error: err.message });
        }
        console.error('Download count error:', err);
        res.status(500).json({ error: '更新下载次数失败' });
    }
});

app.get('/api/cards/:id/download/file', async (req, res) => {
    try {
        const token = typeof req.query.token === 'string' ? req.query.token : '';
        if (!token) {
            return res.status(401).json({ error: '下载链接无效或已过期' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'card-download' || decoded.cardId !== req.params.id) {
            return res.status(403).json({ error: '下载链接无效或已过期' });
        }

        const card = db.prepare('SELECT id, name, avatar_url, data FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        try {
            card.data = card.data ? JSON.parse(card.data) : null;
        } catch {
            card.data = null;
        }

        const fileBuffer = await buildCardDownloadFile(card);
        const fileName = typeof decoded.fileName === 'string' && decoded.fileName.trim()
            ? sanitizeDownloadFilename(decoded.fileName)
            : sanitizeDownloadFilename(card.name);
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        res.set('Content-Disposition', createAttachmentDisposition(fileName));
        res.send(fileBuffer);
    } catch (err) {
        if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: '下载链接无效或已过期' });
        }
        console.error('Download file error:', err);
        res.status(500).json({ error: '生成下载文件失败' });
    }
});

// ============== Card Like Routes ==============
app.post('/api/cards/:id/like', authenticateUser, (req, res) => {
    try {
        const cardId = req.params.id;
        const userId = req.user.id;

        const card = db.prepare("SELECT id FROM character_cards WHERE id = ? AND review_status = 'approved'").get(cardId);
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
        "SELECT COUNT(*) as count FROM character_comments WHERE user_id = ? AND created_at >= ? AND created_at < date(?, '+1 day')"
    ).get(userId, todayStr, todayStr).count;
    const templateCount = db.prepare(
        "SELECT COUNT(*) as count FROM ui_template_comments WHERE user_id = ? AND created_at >= ? AND created_at < date(?, '+1 day')"
    ).get(userId, todayStr, todayStr).count;
    return (cardCount || 0) + (templateCount || 0);
}

// ============== Comment Routes ==============
app.get('/api/cards/:cardId/comments', optionalUserAuth, (req, res) => {
    try {
        const cardId = req.params.cardId;
        const userId = req.user ? req.user.id : null;
        const card = db.prepare('SELECT id, uploader_user_id, review_status FROM character_cards WHERE id = ?').get(cardId);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const canView = card.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && card.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '卡片不存在' });

        const comments = db.prepare(
            `SELECT c.*, u.username as author_name,
                    (SELECT cc2.uploader_user_id FROM character_cards cc2 WHERE cc2.id = c.card_id) as card_uploader_id
             FROM character_comments c 
             LEFT JOIN users u ON c.user_id = u.id 
             WHERE c.card_id = ? 
             ORDER BY c.created_at ASC`
        ).all(cardId);

        // Find the hot comment (highest likes >= 5)
        const hotComment = db.prepare(
            `SELECT id FROM character_comments 
             WHERE card_id = ? AND likes_count >= 5 
             ORDER BY likes_count DESC LIMIT 1`
        ).get(cardId);

        // Check which comments the current user has liked
        let likedCommentIds = new Set();
        if (userId) {
            const liked = db.prepare(
                'SELECT comment_id FROM comment_likes WHERE user_id = ? AND comment_id IN (SELECT id FROM character_comments WHERE card_id = ?)'
            ).all(userId, cardId);
            likedCommentIds = new Set(liked.map(l => l.comment_id));
        }

        const result = comments.map(c => ({
            ...c,
            user_liked: likedCommentIds.has(c.id),
            is_hot: hotComment && hotComment.id === c.id
        }));

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
        const card = db.prepare(
            `SELECT cc.id, cc.name, cc.uploader_user_id,
                    u.username, u.email, u.email_verified
             FROM character_cards cc
             LEFT JOIN users u ON cc.uploader_user_id = u.id
             WHERE cc.id = ? AND cc.review_status = 'approved'`
        ).get(req.params.cardId);
        if (!card) return res.status(404).json({ error: '卡片不存在或尚未通过审核' });

        const id = generateId();
        const now = new Date().toISOString();

        // Resolve reply info
        let replyToName = null;
        if (reply_to_id) {
            const replyComment = db.prepare('SELECT c.id, u.username FROM character_comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.id = ?').get(reply_to_id);
            if (replyComment) replyToName = replyComment.username || '匿名用户';
        }

        // Check daily comment credit limit (max 2 comments per day earn credits)
        const todayStr = now.slice(0, 10); // YYYY-MM-DD
        const todayCommentCount = countTodayCreditComments(userId, todayStr);
        const canEarnCredits = todayCommentCount < 2;

        // Insert comment and optionally add credits
        const insertComment = db.transaction(() => {
            db.prepare(
                'INSERT INTO character_comments (id, card_id, user_id, nickname, content, reply_to_id, reply_to_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.cardId, userId, user.username, content.trim(), reply_to_id || null, replyToName, now);
            db.prepare(
                'UPDATE character_cards SET comment_count_override = comment_count_override + 1 WHERE id = ? AND comment_count_override IS NOT NULL'
            ).run(req.params.cardId);

            if (canEarnCredits) {
                db.prepare('UPDATE users SET download_credits = download_credits + 2 WHERE id = ?').run(userId);
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
        if (card.uploader_user_id && card.uploader_user_id !== userId && userEmailBound(card)) {
            sendCommentNotificationEmail({
                to: card.email,
                ownerName: card.username,
                commenterName: user.username,
                itemType: '角色卡',
                title: card.name,
                content: content.trim()
            });
        }
        res.json({ comment, new_credits: updatedUser.download_credits, credits_earned: canEarnCredits });
    } catch (err) {
        console.error('Create comment error:', err);
        res.status(500).json({ error: '发布评论失败' });
    }
});

app.get('/api/ui-templates/:templateId/comments', optionalUserAuth, (req, res) => {
    try {
        const templateId = req.params.templateId;
        const userId = req.user ? req.user.id : null;
        const template = db.prepare('SELECT id, uploader_user_id, review_status FROM ui_templates WHERE id = ?').get(templateId);
        if (!template) return res.status(404).json({ error: '模板不存在' });
        const canView = template.review_status === 'approved'
            || (req.admin && req.admin.id)
            || isModeratorUser(req.user)
            || (req.user && template.uploader_user_id === req.user.id);
        if (!canView) return res.status(404).json({ error: '模板不存在' });

        const comments = db.prepare(
            `SELECT c.*, u.username as author_name,
                    (SELECT ut.uploader_user_id FROM ui_templates ut WHERE ut.id = c.template_id) as template_uploader_id
             FROM ui_template_comments c
             LEFT JOIN users u ON c.user_id = u.id
             WHERE c.template_id = ?
             ORDER BY c.created_at ASC`
        ).all(templateId);

        const hotComment = db.prepare(
            `SELECT id FROM ui_template_comments
             WHERE template_id = ? AND likes_count >= 5
             ORDER BY likes_count DESC LIMIT 1`
        ).get(templateId);

        let likedCommentIds = new Set();
        if (userId) {
            const liked = db.prepare(
                'SELECT comment_id FROM ui_template_comment_likes WHERE user_id = ? AND comment_id IN (SELECT id FROM ui_template_comments WHERE template_id = ?)'
            ).all(userId, templateId);
            likedCommentIds = new Set(liked.map(l => l.comment_id));
        }

        res.json(comments.map(c => ({
            ...c,
            user_liked: likedCommentIds.has(c.id),
            is_hot: hotComment && hotComment.id === c.id
        })));
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
        const template = db.prepare(
            `SELECT ut.id, ut.title, ut.uploader_user_id,
                    u.username, u.email, u.email_verified
             FROM ui_templates ut
             LEFT JOIN users u ON ut.uploader_user_id = u.id
             WHERE ut.id = ? AND ut.review_status = 'approved'`
        ).get(req.params.templateId);
        if (!template) return res.status(404).json({ error: '模板不存在或尚未通过审核' });

        const id = generateId();
        const now = new Date().toISOString();

        let replyToName = null;
        if (reply_to_id) {
            const replyComment = db.prepare(
                'SELECT c.id, u.username FROM ui_template_comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.id = ? AND c.template_id = ?'
            ).get(reply_to_id, req.params.templateId);
            if (replyComment) replyToName = replyComment.username || '匿名用户';
        }

        const todayStr = now.slice(0, 10);
        const canEarnCredits = countTodayCreditComments(userId, todayStr) < 2;

        const insertComment = db.transaction(() => {
            db.prepare(
                'INSERT INTO ui_template_comments (id, template_id, user_id, nickname, content, reply_to_id, reply_to_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.templateId, userId, user.username, content.trim(), reply_to_id || null, replyToName, now);
            db.prepare(
                'UPDATE ui_templates SET comment_count_override = comment_count_override + 1 WHERE id = ? AND comment_count_override IS NOT NULL'
            ).run(req.params.templateId);

            if (canEarnCredits) {
                db.prepare('UPDATE users SET download_credits = download_credits + 2 WHERE id = ?').run(userId);
            }
        });
        insertComment();

        const comment = db.prepare('SELECT * FROM ui_template_comments WHERE id = ?').get(id);
        comment.author_name = user.username;
        comment.user_liked = false;
        comment.is_hot = false;
        comment.template_uploader_id = template.uploader_user_id || null;

        const updatedUser = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId);
        if (template.uploader_user_id && template.uploader_user_id !== userId && userEmailBound(template)) {
            sendCommentNotificationEmail({
                to: template.email,
                ownerName: template.username,
                commenterName: user.username,
                itemType: 'UI模板',
                title: template.title,
                content: content.trim()
            });
        }
        res.json({
            comment,
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
                db.prepare(
                    `UPDATE ui_templates
                     SET comment_count_override = CASE
                        WHEN comment_count_override > 0 THEN comment_count_override - 1
                        ELSE 0
                     END
                     WHERE id = ? AND comment_count_override IS NOT NULL`
                ).run(comment.template_id);
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
                db.prepare(
                    `UPDATE character_cards
                     SET comment_count_override = CASE
                        WHEN comment_count_override > 0 THEN comment_count_override - 1
                        ELSE 0
                     END
                     WHERE id = ? AND comment_count_override IS NOT NULL`
                ).run(comment.card_id);
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
        res.json({ success: true });
    } catch (err) {
        console.error('Delete comment error:', err);
        res.status(500).json({ error: '删除评论失败' });
    }
});

// ============== Admin Routes ==============
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    try {
        const totalCards = db.prepare('SELECT COUNT(*) as count FROM character_cards').get().count;
        const totalComments = db.prepare('SELECT COUNT(*) as count FROM character_comments').get().count;
        const totalDownloads = db.prepare('SELECT COALESCE(SUM(downloads_count), 0) as count FROM character_cards').get().count;
        const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
        const totalLikes = db.prepare('SELECT COALESCE(SUM(likes_count), 0) as count FROM character_comments').get().count;
        const totalVisits = db.prepare('SELECT COUNT(*) as count FROM page_views').get().count;
        const pendingCards = db.prepare("SELECT COUNT(*) as count FROM character_cards WHERE review_status = 'pending'").get().count;
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

        // 7-day daily comments
        const dailyComments = db.prepare(`
            SELECT date(created_at) as day, COUNT(*) as comments
            FROM character_comments
            WHERE created_at >= date('now', '-6 days')
            GROUP BY date(created_at)
        `).all();

        // 7-day daily visits
        const dailyVisits = db.prepare(`
            SELECT date(created_at) as day, COUNT(*) as visits
            FROM page_views
            WHERE created_at >= date('now', '-6 days')
            GROUP BY date(created_at)
        `).all();

        res.json({
            totalCards, totalComments, totalDownloads, totalUsers, totalLikes, totalVisits,
            recentCards, recentComments, todayNewUsers, todayNewCards, todayNewComments,
            loginAttempts, pendingCards, bannedIpCount, topCards, dailyActivity, dailyComments, dailyVisits
        });
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

        let query = `SELECT cc.id, cc.name, cc.description, cc.creator_notes, cc.downloads_count,
                            cc.uploader_user_id, u.username AS uploader_username,
                            cc.review_status, cc.reviewed_at, cc.rejection_reason, cc.uploader_ip_address, cc.created_at
                     FROM character_cards cc
                     LEFT JOIN users u ON cc.uploader_user_id = u.id`;
        let countQuery = 'SELECT COUNT(*) as count FROM character_cards cc LEFT JOIN users u ON cc.uploader_user_id = u.id';
        const params = [];
        const countParams = [];
        const whereParts = [];
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
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

        const total = db.prepare(countQuery).get(...countParams).count;
        query += ' ORDER BY cc.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const cards = db.prepare(query).all(...params);
        res.json({ cards, total, page, limit, totalPages: Math.ceil(total / limit) });
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

        thumbnailCache.delete(id);
        const updated = db.prepare(
            'SELECT id, name, description, creator_notes, data, downloads_count, uploader_user_id, review_status, reviewed_at, rejection_reason, uploader_ip_address, created_at FROM character_cards WHERE id = ?'
        ).get(id);
        attachUiTemplateSummary(updated);

        logOperation({
            userType: req.admin ? 'admin' : 'user',
            userId: req.admin?.id || req.user.id,
            username: req.admin?.username || req.user.username,
            action: req.admin
                ? (status === 'approved' ? 'admin_approve_card' : 'admin_reject_card')
                : (status === 'approved' ? 'moderator_approve_card' : 'moderator_reject_card'),
            targetType: 'card',
            targetId: id,
            ip: getRequestIp(req),
            details: { name: card.name, reason: status === 'rejected' ? reason : undefined }
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

        res.json({ success: true, card: updated });
    } catch (err) {
        console.error('Admin review card error:', err);
        res.status(500).json({ error: '审核失败' });
    }
});

app.delete('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    try {
        const card = db.prepare('SELECT name, uploader_user_id, review_status FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(req.params.id);
            if (card.uploader_user_id && card.review_status === 'approved') {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
        });
        deleteAndReclaim();
        thumbnailCache.delete(req.params.id);
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'admin_delete_card', targetType: 'card', targetId: req.params.id, ip: getRequestIp(req), details: { name: card?.name } });
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
        const comment = db.prepare('SELECT card_id, content FROM character_comments WHERE id = ?').get(req.params.id);
        const deleteComment = db.transaction(() => {
            const result = db.prepare('DELETE FROM character_comments WHERE id = ?').run(req.params.id);
            if (result.changes > 0 && comment?.card_id) {
                db.prepare(
                    `UPDATE character_cards
                     SET comment_count_override = CASE
                        WHEN comment_count_override > 0 THEN comment_count_override - 1
                        ELSE 0
                     END
                     WHERE id = ? AND comment_count_override IS NOT NULL`
                ).run(comment.card_id);
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
        settings.forEach(s => { result[s.key] = s.value; });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: '获取设置失败' });
    }
});

app.get('/api/admin/email-settings', authenticateAdmin, (req, res) => {
    try {
        const dbApiKey = getSettingValue('zeabur_email_api_key');
        const config = getEmailConfig();
        res.json({
            configured: Boolean(config.apiKey && config.from),
            api_key_configured: Boolean(config.apiKey),
            api_key_masked: maskSecret(config.apiKey),
            api_key_source: dbApiKey ? 'admin' : (ZEABUR_EMAIL_API_KEY ? 'environment' : 'none'),
            from: config.from || '',
            endpoint: config.endpoint || ZEABUR_EMAIL_ENDPOINT,
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
        const endpoint = String(req.body.endpoint || ZEABUR_EMAIL_ENDPOINT).trim();
        const publicBaseUrl = String(req.body.public_base_url || '').trim().replace(/\/+$/, '');
        const adminEmailsRaw = String(req.body.admin_emails || '').trim();
        const commentBlockWordsRaw = String(req.body.comment_block_words ?? '').trim();
        const invalidAdminEmails = findInvalidEmails(adminEmailsRaw);
        const nonQqAdminEmails = findNonQqEmails(adminEmailsRaw);

        if (!from) return res.status(400).json({ error: '请输入有效的发件邮箱' });
        if (!/^https?:\/\//i.test(endpoint)) return res.status(400).json({ error: '邮件 API 地址必须以 http:// 或 https:// 开头' });
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
            db.prepare('DELETE FROM settings WHERE key = ?').run('zeabur_email_api_key');
        } else if (apiKey) {
            setSettingValue('zeabur_email_api_key', apiKey);
        }
        const adminEmails = parseEmailList(adminEmailsRaw);
        setSettingValue('zeabur_email_from', from);
        setSettingValue('zeabur_email_endpoint', endpoint);
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

        const dbApiKey = getSettingValue('zeabur_email_api_key');
        const config = getEmailConfig();
        res.json({
            success: true,
            configured: Boolean(config.apiKey && config.from),
            api_key_configured: Boolean(config.apiKey),
            api_key_masked: maskSecret(config.apiKey),
            api_key_source: dbApiKey ? 'admin' : (ZEABUR_EMAIL_API_KEY ? 'environment' : 'none'),
            from: config.from || '',
            endpoint: config.endpoint || ZEABUR_EMAIL_ENDPOINT,
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

app.get('/api/admin/newapi-redemptions', authenticateAdmin, (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
        const offset = (page - 1) * limit;
        const status = String(req.query.status || '').trim();
        const search = String(req.query.search || '').trim().slice(0, 120);

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

        const total = db.prepare(`SELECT COUNT(*) as count ${baseFrom}`).get(...params).count;
        const summary = db.prepare(
            `SELECT
                COALESCE(SUM(nr.cookies), 0) as cookies_total,
                COALESCE(SUM(CASE WHEN nr.status = 'success' THEN nr.cookies ELSE 0 END), 0) as cookies_success,
                SUM(CASE WHEN nr.status = 'success' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN nr.status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN nr.status = 'failed' THEN 1 ELSE 0 END) as failed_count
             ${baseFrom}`
        ).get(...params);

        const redemptions = db.prepare(
            `SELECT
                nr.id, nr.user_id, nr.newapi_user_id, nr.cookies, nr.heat_used,
                nr.status, nr.error, nr.created_at, nr.completed_at,
                u.username, u.email, u.newapi_redeemed_cookies
             ${baseFrom}
             ORDER BY nr.created_at DESC
             LIMIT ? OFFSET ?`
        ).all(...params, limit, offset).map((row) => {
            let reward = null;
            try {
                reward = getUserNewApiRewardStats(row.user_id);
            } catch (err) {
                reward = null;
            }
            return {
                ...row,
                cookies: floorToTwoDecimals(row.cookies),
                heat_used: floorToTwoDecimals(row.heat_used),
                total_cookies: reward?.total_cookies ?? null,
                redeemed_cookies: reward?.redeemed_cookies ?? floorToTwoDecimals(row.newapi_redeemed_cookies || 0),
                available_cookies: reward?.available_cookies ?? null
            };
        });

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
    'announcement_content',
    'announcement_enabled',
    'announcement_version'
]);

app.get('/api/settings', (req, res) => {
    try {
        const settings = db.prepare('SELECT key, value FROM settings').all();
        const result = {};
        settings.forEach((setting) => {
            if (PUBLIC_SETTINGS_KEYS.has(setting.key)) {
                result[setting.key] = setting.value;
            }
        });
        res.json(result);
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
    'announcement_content', 'announcement_enabled', 'announcement_version'
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
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)');
        const now = new Date().toISOString();
        for (const [key, value] of Object.entries(updates)) {
            if (!ALLOWED_SETTINGS_KEYS.has(key)) continue;
            stmt.run(key, String(value), now);
        }
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_tag_settings',
            targetType: 'settings',
            targetId: 'tag-management',
            ip: getRequestIp(req),
            details: {
                popular_tags_count: parseTagSettingValue(updates.popular_tags).length,
                tag_library_count: parseTagSettingValue(updates.tag_library).length,
                hidden_popular_tags_count: parseTagSettingValue(updates.hidden_popular_tags).length,
                hidden_tag_library_count: parseTagSettingValue(updates.hidden_tag_library).length
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
            return {
                ...log,
                details_json: details,
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

        let where = '';
        const params = [];
        if (search) {
            where = ' WHERE username LIKE ? OR email LIKE ? OR newapi_user_id LIKE ?';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        const total = db.prepare(`SELECT COUNT(*) as count FROM users${where}`).get(...params).count;
        const users = db.prepare(
            `SELECT id, username, email, email_verified, newapi_user_id, newapi_redeemed_cookies, download_credits, is_moderator, is_banned, ban_reason, banned_at, created_at, last_login FROM users${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);

        res.json({ users, total, page, limit, totalPages: Math.ceil(total / limit) });
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

        db.prepare('UPDATE users SET is_moderator = ? WHERE id = ?').run(isModerator ? 1 : 0, userId);
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
        const visitPath = req.body.path || '/';
        const ip = getRequestIp(req);
        const ua = (req.headers['user-agent'] || '').substring(0, 512);
        db.prepare('INSERT INTO page_views (path, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?)').run(visitPath, ip, ua, new Date().toISOString());
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: '记录失败' });
    }
});

// Card view count tracking (skip for card owner to prevent self-inflating heat)
app.post('/api/cards/:id/view', optionalUserAuth, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare('SELECT id, uploader_user_id, review_status FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        if (card.review_status !== 'approved' && !req.admin && !isModeratorUser(req.user) && !(req.user && card.uploader_user_id === req.user.id)) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        // Skip view count increment for admins and card owners.
        const isOwner = req.user && card.uploader_user_id === req.user.id;
        if (req.admin || isModeratorUser(req.user) || isOwner) {
            const current = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
            return res.json({ success: true, views_count: current.views_count, counted: false });
        }

        const viewLimit = recordAccountViewHeat(req, 'card', id);
        if (!viewLimit.counted) {
            const current = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
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
        maybeSendCardHeatMilestoneEmail(id, req);
        res.json({ success: true, views_count: updated.views_count, counted: true });
    } catch (err) {
        console.error('Card view count error:', err);
        res.status(500).json({ error: '记录浏览量失败' });
    }
});

app.get('/api/stats/visits', (req, res) => {
    try {
        const total = db.prepare('SELECT COUNT(*) as count FROM page_views').get().count;
        res.json({ totalVisits: total });
    } catch (err) {
        res.status(500).json({ error: '获取访问量失败' });
    }
});

// ============== Data Export/Import (SQLite DB File) ==============
app.get('/api/admin/export', authenticateAdmin, (req, res) => {
    try {
        // Checkpoint WAL to ensure all data is in the main DB file
        db.pragma('wal_checkpoint(TRUNCATE)');

        const dbPath = path.join(DATA_DIR, 'forum.db');
        const filename = `rph-forum-backup-${new Date().toISOString().slice(0, 10)}.db`;

        res.setHeader('Content-Type', 'application/x-sqlite3');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.sendFile(dbPath);
    } catch (err) {
        console.error('Export error:', err);
        res.status(500).json({ error: '导出失败: ' + err.message });
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

                const dbPath = path.join(DATA_DIR, 'forum.db');
                const backupPath = path.join(DATA_DIR, `forum-pre-import-${Date.now()}.db.bak`);

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
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============== Initialize & Start ==============
initDatabase();

// Cleanup old login attempts every hour
setInterval(cleanupLoginAttempts, 60 * 60 * 1000);
setInterval(cleanupEmailCodes, 60 * 60 * 1000);
setInterval(cleanupOldLogs, 24 * 60 * 60 * 1000);

const server = app.listen(PORT, HOST, () => {
    console.log(`[Server] RP Forum running at http://${HOST}:${PORT}`);
    console.log(`[Server] Admin panel at http://${HOST}:${PORT}/admin`);
});

// Graceful shutdown for Docker
function gracefulShutdown(signal) {
    console.log(`[Server] ${signal} received, shutting down...`);
    server.close(() => {
        db.close();
        console.log('[Server] Database closed, exiting.');
        process.exit(0);
    });
    setTimeout(() => { process.exit(1); }, 5000);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
