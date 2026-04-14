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
const EXPLICIT_JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const DERIVED_JWT_SECRET = process.env.ADMIN_PASSWORD
    ? crypto.createHash('sha256').update(`rp-forum:${process.env.ADMIN_PASSWORD}`).digest('hex')
    : '';
const JWT_SECRET = EXPLICIT_JWT_SECRET || DERIVED_JWT_SECRET || (IS_PRODUCTION ? '' : crypto.randomBytes(32).toString('hex'));

if (!JWT_SECRET) {
    throw new Error('[FATAL] JWT_SECRET must be set in production');
}

if (IS_PRODUCTION && !EXPLICIT_JWT_SECRET) {
    console.warn('[Security] JWT_SECRET is not set. Falling back to a derived secret from ADMIN_PASSWORD. Set JWT_SECRET explicitly for independent secret rotation.');
}

// ============== Brute Force Config ==============
const LOGIN_WINDOW_MINUTES = 1;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 1;

// ============== Captcha Store ==============
const captchaTokens = new Map(); // token -> { createdAt, used }

// ============== Upload Rate Limiting ==============
const MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
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
        { id: user.id, username: user.username, role: 'admin' },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

function generateUserToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: 'user' },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '未授权' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: '权限不足' });
        req.admin = decoded;
        next();
    } catch (err) {
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
        if (decoded.role !== 'user') return res.status(403).json({ error: '权限不足' });
        req.user = decoded;
        next();
    } catch (err) {
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
        if (decoded.role === 'user') req.user = decoded;
        else if (decoded.role === 'admin') { req.admin = decoded; req.user = null; }
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
            req.user = decoded;
        } else if (decoded.role === 'admin') {
            req.admin = decoded;
        } else {
            return res.status(403).json({ error: '权限不足' });
        }
        next();
    } catch (err) {
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

// ============== Auth Routes ==============
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const ip = req.ip;

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
app.post('/api/user/register', async (req, res) => {
    try {
        const { username, password, captchaToken } = req.body;

        // Validate captcha
        if (!captchaToken) {
            return res.status(400).json({ error: '请完成滑块验证' });
        }
        const captchaRecord = captchaTokens.get(captchaToken);
        if (!captchaRecord || !captchaRecord.used) {
            return res.status(400).json({ error: '滑块验证未通过，请重试' });
        }
        captchaTokens.delete(captchaToken);

        if (!username || !password) {
            return res.status(400).json({ error: '请输入用户名和密码' });
        }
        if (username.length < 2 || username.length > 20) {
            return res.status(400).json({ error: '用户名长度需为2-20个字符' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: '密码长度至少6个字符' });
        }

        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existing) {
            return res.status(409).json({ error: '用户名已存在' });
        }

        const hash = await bcrypt.hash(password, 12);
        const now = new Date().toISOString();
        const result = db.prepare(
            'INSERT INTO users (username, password_hash, download_credits, last_login) VALUES (?, ?, 1, ?)'
        ).run(username, hash, now);

        const user = db.prepare('SELECT id, username, download_credits, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
        logOperation({ userType: 'user', userId: user.id, username: user.username, action: 'register', targetType: 'user', targetId: String(user.id), ip: req.ip });
        const token = generateUserToken(user);
        res.json({ token, user });
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

    const ip = req.ip;

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
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
        user: { id: user.id, username: user.username, download_credits: user.download_credits } 
    });
});

app.get('/api/user/me', authenticateUser, (req, res) => {
    const user = db.prepare('SELECT id, username, download_credits, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json({ user });
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

app.get('/api/cards', optionalUserAuth, (req, res) => {
    try {
        const sortMode = req.query.sort || 'latest';
        const heatExpr = '((IFNULL(cc.views_count, 0) * 1.0) + (IFNULL(comment_count, 0) * 1.5) + (IFNULL(cc.downloads_count, 0) * 2.5))';
        let whereClause = '';
        let orderByClause = 'cc.created_at DESC';

        if (sortMode === 'hot') {
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        } else if (sortMode === 'daily') {
            whereClause = "WHERE cc.created_at >= datetime('now', '-1 day')";
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        } else if (sortMode === 'weekly') {
            whereClause = "WHERE cc.created_at >= datetime('now', '-7 days')";
            orderByClause = `${heatExpr} DESC, cc.downloads_count DESC, cc.created_at DESC`;
        }

        const cards = db.prepare(
            `SELECT cc.id, cc.name, cc.description, cc.creator_notes,
                    cc.downloads_count, cc.uploader_user_id, cc.created_at,
                    cc.views_count, cc.is_featured,
                    (SELECT COUNT(*) FROM character_comments cmt WHERE cmt.card_id = cc.id) AS comment_count
             FROM character_cards cc
             ${whereClause}
             ORDER BY ${orderByClause}`
        ).all();
        res.json(cards);
    } catch (err) {
        console.error('Fetch cards error:', err);
        res.status(500).json({ error: '获取卡片失败' });
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
        try { card.data = card.data ? JSON.parse(card.data) : null; } catch (e) { card.data = null; }
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

        // File size check: estimate original size from base64 avatar_url
        if (avatar_url && typeof avatar_url === 'string' && avatar_url.startsWith('data:')) {
            const base64Part = avatar_url.split(',')[1] || '';
            const estimatedBytes = Math.ceil(base64Part.length * 3 / 4);
            if (estimatedBytes > MAX_UPLOAD_SIZE_BYTES) {
                return res.status(400).json({ error: `文件大小超过 10MB 限制 (${(estimatedBytes / 1024 / 1024).toFixed(1)}MB)` });
            }
        }

        // Upload rate limiting (admin exempt)
        if (!req.admin) {
            const rateKey = req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
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

        try {
            db.prepare(
                'INSERT INTO character_cards (id, name, description, avatar_url, data, creator_notes, uploader_user_id, data_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, name, description || '', safeAvatarUrl, dataStr, creator_notes || '', uploaderUserId, dataHash, now);
        } catch (insertErr) {
            if (insertErr.message && insertErr.message.includes('UNIQUE constraint failed')) {
                const conflict = db.prepare('SELECT name FROM character_cards WHERE data_hash = ?').get(dataHash);
                return res.status(409).json({ error: `已存在完全相同的角色卡「${conflict?.name || '未知'}」，禁止重复上传` });
            }
            throw insertErr;
        }

        const card = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(id);
        try { card.data = card.data ? JSON.parse(card.data) : null; } catch (e) { card.data = null; }
        logOperation({ userType: req.user ? 'user' : 'admin', userId: uploaderUserId || req.admin?.id, username: req.user?.username || req.admin?.username, action: 'upload', targetType: 'card', targetId: id, ip: req.ip, details: { name } });

        let newCredits = null;
        if (req.user) {
            db.prepare('UPDATE users SET download_credits = download_credits + 3 WHERE id = ?').run(req.user.id);
            newCredits = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(req.user.id)?.download_credits;
        }
        res.json([card, ...(newCredits !== null ? [{ new_credits: newCredits }] : [])]);
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
        let userId = null;
        let username = '';
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'admin') {
                isAdmin = true;
                userId = decoded.id;
                username = decoded.username || '';
            } else {
                userId = decoded.id;
                username = decoded.username || '';
            }
        } catch {
            return res.status(401).json({ error: '认证失败' });
        }

        const { id } = req.params;
        const card = db.prepare('SELECT name, uploader_user_id FROM character_cards WHERE id = ?').get(id);
        if (!card) {
            return res.status(404).json({ error: '卡片不存在' });
        }

        // Only admin or card owner can delete
        const ownerUserId = card.uploader_user_id == null ? null : Number(card.uploader_user_id);
        if (!isAdmin && (!userId || ownerUserId !== Number(userId))) {
            return res.status(403).json({ error: '无权删除此卡片' });
        }

        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(id);
            // Reclaim upload credits (3) from uploader, minimum 0
            if (card.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
        });
        deleteAndReclaim();
        thumbnailCache.delete(id);

        logOperation({ userType: isAdmin ? 'admin' : 'user', userId, username, action: 'delete', targetType: 'card', targetId: id, ip: req.ip, details: { name: card?.name } });
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
            userType = 'admin'; userId = decoded.id; username = decoded.username;
        } else if (decoded.role === 'user' && card.uploader_user_id === decoded.id) {
            userType = 'user'; userId = decoded.id; username = decoded.username;
        } else {
            return res.status(403).json({ error: '无权编辑此卡片' });
        }

        const { name, description, avatar_url, data, creator_notes, created_at } = req.body;
        const fields = [];
        const values = [];
        if (name !== undefined)          { fields.push('name = ?');          values.push(name); }
        if (description !== undefined)   { fields.push('description = ?');   values.push(description); }
        if (avatar_url !== undefined && avatar_url.startsWith('data:')) { fields.push('avatar_url = ?'); values.push(avatar_url); }
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

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        values.push(req.params.id);
        db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        thumbnailCache.delete(req.params.id);

        logOperation({ userType, userId, username, action: 'edit', targetType: 'card', targetId: req.params.id, ip: req.ip, details: { name: card.name } });

        const updated = db.prepare('SELECT * FROM character_cards WHERE id = ?').get(req.params.id);
        try { updated.data = updated.data ? JSON.parse(updated.data) : null; } catch (e) { updated.data = null; }
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
            targetType: 'card', targetId: id, ip: req.ip,
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
        const card = db.prepare('SELECT id, name, views_count, downloads_count FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        const { views_count, downloads_count } = req.body;
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

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });

        values.push(id);
        db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: 'admin_adjust_heat', targetType: 'card', targetId: id, ip: req.ip,
            details: { name: card.name, views_count, downloads_count }
        });

        const updated = db.prepare('SELECT views_count, downloads_count FROM character_cards WHERE id = ?').get(id);
        res.json({ success: true, views_count: updated.views_count, downloads_count: updated.downloads_count });
    } catch (err) {
        console.error('Admin adjust heat error:', err);
        res.status(500).json({ error: '调整热度失败' });
    }
});

app.post('/api/cards/:id/download', requireUserOrAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare('SELECT id, name, uploader_user_id FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        let newCredits = null;
        const recordDownload = db.transaction(() => {
            const isOwner = req.user && card.uploader_user_id === req.user.id;
            if (!req.admin) {
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

            // Author/admin downloads don't inflate download count
            if (!isOwner && !req.admin) {
                db.prepare('UPDATE character_cards SET downloads_count = downloads_count + 1 WHERE id = ?').run(id);
            }
        });

        recordDownload();
        logOperation({ userType: req.user ? 'user' : 'admin', userId: req.user?.id || req.admin?.id, username: req.user?.username || req.admin?.username, action: 'download', targetType: 'card', targetId: id, ip: req.ip });

        const fileName = sanitizeDownloadFilename(card.name);
        const downloadToken = createCardDownloadToken(id, fileName);
        res.json({
            success: true,
            new_credits: newCredits,
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

        const card = db.prepare('SELECT id FROM character_cards WHERE id = ?').get(cardId);
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

// ============== Comment Routes ==============
app.get('/api/cards/:cardId/comments', optionalUserAuth, (req, res) => {
    try {
        const cardId = req.params.cardId;
        const userId = req.user ? req.user.id : null;

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
        const todayCommentCount = db.prepare(
            "SELECT COUNT(*) as count FROM character_comments WHERE user_id = ? AND created_at >= ? AND created_at < date(?, '+1 day')"
        ).get(userId, todayStr, todayStr).count;
        const canEarnCredits = todayCommentCount < 2;

        // Insert comment and optionally add credits
        const insertComment = db.transaction(() => {
            db.prepare(
                'INSERT INTO character_comments (id, card_id, user_id, nickname, content, reply_to_id, reply_to_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.cardId, userId, user.username, content.trim(), reply_to_id || null, replyToName, now);

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
        res.json({ comment, new_credits: updatedUser.download_credits, credits_earned: canEarnCredits });
    } catch (err) {
        console.error('Create comment error:', err);
        res.status(500).json({ error: '发布评论失败' });
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

app.delete('/api/comments/:id', authenticateAdmin, (req, res) => {
    try {
        const result = db.prepare('DELETE FROM character_comments WHERE id = ?').run(req.params.id);
        if (result.changes === 0) {
            return res.status(404).json({ error: '评论不存在' });
        }
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
            loginAttempts, topCards, dailyActivity, dailyComments, dailyVisits
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

        let query = 'SELECT id, name, description, creator_notes, downloads_count, created_at FROM character_cards';
        let countQuery = 'SELECT COUNT(*) as count FROM character_cards';
        const params = [];
        const countParams = [];

        if (search) {
            const where = ' WHERE name LIKE ? OR description LIKE ? OR creator_notes LIKE ?';
            const searchParam = `%${search}%`;
            query += where;
            countQuery += where;
            params.push(searchParam, searchParam, searchParam);
            countParams.push(searchParam, searchParam, searchParam);
        }

        const total = db.prepare(countQuery).get(...countParams).count;
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const cards = db.prepare(query).all(...params);
        res.json({ cards, total, page, limit, totalPages: Math.ceil(total / limit) });
    } catch (err) {
        console.error('Admin cards error:', err);
        res.status(500).json({ error: '获取卡片列表失败' });
    }
});

app.delete('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    try {
        const card = db.prepare('SELECT name, uploader_user_id FROM character_cards WHERE id = ?').get(req.params.id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });
        const deleteAndReclaim = db.transaction(() => {
            db.prepare('DELETE FROM character_cards WHERE id = ?').run(req.params.id);
            if (card.uploader_user_id) {
                db.prepare('UPDATE users SET download_credits = MAX(0, download_credits - 3) WHERE id = ?').run(card.uploader_user_id);
            }
        });
        deleteAndReclaim();
        thumbnailCache.delete(req.params.id);
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'admin_delete_card', targetType: 'card', targetId: req.params.id, ip: req.ip, details: { name: card?.name } });
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
        const comment = db.prepare('SELECT content FROM character_comments WHERE id = ?').get(req.params.id);
        const result = db.prepare('DELETE FROM character_comments WHERE id = ?').run(req.params.id);
        if (result.changes === 0) return res.status(404).json({ error: '评论不存在' });
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'admin_delete_comment', targetType: 'comment', targetId: req.params.id, ip: req.ip, details: { content: comment?.content?.substring(0, 50) } });
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

const PUBLIC_SETTINGS_KEYS = new Set([
    'site_name',
    'site_description',
    'allow_anonymous_upload',
    'allow_anonymous_comment',
    'popular_tags',
    'tag_library',
    'hidden_popular_tags',
    'hidden_tag_library'
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
    'hidden_popular_tags', 'hidden_tag_library'
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
            ip: req.ip,
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

app.put('/api/admin/password', authenticateAdmin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: '请输入当前密码和新密码' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: '新密码长度至少6位' });
        }
        const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.admin.id);
        if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) {
            return res.status(401).json({ error: '当前密码错误' });
        }
        const hash = await bcrypt.hash(newPassword, 12);
        db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(hash, user.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: '修改密码失败' });
    }
});

app.get('/api/admin/logs', authenticateAdmin, (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;
        const action = req.query.action || '';

        let where = '';
        const params = [];
        if (action) { where = ' WHERE action = ?'; params.push(action); }
        
        const total = db.prepare(`SELECT COUNT(*) as count FROM operation_logs${where}`).get(...params).count;
        const logs = db.prepare(
            `SELECT * FROM operation_logs${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);

        res.json({ logs, total, page, limit, totalPages: Math.ceil(total / limit) });
    } catch (err) {
        res.status(500).json({ error: '获取日志失败' });
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
            where = ' WHERE username LIKE ?';
            params.push(`%${search}%`);
        }
        const total = db.prepare(`SELECT COUNT(*) as count FROM users${where}`).get(...params).count;
        const users = db.prepare(
            `SELECT id, username, download_credits, created_at, last_login FROM users${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
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

        const user = db.prepare('SELECT id, username, download_credits, created_at, last_login FROM users WHERE id = ?').get(userId);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_update_user_credits',
            targetType: 'user',
            targetId: String(userId),
            ip: req.ip,
            details: { download_credits: credits, username: user?.username }
        });

        res.json({ success: true, user });
    } catch (err) {
        console.error('Admin update credits error:', err);
        res.status(500).json({ error: '更新下载次数失败' });
    }
});

app.post('/api/admin/users/:id/reset-password', authenticateAdmin, async (req, res) => {
    try {
        const userId = Number(req.params.id);
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ error: '无效的用户 ID' });
        }

        const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId);
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }

        const providedPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword.trim() : '';
        const temporaryPassword = providedPassword || crypto.randomBytes(6).toString('base64url');
        if (temporaryPassword.length < 6) {
            return res.status(400).json({ error: '新密码长度至少 6 位' });
        }

        const hash = await bcrypt.hash(temporaryPassword, 12);
        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
        logOperation({
            userType: 'admin',
            userId: req.admin.id,
            username: req.admin.username,
            action: 'admin_reset_user_password',
            targetType: 'user',
            targetId: String(userId),
            ip: req.ip,
            details: { username: user.username }
        });

        res.json({
            success: true,
            username: user.username,
            temporary_password: temporaryPassword,
            message: '原密码无法从哈希中恢复，已重置为新的临时密码。'
        });
    } catch (err) {
        console.error('Admin reset password error:', err);
        res.status(500).json({ error: '重置密码失败' });
    }
});

// ============== Visit Tracking ==============
app.post('/api/track/visit', (req, res) => {
    try {
        const visitPath = req.body.path || '/';
        const ip = req.ip;
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
        const card = db.prepare('SELECT id, uploader_user_id FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        // Skip view count increment for card owner
        const isOwner = req.user && card.uploader_user_id === req.user.id;
        if (isOwner) {
            const current = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
            return res.json({ success: true, views_count: current.views_count });
        }

        db.prepare('UPDATE character_cards SET views_count = views_count + 1 WHERE id = ?').run(id);
        const updated = db.prepare('SELECT views_count FROM character_cards WHERE id = ?').get(id);
        res.json({ success: true, views_count: updated.views_count });
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

// ============== Data Export/Import ==============
app.get('/api/admin/export', authenticateAdmin, (req, res) => {
    try {
        const data = {
            export_version: 2,
            export_date: new Date().toISOString(),
            users: db.prepare('SELECT * FROM users').all(),
            character_cards: db.prepare('SELECT * FROM character_cards').all(),
            character_comments: db.prepare('SELECT * FROM character_comments').all(),
            comment_likes: db.prepare('SELECT * FROM comment_likes').all(),
            card_likes: db.prepare('SELECT * FROM card_likes').all(),
            settings: db.prepare('SELECT * FROM settings').all()
        };
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename=rph-forum-backup-${new Date().toISOString().slice(0,10)}.json`);
        res.json(data);
    } catch (err) {
        console.error('Export error:', err);
        res.status(500).json({ error: '导出失败: ' + err.message });
    }
});

app.post('/api/admin/import', authenticateAdmin, (req, res) => {
    try {
        const data = req.body;
        if (!data || !data.export_version) {
            return res.status(400).json({ error: '无效的备份文件格式' });
        }

        const importTransaction = db.transaction(() => {
            // Clear existing data in order (respect foreign keys)
            db.exec('DELETE FROM comment_likes');
            db.exec('DELETE FROM card_likes');
            db.exec('DELETE FROM character_comments');
            db.exec('DELETE FROM character_cards');
            db.exec('DELETE FROM users');

            // Import users (preserve IDs and password hashes)
            if (data.users && data.users.length > 0) {
                const insertUser = db.prepare(
                    `INSERT INTO users (id, username, password_hash, download_credits, created_at, last_login)
                     VALUES (?, ?, ?, ?, ?, ?)`
                );
                for (const u of data.users) {
                    insertUser.run(u.id, u.username, u.password_hash, u.download_credits ?? 1, u.created_at, u.last_login);
                }
            }

            // Import character cards
            if (data.character_cards && data.character_cards.length > 0) {
                const insertCard = db.prepare(
                    `INSERT INTO character_cards (id, name, description, avatar_url, data, creator_notes, downloads_count, uploader_user_id, created_at, data_hash, likes_count, views_count, is_featured)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                );
                for (const c of data.character_cards) {
                    insertCard.run(c.id, c.name, c.description, c.avatar_url, c.data, c.creator_notes,
                        c.downloads_count || 0, c.uploader_user_id, c.created_at, c.data_hash || null, c.likes_count || 0, c.views_count || 0, c.is_featured || 0);
                }
            }

            // Import comments
            if (data.character_comments && data.character_comments.length > 0) {
                const insertComment = db.prepare(
                    `INSERT INTO character_comments (id, card_id, user_id, nickname, content, likes_count, created_at, reply_to_id, reply_to_name)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
                );
                for (const cm of data.character_comments) {
                    insertComment.run(cm.id, cm.card_id, cm.user_id, cm.nickname || '匿名用户', cm.content,
                        cm.likes_count || 0, cm.created_at, cm.reply_to_id || null, cm.reply_to_name || null);
                }
            }

            // Import comment likes
            if (data.comment_likes && data.comment_likes.length > 0) {
                const insertCL = db.prepare(
                    `INSERT INTO comment_likes (id, comment_id, user_id, created_at) VALUES (?, ?, ?, ?)`
                );
                for (const cl of data.comment_likes) {
                    insertCL.run(cl.id, cl.comment_id, cl.user_id, cl.created_at);
                }
            }

            // Import card likes
            if (data.card_likes && data.card_likes.length > 0) {
                const insertCardLike = db.prepare(
                    `INSERT INTO card_likes (id, card_id, user_id, created_at) VALUES (?, ?, ?, ?)`
                );
                for (const cl of data.card_likes) {
                    insertCardLike.run(cl.id, cl.card_id, cl.user_id, cl.created_at);
                }
            }

            // Import settings (upsert)
            if (data.settings && data.settings.length > 0) {
                const upsertSetting = db.prepare(
                    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
                );
                for (const s of data.settings) {
                    upsertSetting.run(s.key, s.value, s.updated_at || new Date().toISOString());
                }
            }
        });

        importTransaction();

        const stats = {
            users: data.users?.length || 0,
            cards: data.character_cards?.length || 0,
            comments: data.character_comments?.length || 0,
            settings: data.settings?.length || 0
        };

        logOperation({
            userType: 'admin', userId: req.admin.id, username: req.admin.username,
            action: 'import', ip: req.ip,
            details: { stats }
        });

        res.json({ success: true, message: '数据导入成功', stats });
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