const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const { db, initDatabase, cleanupLoginAttempts, cleanupOldLogs } = require('./database');

const app = express();
const PORT = parseInt(process.env.PORT) || 9191;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MINUTES = 15;
const LOCKOUT_MINUTES = 30;

// ============== Middleware ==============
app.use(helmet({
    contentSecurityPolicy: false, // Allow CDN scripts in frontend
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: '请求过于频繁，请稍后再试' }
});
app.use('/api/', globalLimiter);

// Strict login rate limiter (brute force protection)
const loginLimiter = rateLimit({
    windowMs: LOGIN_WINDOW_MINUTES * 60 * 1000,
    max: MAX_LOGIN_ATTEMPTS,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: `登录尝试过多，请 ${LOGIN_WINDOW_MINUTES} 分钟后再试` },
    keyGenerator: (req) => {
        return req.ip + ':' + (req.body.username || 'unknown');
    }
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
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const ip = req.ip;

    const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    // Success
    db.prepare('UPDATE admin_users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
    logOperation({ userType: 'admin', userId: user.id, username: user.username, action: 'admin_login', targetType: 'user', targetId: String(user.id), ip, details: { role: 'admin' } });

    const token = generateAdminToken(user);
    res.json({ token, user: { id: user.id, username: user.username } });
});

app.get('/api/auth/me', authenticateAdmin, (req, res) => {
    res.json({ user: req.admin });
});

// ============== User Registration & Login ==============
const userRegisterLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: { error: '注册过于频繁，请稍后再试' }
});

app.post('/api/user/register', userRegisterLimiter, (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: '请输入用户名和密码' });
        }
        if (username.length < 2 || username.length > 20) {
            return res.status(400).json({ error: '用户名长度需为2-20个字符' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: '密码长度至少6位' });
        }
        // Check username allowed chars (letters, numbers, Chinese, underscore)
        if (!/^[\w\u4e00-\u9fa5]+$/.test(username)) {
            return res.status(400).json({ error: '用户名只能包含字母、数字、下划线或中文' });
        }

        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existing) {
            return res.status(409).json({ error: '用户名已存在' });
        }

        const hash = bcrypt.hashSync(password, 12);
        const result = db.prepare(
            'INSERT INTO users (username, password_hash, download_credits) VALUES (?, ?, 1)'
        ).run(username, hash);

        const user = db.prepare('SELECT id, username, download_credits, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
        logOperation({ userType: 'user', userId: user.id, username: user.username, action: 'register', targetType: 'user', targetId: String(user.id), ip: req.ip });
        const token = generateUserToken(user);
        res.json({ token, user });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: '注册失败' });
    }
});

app.post('/api/user/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '请输入用户名和密码' });
    }

    const ip = req.ip;

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
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
        const sortField = req.query.sort === 'hot' ? 'likes_count' : 'created_at';
        const userId = req.user?.id ?? req.admin?.id ?? null;
        const cards = db.prepare(
            `SELECT cc.id, cc.name, cc.description, cc.avatar_url, cc.data, cc.creator_notes,
                    cc.downloads_count, cc.uploader_user_id, cc.created_at, cc.likes_count,
                    CASE WHEN cl.id IS NOT NULL THEN 1 ELSE 0 END AS user_liked
             FROM character_cards cc
             LEFT JOIN card_likes cl ON cl.card_id = cc.id AND cl.user_id = ?
             ORDER BY cc.${sortField} DESC`
        ).all(userId);
        // Parse data field back to JSON for client
        const result = cards.map(c => {
            try {
                c.data = c.data ? JSON.parse(c.data) : null;
            } catch (e) {
                c.data = null;
            }
            return c;
        });
        res.json(result);
    } catch (err) {
        console.error('Fetch cards error:', err);
        res.status(500).json({ error: '获取卡片失败' });
    }
});

app.post('/api/cards', requireUserOrAdmin, (req, res) => {
    try {
        const { name, description, avatar_url, data, creator_notes } = req.body;
        if (!name) {
            return res.status(400).json({ error: '卡片名称不能为空' });
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

        try {
            db.prepare(
                'INSERT INTO character_cards (id, name, description, avatar_url, data, creator_notes, uploader_user_id, data_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(id, name, description || '', avatar_url || '', dataStr, creator_notes || '', uploaderUserId, dataHash, now);
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

app.delete('/api/cards/:id', authenticateAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare('SELECT name FROM character_cards WHERE id = ?').get(id);
        const result = db.prepare('DELETE FROM character_cards WHERE id = ?').run(id);
        if (result.changes === 0) {
            return res.status(404).json({ error: '卡片不存在' });
        }
        logOperation({ userType: 'admin', userId: req.admin.id, username: req.admin.username, action: 'delete', targetType: 'card', targetId: id, ip: req.ip, details: { name: card?.name } });
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
        if (name !== undefined || description !== undefined) {
            return res.status(400).json({ error: '名称和描述不允许修改' });
        }
        const fields = [];
        const values = [];
        if (avatar_url !== undefined)    { fields.push('avatar_url = ?');    values.push(avatar_url); }
        if (data !== undefined)          { fields.push('data = ?');          values.push(typeof data === 'string' ? data : JSON.stringify(data)); }
        if (creator_notes !== undefined) { fields.push('creator_notes = ?'); values.push(creator_notes); }
        if (created_at !== undefined && decoded.role === 'admin') {
            if (isNaN(Date.parse(created_at))) return res.status(400).json({ error: '无效的时间格式' });
            fields.push('created_at = ?'); values.push(created_at);
        }

        if (fields.length === 0) return res.status(400).json({ error: '无更新内容' });
        values.push(req.params.id);
        db.prepare(`UPDATE character_cards SET ${fields.join(', ')} WHERE id = ?`).run(...values);

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

app.post('/api/cards/:id/download', requireUserOrAdmin, (req, res) => {
    try {
        const { id } = req.params;
        const card = db.prepare('SELECT id, uploader_user_id FROM character_cards WHERE id = ?').get(id);
        if (!card) return res.status(404).json({ error: '卡片不存在' });

        // Admin has no credit cost
        if (!req.admin) {
            const isOwner = req.user && card.uploader_user_id === req.user.id;
            if (!isOwner) {
                const result = db.prepare('UPDATE users SET download_credits = download_credits - 1 WHERE id = ? AND download_credits > 0').run(req.user.id);
                if (result.changes === 0) {
                    return res.status(403).json({ error: '下载次数不足' });
                }
            }
        }

        db.prepare('UPDATE character_cards SET downloads_count = downloads_count + 1 WHERE id = ?').run(id);
        logOperation({ userType: req.user ? 'user' : 'admin', userId: req.user?.id || req.admin?.id, username: req.user?.username || req.admin?.username, action: 'download', targetType: 'card', targetId: id, ip: req.ip });
        
        const newCredits = req.user 
            ? db.prepare('SELECT download_credits FROM users WHERE id = ?').get(req.user.id)?.download_credits 
            : null;
        
        res.json({ success: true, new_credits: newCredits });
    } catch (err) {
        console.error('Download count error:', err);
        res.status(500).json({ error: '更新下载次数失败' });
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
            `SELECT c.*, u.username as author_name 
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
        const { content } = req.body;
        if (!content || !content.trim()) {
            return res.status(400).json({ error: '评论内容不能为空' });
        }
        if (content.trim().length < 5) {
            return res.status(400).json({ error: '评论内容不能少于5个字' });
        }
        if (content.length > 5000) {
            return res.status(400).json({ error: '评论内容过长（最多5000字）' });
        }
        
        const userId = req.user.id;
        const user = db.prepare('SELECT username, download_credits FROM users WHERE id = ?').get(userId);
        if (!user) return res.status(401).json({ error: '用户不存在' });

        const id = generateId();
        const now = new Date().toISOString();

        // Insert comment and add 2 credits in a transaction
        const insertComment = db.transaction(() => {
            db.prepare(
                'INSERT INTO character_comments (id, card_id, user_id, nickname, content, created_at) VALUES (?, ?, ?, ?, ?, ?)'
            ).run(id, req.params.cardId, userId, user.username, content.trim(), now);

            db.prepare('UPDATE users SET download_credits = download_credits + 2 WHERE id = ?').run(userId);
        });
        insertComment();

        const comment = db.prepare('SELECT * FROM character_comments WHERE id = ?').get(id);
        comment.author_name = user.username;
        comment.user_liked = false;
        comment.is_hot = false;

        const updatedUser = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId);
        res.json({ comment, new_credits: updatedUser.download_credits });
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
            // Like: add like and give 1 credit
            const likeTransaction = db.transaction(() => {
                db.prepare('INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)').run(commentId, userId);
                db.prepare('UPDATE character_comments SET likes_count = likes_count + 1 WHERE id = ?').run(commentId);
                db.prepare('UPDATE users SET download_credits = download_credits + 1 WHERE id = ?').run(userId);
            });
            likeTransaction();

            const updated = db.prepare('SELECT likes_count FROM character_comments WHERE id = ?').get(commentId);
            const updatedUser = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId);
            return res.json({ liked: true, likes_count: updated.likes_count, new_credits: updatedUser.download_credits });
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
        const card = db.prepare('SELECT name FROM character_cards WHERE id = ?').get(req.params.id);
        const result = db.prepare('DELETE FROM character_cards WHERE id = ?').run(req.params.id);
        if (result.changes === 0) return res.status(404).json({ error: '卡片不存在' });
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

const ALLOWED_SETTINGS_KEYS = new Set([
    'site_name', 'site_description', 'allow_anonymous_upload',
    'allow_anonymous_comment', 'max_upload_size_mb'
]);

app.put('/api/admin/settings', authenticateAdmin, (req, res) => {
    try {
        const updates = req.body;
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)');
        const now = new Date().toISOString();
        for (const [key, value] of Object.entries(updates)) {
            if (!ALLOWED_SETTINGS_KEYS.has(key)) continue;
            stmt.run(key, String(value), now);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: '更新设置失败' });
    }
});

app.put('/api/admin/password', authenticateAdmin, (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: '请输入当前密码和新密码' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: '新密码长度至少6位' });
        }
        const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(req.admin.id);
        if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
            return res.status(401).json({ error: '当前密码错误' });
        }
        const hash = bcrypt.hashSync(newPassword, 12);
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
            `SELECT id, username, password_hash, download_credits, created_at, last_login FROM users${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
        ).all(...params, limit, offset);

        res.json({ users, total, page, limit, totalPages: Math.ceil(total / limit) });
    } catch (err) {
        console.error('Admin users error:', err);
        res.status(500).json({ error: '获取用户列表失败' });
    }
});

// ============== Visit Tracking ==============
const visitTrackLimiter = rateLimit({ windowMs: 60000, max: 30, message: { error: 'Too many requests' } });

app.post('/api/track/visit', visitTrackLimiter, (req, res) => {
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

app.get('/api/stats/visits', (req, res) => {
    try {
        const total = db.prepare('SELECT COUNT(*) as count FROM page_views').get().count;
        res.json({ totalVisits: total });
    } catch (err) {
        res.status(500).json({ error: '获取访问量失败' });
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

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Server] RP Forum running at http://0.0.0.0:${PORT}`);
    console.log(`[Server] Admin panel at http://0.0.0.0:${PORT}/admin`);
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
