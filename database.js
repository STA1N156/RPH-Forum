const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'forum.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 30000');
db.pragma('foreign_keys = ON');

function initDatabase() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token_version INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            download_credits INTEGER DEFAULT 1,
            token_version INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            banned_at DATETIME,
            banned_by_admin_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            FOREIGN KEY (banned_by_admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS character_cards (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            avatar_url TEXT,
            data TEXT,
            creator_notes TEXT,
            downloads_count INTEGER DEFAULT 0,
            uploader_user_id INTEGER,
            review_status TEXT DEFAULT 'approved',
            reviewed_by_admin_id INTEGER,
            reviewed_at DATETIME,
            rejection_reason TEXT,
            uploader_ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS character_comments (
            id TEXT PRIMARY KEY,
            card_id TEXT NOT NULL,
            user_id INTEGER,
            nickname TEXT DEFAULT '匿名用户',
            content TEXT NOT NULL,
            likes_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_id) REFERENCES character_cards(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS comment_likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(comment_id, user_id),
            FOREIGN KEY (comment_id) REFERENCES character_comments(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS card_likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(card_id, user_id),
            FOREIGN KEY (card_id) REFERENCES character_cards(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL DEFAULT 'anonymous',
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            ip_address TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_pattern TEXT UNIQUE NOT NULL,
            reason TEXT,
            created_by_admin_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (created_by_admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cards_created_at ON character_cards(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_comments_card_id ON character_comments(card_id);
        CREATE INDEX IF NOT EXISTS idx_comment_likes_comment ON comment_likes(comment_id);
        CREATE INDEX IF NOT EXISTS idx_comment_likes_user ON comment_likes(user_id);
        CREATE INDEX IF NOT EXISTS idx_card_likes_card ON card_likes(card_id);
        CREATE INDEX IF NOT EXISTS idx_card_likes_user ON card_likes(user_id);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempt_time);
        CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_operation_logs_action ON operation_logs(action);
        CREATE INDEX IF NOT EXISTS idx_page_views_created_at ON page_views(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ip_bans_active ON ip_bans(is_active);
    `);

    // Migration: add columns if they don't exist (for existing databases)
    try { db.exec('ALTER TABLE admin_users ADD COLUMN token_version INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN ban_reason TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN banned_at DATETIME'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN banned_by_admin_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_users_is_banned ON users(is_banned)'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN user_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN likes_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN uploader_user_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN data_hash TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN likes_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_cards_likes_count ON character_cards(likes_count DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_cards_data_hash_unique ON character_cards (data_hash) WHERE data_hash IS NOT NULL'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN reply_to_id TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN reply_to_name TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN views_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN is_featured INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec("ALTER TABLE character_cards ADD COLUMN review_status TEXT DEFAULT 'approved'"); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN reviewed_by_admin_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN reviewed_at DATETIME'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN rejection_reason TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN uploader_ip_address TEXT'); } catch (e) { /* column exists */ }
    try { db.exec("UPDATE character_cards SET review_status = 'approved' WHERE review_status IS NULL OR review_status = ''"); } catch (e) { /* migration best effort */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_cards_review_status ON character_cards(review_status, created_at DESC)'); } catch (e) { /* index exists */ }

    // Seed admin user from environment variables
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    if (process.env.NODE_ENV === 'production' && (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD === '123456')) {
        throw new Error('[FATAL] ADMIN_PASSWORD must be explicitly set in production and must not use the default value');
    }
    const adminPassword = process.env.ADMIN_PASSWORD || '123456';

    if (adminPassword === '123456') {
        console.warn('[Security] Using the default admin password. Set ADMIN_PASSWORD before deploying to production.');
    }

    const existing = db.prepare('SELECT id FROM admin_users WHERE username = ?').get(adminUsername);
    if (!existing) {
        const hash = bcrypt.hashSync(adminPassword, 12);
        db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)').run(adminUsername, hash);
        console.log(`[DB] Admin user "${adminUsername}" created.`);
    }

    // Seed default settings
    const defaultSettings = {
        site_name: '角色卡广场',
        site_description: '发现和分享角色卡',
        allow_anonymous_upload: 'true',
        allow_anonymous_comment: 'true',
        max_upload_size_mb: '50',
        popular_tags: '',
        tag_library: '',
        hidden_popular_tags: '',
        hidden_tag_library: ''
    };
    const upsertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
    for (const [key, value] of Object.entries(defaultSettings)) {
        upsertSetting.run(key, value);
    }

    console.log(`[DB] Database initialized at ${DB_PATH}`);
}

// Cleanup old login attempts periodically (keep 24h)
function cleanupLoginAttempts() {
    db.prepare("DELETE FROM login_attempts WHERE attempt_time < datetime('now', '-24 hours')").run();
}

// Cleanup old logs periodically
function cleanupOldLogs() {
    db.prepare("DELETE FROM operation_logs WHERE created_at < datetime('now', '-90 days')").run();
    db.prepare("DELETE FROM page_views WHERE created_at < datetime('now', '-30 days')").run();
}

module.exports = { db, initDatabase, cleanupLoginAttempts, cleanupOldLogs };
