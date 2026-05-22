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
            email TEXT,
            email_verified INTEGER DEFAULT 0,
            newapi_user_id TEXT,
            newapi_redeemed_cookies REAL DEFAULT 0,
            newapi_penalty_cookies REAL DEFAULT 0,
            comment_email_notifications INTEGER DEFAULT 1,
            password_hash TEXT NOT NULL,
            download_credits INTEGER DEFAULT 1,
            token_version INTEGER DEFAULT 0,
            is_moderator INTEGER DEFAULT 0,
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
            detail_preview TEXT,
            has_ui_templates INTEGER,
            ui_template_count INTEGER,
            ui_template_variable_count INTEGER,
            creator_notes TEXT,
            downloads_count INTEGER DEFAULT 0,
            comment_count_override INTEGER,
            uploader_user_id INTEGER,
            review_status TEXT DEFAULT 'pending',
            reviewed_by_admin_id INTEGER,
            reviewed_at DATETIME,
            rejection_reason TEXT,
            uploader_ip_address TEXT,
            heat_email_milestone INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS card_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(card_id, user_id),
            FOREIGN KEY (card_id) REFERENCES character_cards(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

        CREATE TABLE IF NOT EXISTS ui_template_comments (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            user_id INTEGER,
            nickname TEXT DEFAULT '匿名用户',
            content TEXT NOT NULL,
            likes_count INTEGER DEFAULT 0,
            reply_to_id TEXT,
            reply_to_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (template_id) REFERENCES ui_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS ui_template_comment_likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(comment_id, user_id),
            FOREIGN KEY (comment_id) REFERENCES ui_template_comments(id) ON DELETE CASCADE,
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

        CREATE TABLE IF NOT EXISTS ui_templates (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            file_name TEXT NOT NULL,
            file_ext TEXT,
            mime_type TEXT,
            content TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            downloads_count INTEGER DEFAULT 0,
            views_count INTEGER DEFAULT 0,
            comment_count_override INTEGER,
            is_featured INTEGER DEFAULT 0,
            uploader_user_id INTEGER,
            review_status TEXT DEFAULT 'pending',
            reviewed_by_admin_id INTEGER,
            reviewed_at DATETIME,
            rejection_reason TEXT,
            uploader_ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploader_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (reviewed_by_admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
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

        CREATE TABLE IF NOT EXISTS account_view_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_type TEXT NOT NULL,
            content_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            view_count INTEGER DEFAULT 0,
            window_started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_view_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(content_type, content_id, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

        CREATE TABLE IF NOT EXISTS email_verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL,
            user_id INTEGER,
            code_hash TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS newapi_redemptions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            newapi_user_id TEXT NOT NULL,
            cookies REAL NOT NULL,
            quota INTEGER NOT NULL,
            heat_used REAL NOT NULL,
            quota_before INTEGER,
            quota_after INTEGER,
            status TEXT DEFAULT 'pending',
            error TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_cards_created_at ON character_cards(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_cards_uploader_review ON character_cards(uploader_user_id, review_status);
        CREATE INDEX IF NOT EXISTS idx_comments_card_id ON character_comments(card_id);
        CREATE INDEX IF NOT EXISTS idx_comments_card_user ON character_comments(card_id, user_id);
        CREATE INDEX IF NOT EXISTS idx_comment_likes_comment ON comment_likes(comment_id);
        CREATE INDEX IF NOT EXISTS idx_comment_likes_user ON comment_likes(user_id);
        CREATE INDEX IF NOT EXISTS idx_ui_template_comments_template_id ON ui_template_comments(template_id);
        CREATE INDEX IF NOT EXISTS idx_ui_template_comments_template_user ON ui_template_comments(template_id, user_id);
        CREATE INDEX IF NOT EXISTS idx_ui_template_comment_likes_comment ON ui_template_comment_likes(comment_id);
        CREATE INDEX IF NOT EXISTS idx_ui_template_comment_likes_user ON ui_template_comment_likes(user_id);
        CREATE INDEX IF NOT EXISTS idx_card_likes_card ON card_likes(card_id);
        CREATE INDEX IF NOT EXISTS idx_card_likes_user ON card_likes(user_id);
        CREATE INDEX IF NOT EXISTS idx_ui_templates_review_status ON ui_templates(review_status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ui_templates_uploader_review ON ui_templates(uploader_user_id, review_status);
        CREATE INDEX IF NOT EXISTS idx_ui_templates_created_at ON ui_templates(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempt_time);
        CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_operation_logs_action ON operation_logs(action);
        CREATE INDEX IF NOT EXISTS idx_page_views_created_at ON page_views(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_account_view_limits_lookup ON account_view_limits(content_type, content_id, user_id);
        CREATE INDEX IF NOT EXISTS idx_account_view_limits_last ON account_view_limits(last_view_at);
        CREATE INDEX IF NOT EXISTS idx_ip_bans_active ON ip_bans(is_active);
        CREATE INDEX IF NOT EXISTS idx_email_codes_lookup ON email_verification_codes(email, purpose, user_id, used_at, expires_at);
        CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_user ON newapi_redemptions(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_created_at ON newapi_redemptions(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_status ON newapi_redemptions(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_card_downloads_user ON card_downloads(user_id, created_at DESC);
    `);

    // Migration: add columns if they don't exist (for existing databases)
    try { db.exec('ALTER TABLE admin_users ADD COLUMN token_version INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN newapi_user_id TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN newapi_redeemed_cookies REAL DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN newapi_penalty_cookies REAL DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN comment_email_notifications INTEGER DEFAULT 1'); } catch (e) { /* column exists */ }
    try {
        const migrated = db.prepare("SELECT value FROM settings WHERE key = 'comment_email_notifications_default_on_migrated'").get();
        if (!migrated) {
            db.prepare('UPDATE users SET comment_email_notifications = 1 WHERE comment_email_notifications IS NULL OR comment_email_notifications = 0').run();
            db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)')
                .run('comment_email_notifications_default_on_migrated', '1', new Date().toISOString());
        }
    } catch (e) { /* best effort default migration */ }
    try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_newapi_user_unique ON users(newapi_user_id) WHERE newapi_user_id IS NOT NULL AND newapi_user_id != ''"); } catch (e) { /* index exists */ }
    try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email COLLATE NOCASE) WHERE email IS NOT NULL AND email != ''"); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN is_moderator INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_users_is_moderator ON users(is_moderator)'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN ban_reason TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN banned_at DATETIME'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE users ADD COLUMN banned_by_admin_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_users_is_banned ON users(is_banned)'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN user_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN likes_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_comments_card_user ON character_comments(card_id, user_id)'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN uploader_user_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN data_hash TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN detail_preview TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN has_ui_templates INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN ui_template_count INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN ui_template_variable_count INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN likes_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN comment_count_override INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_cards_likes_count ON character_cards(likes_count DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_cards_data_hash_unique ON character_cards (data_hash) WHERE data_hash IS NOT NULL'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN reply_to_id TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_comments ADD COLUMN reply_to_name TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE ui_template_comments ADD COLUMN reply_to_id TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE ui_template_comments ADD COLUMN reply_to_name TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_ui_template_comments_template_user ON ui_template_comments(template_id, user_id)'); } catch (e) { /* index exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN views_count INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN is_featured INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec("ALTER TABLE character_cards ADD COLUMN review_status TEXT DEFAULT 'approved'"); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN reviewed_by_admin_id INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN reviewed_at DATETIME'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN rejection_reason TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN uploader_ip_address TEXT'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN heat_email_milestone INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE character_cards ADD COLUMN updated_at DATETIME'); } catch (e) { /* column exists */ }
    try { db.exec("UPDATE character_cards SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL"); } catch (e) { /* ignore */ }
    try { db.exec("UPDATE character_cards SET review_status = 'approved' WHERE review_status IS NULL OR review_status = ''"); } catch (e) { /* migration best effort */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_cards_review_status ON character_cards(review_status, created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_cards_uploader_review ON character_cards(uploader_user_id, review_status)'); } catch (e) { /* index exists */ }
    try { db.exec("UPDATE ui_templates SET review_status = 'approved' WHERE review_status IS NULL OR review_status = ''"); } catch (e) { /* migration best effort */ }
    try { db.exec('ALTER TABLE ui_templates ADD COLUMN is_featured INTEGER DEFAULT 0'); } catch (e) { /* column exists */ }
    try { db.exec('ALTER TABLE ui_templates ADD COLUMN comment_count_override INTEGER'); } catch (e) { /* column exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_ui_templates_review_status ON ui_templates(review_status, created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_ui_templates_uploader_review ON ui_templates(uploader_user_id, review_status)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_ui_templates_featured ON ui_templates(is_featured, created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_ui_templates_created_at ON ui_templates(created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_email_codes_lookup ON email_verification_codes(email, purpose, user_id, used_at, expires_at)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_user ON newapi_redemptions(user_id, created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_created_at ON newapi_redemptions(created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_newapi_redemptions_status ON newapi_redemptions(status, created_at DESC)'); } catch (e) { /* index exists */ }
    try { db.exec(`
        CREATE TABLE IF NOT EXISTS card_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(card_id, user_id),
            FOREIGN KEY (card_id) REFERENCES character_cards(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `); } catch (e) { /* table exists */ }
    try { db.exec('CREATE INDEX IF NOT EXISTS idx_card_downloads_user ON card_downloads(user_id, created_at DESC)'); } catch (e) { /* index exists */ }

    try {
        db.exec(`
            CREATE TRIGGER IF NOT EXISTS trg_character_cards_review_guard_insert
            AFTER INSERT ON character_cards
            WHEN NEW.review_status IS NULL
                OR NEW.review_status = ''
                OR (NEW.review_status = 'approved' AND NEW.reviewed_at IS NULL)
            BEGIN
                UPDATE character_cards
                   SET review_status = 'pending',
                       reviewed_by_admin_id = NULL,
                       reviewed_at = NULL,
                       rejection_reason = NULL
                 WHERE id = NEW.id;
            END;

            CREATE TRIGGER IF NOT EXISTS trg_character_cards_review_guard_update
            AFTER UPDATE OF review_status ON character_cards
            WHEN NEW.review_status IS NULL
                OR NEW.review_status = ''
                OR (NEW.review_status = 'approved' AND NEW.reviewed_at IS NULL)
            BEGIN
                UPDATE character_cards
                   SET review_status = 'pending',
                       reviewed_by_admin_id = NULL,
                       reviewed_at = NULL,
                       rejection_reason = NULL
                 WHERE id = NEW.id;
            END;

            CREATE TRIGGER IF NOT EXISTS trg_ui_templates_review_guard_insert
            AFTER INSERT ON ui_templates
            WHEN NEW.review_status IS NULL
                OR NEW.review_status = ''
                OR (NEW.review_status = 'approved' AND NEW.reviewed_at IS NULL)
            BEGIN
                UPDATE ui_templates
                   SET review_status = 'pending',
                       reviewed_by_admin_id = NULL,
                       reviewed_at = NULL,
                       rejection_reason = NULL
                 WHERE id = NEW.id;
            END;

            CREATE TRIGGER IF NOT EXISTS trg_ui_templates_review_guard_update
            AFTER UPDATE OF review_status ON ui_templates
            WHEN NEW.review_status IS NULL
                OR NEW.review_status = ''
                OR (NEW.review_status = 'approved' AND NEW.reviewed_at IS NULL)
            BEGIN
                UPDATE ui_templates
                   SET review_status = 'pending',
                       reviewed_by_admin_id = NULL,
                       reviewed_at = NULL,
                       rejection_reason = NULL
                 WHERE id = NEW.id;
            END;
        `);
    } catch (e) {
        console.warn('[DB] Failed to install review guard triggers:', e.message);
    }

    try {
        const repairedCards = db.prepare(`
            UPDATE character_cards
               SET review_status = 'pending',
                   reviewed_by_admin_id = NULL,
                   reviewed_at = NULL,
                   rejection_reason = NULL
             WHERE review_status = 'approved'
               AND EXISTS (
                   SELECT 1
                     FROM operation_logs
                    WHERE target_type = 'card'
                      AND target_id = character_cards.id
                      AND action = 'upload_pending'
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM operation_logs
                    WHERE target_type = 'card'
                      AND target_id = character_cards.id
                      AND action IN ('admin_approve_card', 'moderator_approve_card')
               )
        `).run();
        if (repairedCards.changes > 0) {
            console.warn(`[DB] Reverted ${repairedCards.changes} unreviewed approved card(s) back to pending.`);
        }
    } catch (e) {
        console.warn('[DB] Failed to repair unreviewed approved cards:', e.message);
    }

    try {
        const repairedTemplates = db.prepare(`
            UPDATE ui_templates
               SET review_status = 'pending',
                   reviewed_by_admin_id = NULL,
                   reviewed_at = NULL,
                   rejection_reason = NULL
             WHERE review_status = 'approved'
               AND EXISTS (
                   SELECT 1
                     FROM operation_logs
                    WHERE target_type = 'ui_template'
                      AND target_id = ui_templates.id
                      AND action = 'upload_ui_template_pending'
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM operation_logs
                    WHERE target_type = 'ui_template'
                      AND target_id = ui_templates.id
                      AND action IN ('admin_approve_ui_template', 'moderator_approve_ui_template')
               )
        `).run();
        if (repairedTemplates.changes > 0) {
            console.warn(`[DB] Reverted ${repairedTemplates.changes} unreviewed approved UI template(s) back to pending.`);
        }
    } catch (e) {
        console.warn('[DB] Failed to repair unreviewed approved UI templates:', e.message);
    }

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
        hidden_tag_library: '',
        comment_email_block_words: '已严肃\n严肃\n12345'
    };
    const upsertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
    for (const [key, value] of Object.entries(defaultSettings)) {
        upsertSetting.run(key, value);
    }
    try {
        db.prepare('UPDATE settings SET value = ? WHERE key = ? AND value = ?')
            .run('已严肃\n严肃\n12345', 'comment_email_block_words', '已严肃\n严肃');
    } catch (e) { /* best effort default migration */ }

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
    db.prepare("DELETE FROM account_view_limits WHERE last_view_at < datetime('now', '-30 days')").run();
}

module.exports = { db, initDatabase, cleanupLoginAttempts, cleanupOldLogs };
