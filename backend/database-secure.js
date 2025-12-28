const Database = require('better-sqlite3');
const crypto = require('crypto');
const validator = require('./utils/input-validator');

/**
 * Secure Database Manager
 * All queries use parameterized statements to prevent SQL injection
 */
class SecureDatabaseManager {
  constructor(dbPath = process.env.DB_PATH || '/data/sync-monitor.db') {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    
    this.initializeSchema();
    console.log('Database initialized:', dbPath);
  }

  initializeSchema() {
    this.db.exec(`
      -- Configuration table
      CREATE TABLE IF NOT EXISTS config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        source_gitlab_url TEXT NOT NULL,
        source_group_id TEXT,
        target_gitlab_url TEXT NOT NULL,
        target_group_id TEXT,
        cron_schedule TEXT NOT NULL DEFAULT '0 */6 * * *',
        retry_attempts INTEGER NOT NULL DEFAULT 3,
        retry_delay_seconds INTEGER NOT NULL DEFAULT 60,
        enabled BOOLEAN NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      -- Sync history table
      CREATE TABLE IF NOT EXISTS sync_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'partial')),
        total_repos INTEGER NOT NULL DEFAULT 0,
        synced_repos INTEGER NOT NULL DEFAULT 0,
        failed_repos INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_sync_history_started ON sync_history(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sync_history_status ON sync_history(status);

      -- Repository sync details table
      CREATE TABLE IF NOT EXISTS repo_sync_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sync_id INTEGER NOT NULL,
        source_repo_id TEXT NOT NULL,
        source_repo_name TEXT NOT NULL,
        source_repo_url TEXT NOT NULL,
        target_repo_id TEXT,
        target_repo_name TEXT,
        target_repo_url TEXT,
        status TEXT NOT NULL CHECK (status IN ('pending', 'syncing', 'synced', 'failed', 'skipped')),
        action TEXT CHECK (action IN ('create', 'update', 'skip', 'error')),
        commits_ahead INTEGER DEFAULT 0,
        commits_behind INTEGER DEFAULT 0,
        last_commit_source TEXT,
        last_commit_target TEXT,
        error_message TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        synced_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (sync_id) REFERENCES sync_history(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_repo_sync_sync_id ON repo_sync_details(sync_id);
      CREATE INDEX IF NOT EXISTS idx_repo_sync_status ON repo_sync_details(status);

      -- Sync logs table
      CREATE TABLE IF NOT EXISTS sync_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sync_id INTEGER NOT NULL,
        repo_id INTEGER,
        level TEXT NOT NULL CHECK (level IN ('info', 'warning', 'error')),
        message TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (sync_id) REFERENCES sync_history(id) ON DELETE CASCADE,
        FOREIGN KEY (repo_id) REFERENCES repo_sync_details(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_sync_logs_sync_id ON sync_logs(sync_id);
      CREATE INDEX IF NOT EXISTS idx_sync_logs_level ON sync_logs(level);

      -- Users table (Phase 2)
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
        is_active BOOLEAN NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

      -- Sessions table (Phase 2)
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

      -- Pending repositories table (Phase 2)
      CREATE TABLE IF NOT EXISTS pending_repositories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repository_id TEXT NOT NULL,
        repository_name TEXT NOT NULL,
        repository_url TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined', 'synced', 'failed')),
        event_type TEXT NOT NULL,
        author_name TEXT,
        author_email TEXT,
        commit_message TEXT,
        commit_sha TEXT,
        webhook_payload TEXT,
        approved_by INTEGER,
        approved_at TEXT,
        declined_by INTEGER,
        declined_at TEXT,
        decline_reason TEXT,
        synced_at TEXT,
        error_message TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (approved_by) REFERENCES users(id),
        FOREIGN KEY (declined_by) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_pending_repos_status ON pending_repositories(status);
      CREATE INDEX IF NOT EXISTS idx_pending_repos_created ON pending_repositories(created_at DESC);

      -- Audit log table (Phase 2)
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

      -- Cleanup trigger for expired sessions
      CREATE TRIGGER IF NOT EXISTS cleanup_expired_sessions
      AFTER INSERT ON sessions
      BEGIN
        DELETE FROM sessions WHERE datetime(expires_at) < datetime('now');
      END;

      -- Cleanup trigger for old declined repositories (after 5 days)
      CREATE TRIGGER IF NOT EXISTS cleanup_old_declined
      AFTER UPDATE ON pending_repositories
      WHEN NEW.status = 'declined'
      BEGIN
        DELETE FROM pending_repositories 
        WHERE status = 'declined' 
        AND datetime(declined_at, '+5 days') < datetime('now');
      END;
    `);
  }

  // ===================
  // Configuration CRUD
  // ===================

  getConfig() {
    const stmt = this.db.prepare('SELECT * FROM config WHERE id = 1');
    return stmt.get();
  }

  upsertConfig(config) {
    // Validate inputs
    validator.validateString(config.source_gitlab_url, 2048, 'source_gitlab_url');
    validator.validateString(config.target_gitlab_url, 2048, 'target_gitlab_url');

    const stmt = this.db.prepare(`
      INSERT INTO config (
        id, source_gitlab_url, source_group_id, target_gitlab_url, target_group_id,
        cron_schedule, retry_attempts, retry_delay_seconds, enabled, updated_at
      ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        source_gitlab_url = excluded.source_gitlab_url,
        source_group_id = excluded.source_group_id,
        target_gitlab_url = excluded.target_gitlab_url,
        target_group_id = excluded.target_group_id,
        cron_schedule = excluded.cron_schedule,
        retry_attempts = excluded.retry_attempts,
        retry_delay_seconds = excluded.retry_delay_seconds,
        enabled = excluded.enabled,
        updated_at = datetime('now')
    `);

    const result = stmt.run(
      config.source_gitlab_url,
      config.source_group_id || null,
      config.target_gitlab_url,
      config.target_group_id || null,
      config.cron_schedule || '0 */6 * * *',
      config.retry_attempts || 3,
      config.retry_delay_seconds || 60,
      config.enabled !== undefined ? (config.enabled ? 1 : 0) : 1
    );

    return result;
  }

  // ===================
  // Sync History CRUD
  // ===================

  createSyncHistory() {
    const stmt = this.db.prepare(`
      INSERT INTO sync_history (started_at, status)
      VALUES (datetime('now'), 'running')
    `);

    const result = stmt.run();
    return result.lastInsertRowid;
  }

  updateSyncHistory(id, updates) {
    const validId = validator.validateId(id);

    const stmt = this.db.prepare(`
      UPDATE sync_history 
      SET completed_at = ?,
          status = ?,
          total_repos = ?,
          synced_repos = ?,
          failed_repos = ?,
          error_message = ?
      WHERE id = ?
    `);

    return stmt.run(
      updates.completed_at || null,
      updates.status,
      updates.total_repos || 0,
      updates.synced_repos || 0,
      updates.failed_repos || 0,
      updates.error_message || null,
      validId
    );
  }

  getSyncHistory(limit = 10, offset = 0) {
    const validLimit = validator.validateId(limit);
    const validOffset = validator.validateId(offset);

    const stmt = this.db.prepare(`
      SELECT * FROM sync_history 
      ORDER BY started_at DESC 
      LIMIT ? OFFSET ?
    `);

    return stmt.all(validLimit, validOffset);
  }

  getSyncById(id) {
    const validId = validator.validateId(id);
    const stmt = this.db.prepare('SELECT * FROM sync_history WHERE id = ?');
    return stmt.get(validId);
  }

  // ===================
  // Repository Sync Details CRUD
  // ===================

  createRepoSyncDetail(detail) {
    const validSyncId = validator.validateId(detail.sync_id);

    const stmt = this.db.prepare(`
      INSERT INTO repo_sync_details (
        sync_id, source_repo_id, source_repo_name, source_repo_url,
        target_repo_id, target_repo_name, target_repo_url, status, action
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      validSyncId,
      detail.source_repo_id,
      detail.source_repo_name,
      detail.source_repo_url,
      detail.target_repo_id || null,
      detail.target_repo_name || null,
      detail.target_repo_url || null,
      detail.status || 'pending',
      detail.action || null
    );

    return result.lastInsertRowid;
  }

  updateRepoSyncDetail(id, updates) {
    const validId = validator.validateId(id);

    const stmt = this.db.prepare(`
      UPDATE repo_sync_details 
      SET status = ?,
          action = ?,
          commits_ahead = ?,
          commits_behind = ?,
          error_message = ?,
          retry_count = ?,
          synced_at = ?
      WHERE id = ?
    `);

    return stmt.run(
      updates.status,
      updates.action || null,
      updates.commits_ahead || 0,
      updates.commits_behind || 0,
      updates.error_message || null,
      updates.retry_count || 0,
      updates.synced_at || null,
      validId
    );
  }

  getRepoSyncDetailsBySyncId(syncId) {
    const validSyncId = validator.validateId(syncId);

    const stmt = this.db.prepare(`
      SELECT * FROM repo_sync_details 
      WHERE sync_id = ? 
      ORDER BY created_at DESC
    `);

    return stmt.all(validSyncId);
  }

  // ===================
  // Sync Logs CRUD
  // ===================

  createSyncLog(log) {
    const validSyncId = validator.validateId(log.sync_id);
    const level = validator.validateEnum(log.level, ['info', 'warning', 'error'], 'log level');

    const stmt = this.db.prepare(`
      INSERT INTO sync_logs (sync_id, repo_id, level, message, details)
      VALUES (?, ?, ?, ?, ?)
    `);

    return stmt.run(
      validSyncId,
      log.repo_id || null,
      level,
      validator.sanitizeLogOutput(log.message),
      log.details || null
    );
  }

  getSyncLogs(syncId, limit = 100) {
    const validSyncId = validator.validateId(syncId);
    const validLimit = validator.validateId(limit);

    const stmt = this.db.prepare(`
      SELECT * FROM sync_logs 
      WHERE sync_id = ? 
      ORDER BY created_at DESC 
      LIMIT ?
    `);

    return stmt.all(validSyncId, validLimit);
  }

  // ===================
  // Users CRUD (Phase 2)
  // ===================

  createUser(user) {
    validator.validateUsername(user.username);
    validator.validateEmail(user.email);

    const stmt = this.db.prepare(`
      INSERT INTO users (username, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `);

    try {
      const result = stmt.run(
        user.username,
        user.email.toLowerCase(),
        user.password_hash,
        user.role || 'user'
      );

      return result.lastInsertRowid;
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new Error('Username or email already exists');
      }
      throw error;
    }
  }

  getUserByUsername(username) {
    const validUsername = validator.validateUsername(username);

    const stmt = this.db.prepare('SELECT * FROM users WHERE username = ? AND is_active = 1');
    return stmt.get(validUsername);
  }

  getUserByEmail(email) {
    const validEmail = validator.validateEmail(email);

    const stmt = this.db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
    return stmt.get(validEmail);
  }

  getUserById(id) {
    const validId = validator.validateId(id);

    const stmt = this.db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1');
    return stmt.get(validId);
  }

  updateUserPassword(userId, passwordHash) {
    const validId = validator.validateId(userId);

    const stmt = this.db.prepare(`
      UPDATE users 
      SET password_hash = ?, updated_at = datetime('now')
      WHERE id = ?
    `);

    return stmt.run(passwordHash, validId);
  }

  // ===================
  // Sessions CRUD (Phase 2)
  // ===================

  createSession(session) {
    const validUserId = validator.validateId(session.userId);

    const stmt = this.db.prepare(`
      INSERT INTO sessions (session_id, user_id, ip_address, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    return stmt.run(
      session.sessionId,
      validUserId,
      session.ipAddress || null,
      session.userAgent || null,
      session.expiresAt
    );
  }

  getSession(sessionId) {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions 
      WHERE session_id = ? 
      AND datetime(expires_at) > datetime('now')
    `);

    return stmt.get(sessionId);
  }

  deleteSession(sessionId) {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE session_id = ?');
    return stmt.run(sessionId);
  }

  invalidateUserSessions(userId) {
    const validId = validator.validateId(userId);

    const stmt = this.db.prepare('DELETE FROM sessions WHERE user_id = ?');
    return stmt.run(validId);
  }

  // ===================
  // Pending Repositories CRUD (Phase 2)
  // ===================

  createPendingRepository(repo) {
    const stmt = this.db.prepare(`
      INSERT INTO pending_repositories (
        repository_id, repository_name, repository_url, event_type,
        author_name, author_email, commit_message, commit_sha, webhook_payload
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      repo.repository_id,
      repo.repository_name,
      repo.repository_url,
      repo.event_type,
      repo.author_name || null,
      repo.author_email || null,
      repo.commit_message || null,
      repo.commit_sha || null,
      repo.webhook_payload || null
    );

    return result.lastInsertRowid;
  }

  getPendingRepositories(status = 'pending') {
    const validStatus = validator.validateEnum(
      status,
      ['pending', 'approved', 'declined', 'synced', 'failed'],
      'status'
    );

    const stmt = this.db.prepare(`
      SELECT * FROM pending_repositories 
      WHERE status = ? 
      ORDER BY created_at DESC
    `);

    return stmt.all(validStatus);
  }

  updatePendingRepository(id, updates) {
    const validId = validator.validateId(id);

    const stmt = this.db.prepare(`
      UPDATE pending_repositories 
      SET status = ?,
          approved_by = ?,
          approved_at = ?,
          declined_by = ?,
          declined_at = ?,
          decline_reason = ?,
          synced_at = ?,
          error_message = ?,
          updated_at = datetime('now')
      WHERE id = ?
    `);

    return stmt.run(
      updates.status,
      updates.approved_by || null,
      updates.approved_at || null,
      updates.declined_by || null,
      updates.declined_at || null,
      updates.decline_reason || null,
      updates.synced_at || null,
      updates.error_message || null,
      validId
    );
  }

  // ===================
  // Audit Log CRUD (Phase 2)
  // ===================

  createAuditLog(log) {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      log.userId || null,
      log.action,
      log.resource_type,
      log.resource_id || null,
      log.details || null,
      log.ipAddress || null,
      log.userAgent || null
    );
  }

  getAuditLogs(limit = 100, offset = 0) {
    const validLimit = validator.validateId(limit);
    const validOffset = validator.validateId(offset);

    const stmt = this.db.prepare(`
      SELECT a.*, u.username 
      FROM audit_log a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `);

    return stmt.all(validLimit, validOffset);
  }

  // ===================
  // Utility Methods
  // ===================

  close() {
    this.db.close();
  }

  backup(backupPath) {
    return this.db.backup(backupPath);
  }
}

module.exports = SecureDatabaseManager;
