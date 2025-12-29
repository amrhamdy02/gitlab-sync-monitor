const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const Database = require('better-sqlite3');
const cron = require('node-cron');
const simpleGit = require('simple-git');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Gitlab } = require('@gitbeaker/node');

// ============================================================================
// CONFIGURATION - All sensitive data from environment variables
// ============================================================================
const CONFIG = {
  port: process.env.PORT || 3001,
  
  // GitLab Source Configuration
  source: {
    url: process.env.SOURCE_GITLAB_URL,
    token: process.env.SOURCE_GITLAB_TOKEN,
    groupId: process.env.SOURCE_GROUP_ID
  },
  
  // GitLab Target Configuration
  target: {
    url: process.env.TARGET_GITLAB_URL,
    token: process.env.TARGET_GITLAB_TOKEN,
    groupId: process.env.TARGET_GROUP_ID
  },
  
  // Webhook Security
  webhookSecret: process.env.WEBHOOK_SECRET || process.env.gitlab_webhook_secret || crypto.randomBytes(32).toString('hex'),
  
  // JWT Configuration
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  
  // Sync Configuration
  syncSchedule: process.env.SYNC_SCHEDULE || '0 2 * * *', // 2 AM daily
  
  // File Paths
  dbPath: process.env.DB_PATH || '/data/sync.db',
  reposPath: process.env.REPOS_PATH || '/data/repos'
};

// ============================================================================
// INITIALIZE EXPRESS AND SOCKET.IO
// ============================================================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST']
  }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend/build')));

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================
function initializeDatabase() {
  // Ensure data directory exists
  const dataDir = path.dirname(CONFIG.dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  
  // Ensure repos directory exists
  if (!fs.existsSync(CONFIG.reposPath)) {
    fs.mkdirSync(CONFIG.reposPath, { recursive: true });
  }

  const db = new Database(CONFIG.dbPath);
  
  // Create tables
  db.exec(`
    -- Configuration table
    CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_url TEXT NOT NULL,
      source_group_id TEXT NOT NULL,
      target_url TEXT NOT NULL,
      target_group_id TEXT NOT NULL,
      sync_schedule TEXT DEFAULT '0 2 * * *',
      last_sync DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Repositories table
    CREATE TABLE IF NOT EXISTS repositories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      gitlab_id INTEGER NOT NULL UNIQUE,
      name TEXT NOT NULL,
      path TEXT NOT NULL,
      description TEXT,
      web_url TEXT,
      ssh_url TEXT,
      http_url TEXT,
      last_activity DATETIME,
      has_new_commits BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Sync history table
    CREATE TABLE IF NOT EXISTS sync_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repository_id INTEGER,
      status TEXT CHECK(status IN ('pending', 'running', 'success', 'failed')),
      started_at DATETIME,
      completed_at DATETIME,
      error_message TEXT,
      commits_synced INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (repository_id) REFERENCES repositories(id)
    );
    
    -- Phase 2: Pending approvals table (for future use)
    CREATE TABLE IF NOT EXISTS pending_approvals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repository_id INTEGER,
      event_type TEXT,
      commit_sha TEXT,
      commit_message TEXT,
      author_name TEXT,
      author_email TEXT,
      status TEXT CHECK(status IN ('pending', 'approved', 'declined')) DEFAULT 'pending',
      approved_by TEXT,
      approved_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (repository_id) REFERENCES repositories(id)
    );
    
    -- Commit audit log table
    CREATE TABLE IF NOT EXISTS commit_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repository_id INTEGER,
      repository_name TEXT,
      branch TEXT,
      commit_sha TEXT,
      commit_message TEXT,
      author_name TEXT,
      author_email TEXT,
      commit_type TEXT CHECK(commit_type IN ('push', 'merge', 'force')),
      is_force_push BOOLEAN DEFAULT 0,
      timestamp DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (repository_id) REFERENCES repositories(id)
    );
    
    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_sync_history_repo ON sync_history(repository_id);
    CREATE INDEX IF NOT EXISTS idx_sync_history_status ON sync_history(status);
    CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status);
    CREATE INDEX IF NOT EXISTS idx_repositories_gitlab_id ON repositories(gitlab_id);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_repo ON commit_audit(repository_id);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_branch ON commit_audit(branch);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_timestamp ON commit_audit(timestamp DESC);
  `);
  
  console.log('✅ Database initialized successfully');
  return db;
}

const db = initializeDatabase();

// ============================================================================
// GITLAB API CLIENTS
// ============================================================================
let sourceGitlab, targetGitlab;

function initializeGitlabClients() {
  if (!CONFIG.source.url || !CONFIG.source.token) {
    console.error('❌ Source GitLab configuration missing');
    return false;
  }
  
  if (!CONFIG.target.url || !CONFIG.target.token) {
    console.error('❌ Target GitLab configuration missing');
    return false;
  }
  
  try {
    sourceGitlab = new Gitlab({
      host: CONFIG.source.url,
      token: CONFIG.source.token
    });
    
    targetGitlab = new Gitlab({
      host: CONFIG.target.url,
      token: CONFIG.target.token
    });
    
    console.log('✅ GitLab clients initialized');
    
    // Log group configuration
    if (CONFIG.source.groupId) {
      console.log(`   Source: Group ${CONFIG.source.groupId}`);
    } else {
      console.log(`   Source: All accessible projects`);
    }
    
    if (CONFIG.target.groupId) {
      console.log(`   Target: Group ${CONFIG.target.groupId}`);
    } else {
      console.log(`   Target: User namespace`);
    }
    
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize GitLab clients:', error.message);
    return false;
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Sanitize repository name for safe file system operations
function sanitizeRepoName(name) {
  return name.replace(/[^a-zA-Z0-9-_]/g, '_');
}

// Verify webhook signature
function verifyWebhookSignature(payload, receivedToken) {
  if (!CONFIG.webhookSecret) {
    console.warn('⚠️ No webhook secret configured, skipping verification');
    return true; // Allow if no secret configured
  }
  
  if (!receivedToken) {
    console.warn('⚠️ No token received in webhook');
    return false;
  }
  
  // GitLab sends the secret token directly in X-Gitlab-Token header
  // Simple comparison (GitLab doesn't use HMAC by default)
  return receivedToken === CONFIG.webhookSecret;
}

// Emit event to all connected clients
function emitToClients(event, data) {
  io.emit(event, data);
  console.log(`📡 Emitted ${event}:`, data);
}

// ============================================================================
// DATABASE OPERATIONS (Parameterized queries for SQL injection prevention)
// ============================================================================

function getRepositories() {
  const stmt = db.prepare(`
    SELECT r.*, 
           sh.status as last_sync_status,
           sh.completed_at as last_sync_time,
           sh.error_message as last_sync_error,
           r.has_new_commits
    FROM repositories r
    LEFT JOIN (
      SELECT repository_id, status, completed_at, error_message,
             ROW_NUMBER() OVER (PARTITION BY repository_id ORDER BY created_at DESC) as rn
      FROM sync_history
    ) sh ON r.id = sh.repository_id AND sh.rn = 1
    ORDER BY r.last_activity DESC
  `);
  
  return stmt.all();
}

function getRepository(gitlabId) {
  const stmt = db.prepare('SELECT * FROM repositories WHERE gitlab_id = ?');
  return stmt.get(gitlabId);
}

function upsertRepository(repo) {
  const existing = getRepository(repo.id);
  
  if (existing) {
    const stmt = db.prepare(`
      UPDATE repositories 
      SET name = ?, path = ?, description = ?, web_url = ?, 
          ssh_url = ?, http_url = ?, last_activity = ?, updated_at = CURRENT_TIMESTAMP
      WHERE gitlab_id = ?
    `);
    
    stmt.run(
      repo.name,
      repo.path_with_namespace,
      repo.description || '',
      repo.web_url,
      repo.ssh_url_to_repo,
      repo.http_url_to_repo,
      repo.last_activity_at,
      repo.id
    );
    
    return existing.id;
  } else {
    const stmt = db.prepare(`
      INSERT INTO repositories (gitlab_id, name, path, description, web_url, ssh_url, http_url, last_activity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(
      repo.id,
      repo.name,
      repo.path_with_namespace,
      repo.description || '',
      repo.web_url,
      repo.ssh_url_to_repo,
      repo.http_url_to_repo,
      repo.last_activity_at
    );
    
    return result.lastInsertRowid;
  }
}

function createSyncHistory(repositoryId, status) {
  const stmt = db.prepare(`
    INSERT INTO sync_history (repository_id, status, started_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
  `);
  
  const result = stmt.run(repositoryId, status);
  return result.lastInsertRowid;
}

function updateSyncHistory(syncId, status, error = null, commitCount = 0) {
  const stmt = db.prepare(`
    UPDATE sync_history 
    SET status = ?, completed_at = CURRENT_TIMESTAMP, error_message = ?, commits_synced = ?
    WHERE id = ?
  `);
  
  stmt.run(status, error, commitCount, syncId);
}

function getSyncHistory(limit = 50) {
  const stmt = db.prepare(`
    SELECT sh.*, r.name as repository_name, r.path as repository_path
    FROM sync_history sh
    JOIN repositories r ON sh.repository_id = r.id
    ORDER BY sh.created_at DESC
    LIMIT ?
  `);
  
  return stmt.all(limit);
}

async function findOrCreateTargetNamespace(sourceNamespacePath) {
  try {
    // sourceNamespacePath is like "engineering/subgroup" or just "engineering"
    // We need to find the matching namespace on target
    
    console.log(`  🔍 Looking for namespace: ${sourceNamespacePath}`);
    
    // Try to find existing group by path
    const groups = await targetGitlab.Groups.all({
      search: sourceNamespacePath,
      perPage: 100
    });
    
    // Look for exact path match
    let targetGroup = groups.find(g => g.full_path === sourceNamespacePath);
    
    if (targetGroup) {
      console.log(`  ✅ Found existing namespace: ${targetGroup.full_path} (ID: ${targetGroup.id})`);
      return targetGroup.id;
    }
    
    // If not found, try to create it
    // For nested groups like "engineering/backend", we need to handle parent groups
    const pathParts = sourceNamespacePath.split('/');
    
    if (pathParts.length > 1) {
      // Nested group - not implementing auto-creation of nested groups for safety
      console.warn(`  ⚠️ Nested group ${sourceNamespacePath} not found on target`);
      console.warn(`  ⚠️ Please create this group manually on target GitLab`);
      return null;
    }
    
    // Try to create single-level group
    console.log(`  ➕ Creating group: ${sourceNamespacePath}`);
    const newGroup = await targetGitlab.Groups.create({
      name: pathParts[0],
      path: pathParts[0],
      visibility: 'private'
    });
    
    console.log(`  ✅ Created group: ${newGroup.full_path} (ID: ${newGroup.id})`);
    return newGroup.id;
    
  } catch (error) {
    console.error(`  ❌ Error finding/creating namespace ${sourceNamespacePath}:`, error.message);
    return null;
  }
}

function logCommitsToAudit(repositoryId, repositoryName, commits) {
  const stmt = db.prepare(`
    INSERT INTO commit_audit (
      repository_id, repository_name, branch, commit_sha, commit_message,
      author_name, author_email, commit_type, is_force_push, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  for (const commit of commits) {
    try {
      stmt.run(
        repositoryId,
        repositoryName,
        commit.branch || 'unknown',
        commit.sha,
        commit.message,
        commit.author_name,
        commit.author_email,
        commit.type || 'push',
        commit.is_force ? 1 : 0,
        commit.timestamp || new Date().toISOString()
      );
    } catch (error) {
      console.warn(`Failed to log commit ${commit.sha}:`, error.message);
    }
  }
}

// Cleanup old audit logs to prevent database bloat
function cleanupOldAuditLogs(retentionDays = 90) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.setDate() - retentionDays);
    
    const stmt = db.prepare(`
      DELETE FROM commit_audit 
      WHERE timestamp < ?
    `);
    
    const result = stmt.run(cutoffDate.toISOString());
    
    if (result.changes > 0) {
      console.log(`🗑️ Cleaned up ${result.changes} audit log entries older than ${retentionDays} days`);
    }
    
    return result.changes;
  } catch (error) {
    console.error('❌ Error cleaning up audit logs:', error.message);
    return 0;
  }
}

function cleanupOldAuditLogs(retentionDays = 30) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
    
    const stmt = db.prepare(`
      DELETE FROM commit_audit 
      WHERE timestamp < ?
    `);
    
    const result = stmt.run(cutoffDate.toISOString());
    
    if (result.changes > 0) {
      console.log(`🗑️ Cleaned up ${result.changes} audit log entries older than ${retentionDays} days`);
    }
    
    return result.changes;
  } catch (error) {
    console.error('❌ Error cleaning up audit logs:', error.message);
    return 0;
  }
}

// ============================================================================
// SYNC OPERATIONS
// ============================================================================

async function fetchSourceRepositories() {
  try {
    let projects;
    
    if (CONFIG.source.groupId) {
      // Fetch projects from specific group
      console.log(`🔍 Fetching repositories from source group ${CONFIG.source.groupId}...`);
      projects = await sourceGitlab.GroupProjects.all(CONFIG.source.groupId, {
        perPage: 100,
        includeSubgroups: true
      });
    } else {
      // Fetch all projects accessible to the user
      console.log(`🔍 Fetching all accessible repositories from source...`);
      projects = await sourceGitlab.Projects.all({
        perPage: 100,
        membership: true,  // Only projects user is a member of
        archived: false    // Exclude archived projects
      });
    }
    
    console.log(`✅ Found ${projects.length} repositories in source`);
    
    // Update database
    for (const project of projects) {
      upsertRepository(project);
    }
    
    emitToClients('repositories_updated', { count: projects.length });
    
    return projects;
  } catch (error) {
    console.error('❌ Error fetching repositories:', error.message);
    throw error;
  }
}

async function syncRepository(repoId) {
  const repo = db.prepare('SELECT * FROM repositories WHERE id = ?').get(repoId);
  
  if (!repo) {
    throw new Error('Repository not found');
  }
  
  const syncId = createSyncHistory(repoId, 'running');
  
  emitToClients('sync_started', {
    repositoryId: repoId,
    repositoryName: repo.name,
    syncId
  });
  
  // Use temporary directory for clone (ephemeral pod storage, auto-cleanup)
  const tempId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const localPath = path.join('/tmp', `mirror-${tempId}`);
  
  try {
    console.log(`🔄 Starting sync for ${repo.name}...`);
    console.log(`  📁 Using temporary clone: ${localPath}`);
    
    const git = simpleGit();
    
    // Clone repository to temporary location with mirror
    console.log(`  📥 Cloning ${repo.name} to temporary location...`);
    
    // Construct authenticated source URL
    const sourceUrl = new URL(repo.http_url);
    sourceUrl.username = 'oauth2';
    sourceUrl.password = CONFIG.source.token;
    
    await git.clone(sourceUrl.toString(), localPath, {
      '--mirror': null
    });
    
    console.log(`  ✅ Clone completed`);
    
    // Get target repository or create it
    let targetRepo;
    try {
      // Extract namespace from source repo path
      // repo.path is like "engineering/backend-api" or "devops/infrastructure"
      const pathParts = repo.path.split('/');
      const repoName = pathParts[pathParts.length - 1]; // Last part is repo name
      const namespacePath = pathParts.slice(0, -1).join('/'); // Everything before is namespace
      
      console.log(`  📂 Source namespace: ${namespacePath || '(root)'}`);
      
      // Determine target namespace
      let targetNamespaceId = null;
      
      if (CONFIG.target.groupId) {
        // If target group ID specified, always use that (single target group mode)
        targetNamespaceId = CONFIG.target.groupId;
        console.log(`  📂 Using configured target group ID: ${targetNamespaceId}`);
      } else if (namespacePath) {
        // Try to preserve the source namespace structure
        targetNamespaceId = await findOrCreateTargetNamespace(namespacePath);
        
        if (!targetNamespaceId) {
          console.warn(`  ⚠️ Could not find/create namespace ${namespacePath} on target`);
          console.warn(`  ⚠️ Repository will be created in your personal namespace`);
          console.warn(`  ⚠️ To fix: Create group "${namespacePath}" on target GitLab first`);
        }
      }
      
      // Try to find existing project
      if (targetNamespaceId) {
        const targetProjects = await targetGitlab.GroupProjects.all(targetNamespaceId);
        targetRepo = targetProjects.find(p => p.path === repoName);
      } else {
        // Search in user namespace
        const targetProjects = await targetGitlab.Projects.all({
          perPage: 100,
          membership: true,
          search: repo.name
        });
        targetRepo = targetProjects.find(p => p.path === repoName);
      }
      
      if (!targetRepo) {
        console.log(`  ➕ Creating target repository ${repo.name}...`);
        const createParams = {
          name: repo.name,
          path: repoName,
          description: repo.description,
          visibility: 'private'
        };
        
        // Add namespace if we found/created one
        if (targetNamespaceId) {
          createParams.namespaceId = targetNamespaceId;
          console.log(`  📂 Creating in namespace ID: ${targetNamespaceId}`);
        } else {
          console.log(`  📂 Creating in user namespace`);
        }
        
        targetRepo = await targetGitlab.Projects.create(createParams);
      }
    } catch (error) {
      console.error('  ❌ Error finding/creating target repo:', error.message);
      throw error;
    }
    
    // Push to target using http URL with token embedded (safer than shell commands)
    console.log(`  📤 Pushing to target...`);
    const repoGit = simpleGit(localPath);
    
    // Construct authenticated target URL safely
    const targetUrl = new URL(targetRepo.http_url_to_repo);
    targetUrl.username = 'oauth2';
    targetUrl.password = CONFIG.target.token;
    
    // Handle protected branches: unprotect, mirror, then re-protect
    let protectedBranches = [];
    try {
      // Get list of protected branches
      protectedBranches = await targetGitlab.ProtectedBranches.all(targetRepo.id);
      
      if (protectedBranches.length > 0) {
        console.log(`  🔓 Unprotecting ${protectedBranches.length} branches...`);
        
        // Unprotect all branches temporarily
        for (const branch of protectedBranches) {
          await targetGitlab.ProtectedBranches.unprotect(targetRepo.id, branch.name);
        }
      }
    } catch (error) {
      console.warn(`  ⚠️ Could not check/unprotect branches: ${error.message}`);
    }
    
    // Push with mirror
    await repoGit.push(targetUrl.toString(), '--mirror');
    
    console.log(`  ✅ Mirror push completed`);
    
    // Note: Audit log is populated via webhooks, not from git log extraction
    // This keeps sync fast and storage minimal
    
    // Re-protect branches that were protected
    if (protectedBranches.length > 0) {
      console.log(`  🔒 Re-protecting ${protectedBranches.length} branches...`);
      
      for (const branch of protectedBranches) {
        try {
          await targetGitlab.ProtectedBranches.protect(targetRepo.id, branch.name, {
            pushAccessLevel: branch.push_access_levels?.[0]?.access_level || 40,
            mergeAccessLevel: branch.merge_access_levels?.[0]?.access_level || 40,
            unprotectAccessLevel: branch.unprotect_access_levels?.[0]?.access_level || 40
          });
        } catch (error) {
          console.warn(`  ⚠️ Could not re-protect branch ${branch.name}: ${error.message}`);
        }
      }
    }
    
    // Success - update sync history
    // Note: commitCount is 0 since we're not extracting from git log
    // Actual commit tracking happens via webhooks
    const commitCount = 0;
    
    updateSyncHistory(syncId, 'success', null, commitCount);
    
    // Clear the "new commits" flag since we just synced
    db.prepare('UPDATE repositories SET has_new_commits = 0 WHERE id = ?').run(repoId);
    
    console.log(`✅ Successfully synced ${repo.name}`);
    
    emitToClients('sync_completed', {
      repositoryId: repoId,
      repositoryName: repo.name,
      syncId,
      status: 'success',
      commitCount
    });
    
    // Cleanup: Delete temporary clone
    console.log(`  🗑️ Cleaning up temporary clone...`);
    if (fs.existsSync(localPath)) {
      fs.rmSync(localPath, { recursive: true, force: true });
      console.log(`  ✅ Temporary clone deleted`);
    }
    
    return { success: true, commitCount };
    
  } catch (error) {
    console.error(`❌ Error syncing ${repo.name}:`, error.message);
    
    updateSyncHistory(syncId, 'failed', error.message);
    
    emitToClients('sync_completed', {
      repositoryId: repoId,
      repositoryName: repo.name,
      syncId,
      status: 'failed',
      error: error.message
    });
    
    // Cleanup: Delete temporary clone even on error
    try {
      if (fs.existsSync(localPath)) {
        fs.rmSync(localPath, { recursive: true, force: true });
        console.log(`  🗑️ Cleaned up temporary clone after error`);
      }
    } catch (cleanupError) {
      console.warn(`  ⚠️ Could not cleanup temporary clone: ${cleanupError.message}`);
    }
    
    throw error;
  }
}

async function syncAllRepositories() {
  console.log('🚀 Starting sync of all repositories...');
  
  const repos = getRepositories();
  const results = {
    total: repos.length,
    success: 0,
    failed: 0,
    errors: []
  };
  
  for (const repo of repos) {
    try {
      await syncRepository(repo.id);
      results.success++;
    } catch (error) {
      results.failed++;
      results.errors.push({
        repository: repo.name,
        error: error.message
      });
    }
  }
  
  console.log(`✅ Sync completed: ${results.success} success, ${results.failed} failed`);
  
  emitToClients('sync_all_completed', results);
  
  return results;
}

// ============================================================================
// REST API ENDPOINTS
// ============================================================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: db ? 'connected' : 'disconnected',
    gitlab: sourceGitlab && targetGitlab ? 'connected' : 'disconnected'
  });
});

// Get configuration
app.get('/api/config', (req, res) => {
  res.json({
    source: {
      url: CONFIG.source.url,
      groupId: CONFIG.source.groupId
    },
    target: {
      url: CONFIG.target.url,
      groupId: CONFIG.target.groupId
    },
    syncSchedule: CONFIG.syncSchedule
  });
});

// Get all repositories
app.get('/api/repositories', (req, res) => {
  try {
    const repos = getRepositories();
    res.json(repos);
  } catch (error) {
    console.error('Error fetching repositories:', error);
    res.status(500).json({ error: error.message });
  }
});

// Refresh repository list from source
app.post('/api/repositories/refresh', async (req, res) => {
  try {
    const projects = await fetchSourceRepositories();
    res.json({ success: true, count: projects.length });
  } catch (error) {
    console.error('Error refreshing repositories:', error);
    res.status(500).json({ error: error.message });
  }
});

// Sync single repository
app.post('/api/sync/:repoId', async (req, res) => {
  try {
    const repoId = parseInt(req.params.repoId);
    const result = await syncRepository(repoId);
    res.json(result);
  } catch (error) {
    console.error('Error syncing repository:', error);
    res.status(500).json({ error: error.message });
  }
});

// Sync all repositories
app.post('/api/sync/all', async (req, res) => {
  try {
    // Start sync in background
    syncAllRepositories().catch(err => {
      console.error('Background sync error:', err);
    });
    
    res.json({ success: true, message: 'Sync started' });
  } catch (error) {
    console.error('Error starting sync:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get sync history
app.get('/api/sync/history', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const history = getSyncHistory(limit);
    res.json(history);
  } catch (error) {
    console.error('Error fetching sync history:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get commit audit log
app.get('/api/audit/commits', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const stmt = db.prepare(`
      SELECT 
        repository_name as repository,
        branch,
        commit_sha as sha,
        commit_message as message,
        author_name,
        author_email,
        commit_type as type,
        is_force_push as is_force,
        timestamp
      FROM commit_audit
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    const commits = stmt.all(limit);
    res.json(commits);
  } catch (error) {
    console.error('Error fetching commit audit:', error);
    res.status(500).json({ error: error.message });
  }
});

// Webhook endpoint - Process GitLab push events for real-time monitoring
app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-gitlab-token'];
  
  if (!verifyWebhookSignature(req.body, signature)) {
    console.warn('⚠️ Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  const event = req.headers['x-gitlab-event'];
  console.log(`📨 Received webhook: ${event}`);
  
  // Handle Push events for commit monitoring
  if (event === 'Push Hook') {
    try {
      const payload = req.body;
      const projectName = payload.project?.name || 'Unknown';
      const projectId = payload.project?.id;
      const ref = payload.ref || '';
      const branch = ref.replace('refs/heads/', '');
      const isForce = payload.total_commits_count === 0 && payload.commits?.length === 0;
      
      console.log(`  📝 Push to ${projectName}/${branch} (${payload.commits?.length || 0} commits)`);
      
      // Find repository in database
      let repoId = null;
      if (projectId) {
        const repo = db.prepare('SELECT id FROM repositories WHERE gitlab_id = ?').get(projectId);
        repoId = repo?.id;
        
        // Mark repository as having new commits (needs sync)
        if (repoId) {
          db.prepare('UPDATE repositories SET has_new_commits = 1 WHERE id = ?').run(repoId);
          
          // Notify UI to refresh repository list
          emitToClients('repositories_updated', {
            repositoryId: repoId,
            hasNewCommits: true
          });
        }
      }
      
      // Log commits to audit
      if (payload.commits && payload.commits.length > 0) {
        const commitData = payload.commits.map(commit => ({
          branch: branch,
          sha: commit.id,
          message: commit.message,
          author_name: commit.author?.name || 'Unknown',
          author_email: commit.author?.email || '',
          timestamp: commit.timestamp,
          type: commit.message?.toLowerCase().includes('merge') ? 'merge' : 'push',
          is_force: isForce
        }));
        
        logCommitsToAudit(repoId, projectName, commitData);
        console.log(`  ✅ Logged ${commitData.length} commits to audit`);
        
        // Emit to connected clients for real-time update
        emitToClients('audit_updated', {
          repository: projectName,
          branch: branch,
          commits: commitData.length,
          isForce: isForce
        });
      } else if (isForce) {
        // Force push with no commits shown (rewrites history)
        console.log(`  ⚠️ Force push detected on ${branch}`);
        
        const forcePushData = [{
          branch: branch,
          sha: payload.after || 'unknown',
          message: `Force push to ${branch}`,
          author_name: payload.user_name || 'Unknown',
          author_email: payload.user_email || '',
          timestamp: new Date().toISOString(),
          type: 'force',
          is_force: true
        }];
        
        logCommitsToAudit(repoId, projectName, forcePushData);
        
        emitToClients('audit_updated', {
          repository: projectName,
          branch: branch,
          commits: 1,
          isForce: true
        });
      }
      
    } catch (error) {
      console.error('❌ Error processing webhook:', error);
    }
  }
  
  // Legacy webhook event notification
  emitToClients('webhook_received', {
    event,
    timestamp: new Date().toISOString()
  });
  
  res.json({ success: true });
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build', 'index.html'));
});

// ============================================================================
// WEBSOCKET CONNECTION
// ============================================================================
io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);
  
  socket.on('disconnect', () => {
    console.log('🔌 Client disconnected:', socket.id);
  });
});

// ============================================================================
// SCHEDULED SYNC
// ============================================================================
let syncTask = null;

function startScheduledSync() {
  // Allow disabling scheduled sync via environment variable
  if (process.env.DISABLE_SCHEDULED_SYNC === 'true') {
    console.log('⏰ Scheduled sync is DISABLED (DISABLE_SCHEDULED_SYNC=true)');
  } else {
    if (syncTask) {
      syncTask.stop();
    }
    
    console.log(`⏰ Scheduling sync: ${CONFIG.syncSchedule}`);
    
    syncTask = cron.schedule(CONFIG.syncSchedule, async () => {
      console.log('⏰ Running scheduled sync...');
      try {
        await syncAllRepositories();
      } catch (error) {
        console.error('Scheduled sync error:', error);
      }
    });
  }
  
  // Schedule daily audit log cleanup (runs at 3 AM)
  const retentionDays = parseInt(process.env.AUDIT_RETENTION_DAYS) || 90;
  console.log(`🗑️ Scheduling daily audit log cleanup (retention: ${retentionDays} days, runs at 3 AM)`);
  
  cron.schedule('0 3 * * *', () => {
    console.log('🗑️ Running scheduled audit log cleanup...');
    cleanupOldAuditLogs(retentionDays);
  });
}

// ============================================================================
// SERVER STARTUP
// ============================================================================
async function startServer() {
  try {
    // Git SSL configuration is handled via GIT_SSL_NO_VERIFY environment variable
    // Set in Dockerfile, no need to write config file
    console.log('🔧 Git configured to trust self-signed certificates (via GIT_SSL_NO_VERIFY)');
    
    // Initialize GitLab clients
    const gitlabReady = initializeGitlabClients();
    
    if (gitlabReady) {
      // Fetch initial repository list
      await fetchSourceRepositories();
      
      // Start scheduled sync
      startScheduledSync();
    } else {
      console.warn('⚠️ GitLab clients not initialized. Please check environment variables.');
    }
    
    // Start server
    server.listen(CONFIG.port, () => {
      console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          🚀 GitLab Sync Monitor - Phase 1 (Secure)            ║
║                                                                ║
║  Server running on port ${CONFIG.port}                               ║
║  Environment: ${process.env.NODE_ENV || 'development'}                                ║
║  Database: ${CONFIG.dbPath}                           ║
║  Sync Schedule: ${CONFIG.syncSchedule}                           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
      `);
      
      console.log('\n📋 Configuration Status:');
      console.log(`  Source GitLab: ${CONFIG.source.url ? '✅' : '❌'}`);
      console.log(`  Target GitLab: ${CONFIG.target.url ? '✅' : '❌'}`);
      console.log(`  Webhook Secret: ${CONFIG.webhookSecret ? '✅' : '❌'}`);
      console.log(`  JWT Secret: ${CONFIG.jwtSecret ? '✅' : '❌'}\n`);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================
process.on('SIGTERM', () => {
  console.log('📴 SIGTERM received. Shutting down gracefully...');
  
  if (syncTask) {
    syncTask.stop();
  }
  
  db.close();
  
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// Start the server
startServer();
