// ============================================================================
// GitLab Sync Monitor - Complete Single-File Version
// Combines: Modular logic + Security hardening + Storage optimization
// ============================================================================

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Gitlab } = require('@gitbeaker/node');
const Database = require('better-sqlite3');
const cron = require('node-cron');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const simpleGit = require('simple-git');

// ============================================================================
// CONFIGURATION
// ============================================================================
const CONFIG = {
  port: process.env.PORT || 3001,
  
  // GitLab Source
  source: {
    url: process.env.SOURCE_GITLAB_URL,
    token: process.env.SOURCE_GITLAB_TOKEN,
    groupId: process.env.SOURCE_GROUP_ID || null
  },
  
  // GitLab Target
  target: {
    url: process.env.TARGET_GITLAB_URL,
    token: process.env.TARGET_GITLAB_TOKEN,
    groupId: process.env.TARGET_GROUP_ID || null
  },
  
  // Webhook Security
  webhookSecret: process.env.WEBHOOK_SECRET || process.env.gitlab_webhook_secret || crypto.randomBytes(32).toString('hex'),
  
  // Paths
  dbPath: process.env.DB_PATH || '/data/sync.db',
  
  // Settings
  disableScheduledSync: process.env.DISABLE_SCHEDULED_SYNC === 'true',
  auditRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS) || 90
};

// ============================================================================
// EXPRESS & SOCKET.IO SETUP
// ============================================================================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static frontend
app.use(express.static(path.join(__dirname, '../frontend/build')));

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================
let db;

function initializeDatabase() {
  db = new Database(CONFIG.dbPath);
  db.pragma('journal_mode = WAL');
  
  // Create tables
  db.exec(`
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
    
    CREATE INDEX IF NOT EXISTS idx_sync_history_repo ON sync_history(repository_id);
    CREATE INDEX IF NOT EXISTS idx_sync_history_status ON sync_history(status);
    CREATE INDEX IF NOT EXISTS idx_repositories_gitlab_id ON repositories(gitlab_id);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_repo ON commit_audit(repository_id);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_branch ON commit_audit(branch);
    CREATE INDEX IF NOT EXISTS idx_commit_audit_timestamp ON commit_audit(timestamp DESC);
  `);
  
  console.log('✅ Database initialized successfully');
  return db;
}

// ============================================================================
// GITLAB CLIENT INITIALIZATION
// ============================================================================
let sourceGitlab, targetGitlab;

function initializeGitlabClients() {
  try {
    if (!CONFIG.source.url || !CONFIG.source.token) {
      console.warn('⚠️ Source GitLab not configured');
      return false;
    }
    
    if (!CONFIG.target.url || !CONFIG.target.token) {
      console.warn('⚠️ Target GitLab not configured');
      return false;
    }
    
    sourceGitlab = new Gitlab({
      host: CONFIG.source.url,
      token: CONFIG.source.token,
      rejectUnauthorized: false
    });
    
    targetGitlab = new Gitlab({
      host: CONFIG.target.url,
      token: CONFIG.target.token,
      rejectUnauthorized: false
    });
    
    console.log('✅ GitLab clients initialized');
    console.log(`   Source: ${CONFIG.source.groupId || 'All accessible projects'}`);
    console.log(`   Target: ${CONFIG.target.groupId || 'Preserve source namespaces'}`);
    
    return true;
  } catch (error) {
    console.error('❌ Failed to initialize GitLab clients:', error.message);
    return false;
  }
}

// ============================================================================
// DATABASE HELPER FUNCTIONS
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
    VALUES (?, ?, ?)
  `);
  
  const result = stmt.run(repositoryId, status, new Date().toISOString());
  return result.lastInsertRowid;
}

function updateSyncHistory(syncId, status, errorMessage = null, commitCount = 0) {
  const stmt = db.prepare(`
    UPDATE sync_history 
    SET status = ?, completed_at = ?, error_message = ?, commits_synced = ?
    WHERE id = ?
  `);
  
  stmt.run(status, new Date().toISOString(), errorMessage, commitCount, syncId);
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

function cleanupOldAuditLogs(retentionDays = 90) {
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
// GITLAB OPERATIONS
// ============================================================================

async function fetchSourceRepositories() {
  try {
    console.log('🔍 Fetching repositories from source GitLab...');
    
    let projects;
    
    if (CONFIG.source.groupId) {
      // Fetch from specific group
      projects = await sourceGitlab.GroupProjects.all(CONFIG.source.groupId, {
        includeSubgroups: true,
        perPage: 100,
        archived: false
      });
      console.log(`✅ Found ${projects.length} repositories in group ${CONFIG.source.groupId}`);
    } else {
      // Fetch all accessible projects
      projects = await sourceGitlab.Projects.all({
        membership: true,
        archived: false,
        perPage: 100
      });
      console.log(`✅ Found ${projects.length} accessible repositories`);
    }
    
    // Upsert to database
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

async function findOrCreateTargetNamespace(sourceNamespacePath) {
  try {
    console.log(`  🔍 Looking for namespace: ${sourceNamespacePath}`);
    
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
    
    // For nested groups, try to match base group
    const pathParts = sourceNamespacePath.split('/');
    const baseGroup = pathParts[0];
    
    targetGroup = groups.find(g => g.path === baseGroup || g.full_path === baseGroup);
    
    if (targetGroup) {
      console.log(`  ✅ Found base namespace: ${targetGroup.full_path} (ID: ${targetGroup.id})`);
      if (pathParts.length > 1) {
        console.warn(`  ⚠️ Source uses nested group "${sourceNamespacePath}" but only found "${targetGroup.full_path}"`);
        console.warn(`  ⚠️ Repo will be created in base group: ${targetGroup.full_path}`);
      }
      return targetGroup.id;
    }
    
    // Group not found - try to create it (single level only)
    if (pathParts.length > 1) {
      console.error(`  ❌ Nested group "${sourceNamespacePath}" not found on target`);
      console.error(`  ❌ Please create this group manually on target GitLab`);
      return null;
    }
    
    // Create single-level group
    console.log(`  ➕ Creating group: ${baseGroup}`);
    const newGroup = await targetGitlab.Groups.create({
      name: baseGroup,
      path: baseGroup,
      visibility: 'private'
    });
    
    console.log(`  ✅ Created group: ${newGroup.full_path} (ID: ${newGroup.id})`);
    return newGroup.id;
    
  } catch (error) {
    console.error(`  ❌ Error finding/creating namespace ${sourceNamespacePath}:`, error.message);
    return null;
  }
}

// ============================================================================
// REPOSITORY SYNC FUNCTION
// ============================================================================

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
  
  // Use temporary directory for clone (ephemeral pod storage)
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
    
    // Get or create target repository
    const pathParts = repo.path.split('/');
    const repoName = pathParts[pathParts.length - 1];
    const namespacePath = pathParts.slice(0, -1).join('/');
    
    console.log(`  📂 Source namespace: ${namespacePath || '(root)'}`);
    
    // Determine target namespace
    let targetNamespaceId = null;
    
    if (CONFIG.target.groupId) {
      targetNamespaceId = CONFIG.target.groupId;
      console.log(`  📂 Using configured target group ID: ${targetNamespaceId}`);
    } else if (namespacePath) {
      targetNamespaceId = await findOrCreateTargetNamespace(namespacePath);
      
      if (!targetNamespaceId) {
        throw new Error(`Namespace "${namespacePath}" not found on target and could not be created`);
      }
    } else {
      throw new Error(`Cannot determine target namespace. Set TARGET_GROUP_ID or ensure groups exist on target.`);
    }
    
    // Try to find existing project
    let targetRepo;
    const targetProjects = await targetGitlab.GroupProjects.all(targetNamespaceId);
    targetRepo = targetProjects.find(p => p.path === repoName);
    
    if (!targetRepo) {
      console.log(`  ➕ Creating target repository ${repo.name}...`);
      targetRepo = await targetGitlab.Projects.create({
        name: repo.name,
        path: repoName,
        description: repo.description,
        visibility: 'private',
        namespaceId: targetNamespaceId
      });
      console.log(`  ✅ Created target repository`);
    }
    
    // Push to target
    console.log(`  📤 Pushing to target...`);
    const repoGit = simpleGit(localPath);
    
    // Construct authenticated target URL
    const targetUrl = new URL(targetRepo.http_url_to_repo);
    targetUrl.username = 'oauth2';
    targetUrl.password = CONFIG.target.token;
    
    // Handle protected branches
    let protectedBranches = [];
    try {
      protectedBranches = await targetGitlab.ProtectedBranches.all(targetRepo.id);
      
      if (protectedBranches.length > 0) {
        console.log(`  🔓 Unprotecting ${protectedBranches.length} branches...`);
        for (const branch of protectedBranches) {
          await targetGitlab.ProtectedBranches.unprotect(targetRepo.id, branch.name);
        }
      }
    } catch (error) {
      console.warn(`  ⚠️ Could not check/unprotect branches: ${error.message}`);
    }
    
    // Push branches and tags (NOT --mirror to avoid hidden refs)
    try {
      await repoGit.push(targetUrl.toString(), '--all');
      console.log(`  ✅ Branches pushed`);
      
      await repoGit.push(targetUrl.toString(), '--tags');
      console.log(`  ✅ Tags pushed`);
    } catch (pushError) {
      console.warn(`  ⚠️ Push warning: ${pushError.message}`);
    }
    
    console.log(`  ✅ Mirror push completed`);
    
    // Re-protect branches
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
    
    const commitCount = 0; // Note: Audit via webhooks, not git log
    updateSyncHistory(syncId, 'success', null, commitCount);
    
    // Clear the "new commits" flag
    db.prepare('UPDATE repositories SET has_new_commits = 0 WHERE id = ?').run(repoId);
    
    console.log(`✅ Successfully synced ${repo.name}`);
    
    emitToClients('sync_completed', {
      repositoryId: repoId,
      repositoryName: repo.name,
      syncId,
      status: 'success',
      commitCount
    });
    
    // Cleanup temporary clone
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
    
    // Cleanup temporary clone even on error
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
    failed: 0
  };
  
  for (const repo of repos) {
    try {
      await syncRepository(repo.id);
      results.success++;
    } catch (error) {
      console.error(`Failed to sync ${repo.name}:`, error.message);
      results.failed++;
    }
  }
  
  console.log(`✅ Sync all completed: ${results.success} success, ${results.failed} failed`);
  
  emitToClients('sync_all_completed', results);
  
  return results;
}

// ============================================================================
// WEBHOOK HANDLING
// ============================================================================

function verifyWebhookSignature(payload, receivedToken) {
  if (!CONFIG.webhookSecret) {
    console.warn('⚠️ No webhook secret configured, skipping verification');
    return true;
  }
  
  if (!receivedToken) {
    console.warn('⚠️ No token received in webhook');
    return false;
  }
  
  return receivedToken === CONFIG.webhookSecret;
}

function emitToClients(event, data) {
  io.emit(event, data);
  console.log(`📡 Emitted ${event}:`, data);
}

// ============================================================================
// API ROUTES
// ============================================================================

// Configuration
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
    syncSchedule: '0 2 * * *'
  });
});

// Get repositories
app.get('/api/repositories', (req, res) => {
  try {
    const repos = getRepositories();
    res.json(repos);
  } catch (error) {
    console.error('Error fetching repositories:', error);
    res.status(500).json({ error: error.message });
  }
});

// Refresh repository list
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

// Webhook endpoint
app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-gitlab-token'];
  
  if (!verifyWebhookSignature(req.body, signature)) {
    console.warn('⚠️ Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  const event = req.headers['x-gitlab-event'];
  const payload = req.body;
  
  console.log(`📨 Received webhook: ${event} (${payload.object_kind || payload.event_name})`);
  
  // Handle Push events from System Hooks or Project Hooks
  const isPushEvent = 
    payload.object_kind === 'push' || 
    payload.event_name === 'push' ||
    event === 'Push Hook';
  
  if (isPushEvent) {
    try {
      const projectName = payload.project?.name || 'Unknown';
      const projectId = payload.project?.id || payload.project_id;
      const ref = payload.ref || '';
      const branch = ref.replace('refs/heads/', '');
      const isForce = payload.total_commits_count === 0 && payload.commits?.length === 0;
      
      console.log(`  📝 Push to ${projectName}/${branch} (${payload.commits?.length || 0} commits)`);
      
      // Find repository in database
      let repoId = null;
      if (projectId) {
        const repo = db.prepare('SELECT id FROM repositories WHERE gitlab_id = ?').get(projectId);
        repoId = repo?.id;
        
        // Mark repository as having new commits
        if (repoId) {
          db.prepare('UPDATE repositories SET has_new_commits = 1 WHERE id = ?').run(repoId);
          
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
        
        emitToClients('audit_updated', {
          repository: projectName,
          branch: branch,
          commits: commitData.length,
          isForce: isForce
        });
      } else if (isForce) {
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
  
  emitToClients('webhook_received', {
    event,
    timestamp: new Date().toISOString()
  });
  
  res.json({ success: true });
});

// Serve frontend
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
// SCHEDULER SETUP
// ============================================================================
let syncTask = null;

function startScheduledSync() {
  if (CONFIG.disableScheduledSync) {
    console.log('⏰ Scheduled sync is DISABLED (DISABLE_SCHEDULED_SYNC=true)');
  } else {
    if (syncTask) {
      syncTask.stop();
    }
    
    const schedule = '0 2 * * *'; // 2 AM daily
    console.log(`⏰ Scheduling sync: ${schedule}`);
    
    syncTask = cron.schedule(schedule, async () => {
      console.log('⏰ Running scheduled sync...');
      try {
        await syncAllRepositories();
      } catch (error) {
        console.error('Scheduled sync error:', error);
      }
    });
  }
  
  // Schedule daily audit log cleanup (3 AM)
  console.log(`🗑️ Scheduling daily audit log cleanup (retention: ${CONFIG.auditRetentionDays} days, runs at 3 AM)`);
  
  cron.schedule('0 3 * * *', () => {
    console.log('🗑️ Running scheduled audit log cleanup...');
    cleanupOldAuditLogs(CONFIG.auditRetentionDays);
  });
}

// ============================================================================
// SERVER STARTUP
// ============================================================================
async function startServer() {
  try {
    // Initialize database
    initializeDatabase();
    
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
║  🚀 GitLab Sync Monitor - Combined Version                    ║
║                                                                ║
║  📡 Server running on port ${CONFIG.port}                              ║
║  💾 Database: ${CONFIG.dbPath}                    ║
║  🔐 Webhook secret: ${CONFIG.webhookSecret ? 'Configured' : 'NOT CONFIGURED'}                        ║
║  🔧 Git SSL verification: DISABLED (self-signed certs)        ║
║  📦 Storage: Temporary /tmp/ (ephemeral)                      ║
║  🗑️  Audit retention: ${CONFIG.auditRetentionDays} days                                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
      `);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  
  if (syncTask) {
    syncTask.stop();
  }
  
  if (db) {
    db.close();
  }
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = { app, server, io };
