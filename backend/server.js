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
  webhookSecret: process.env.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),
  
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
    
    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_sync_history_repo ON sync_history(repository_id);
    CREATE INDEX IF NOT EXISTS idx_sync_history_status ON sync_history(status);
    CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status);
    CREATE INDEX IF NOT EXISTS idx_repositories_gitlab_id ON repositories(gitlab_id);
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
function verifyWebhookSignature(payload, signature) {
  if (!CONFIG.webhookSecret) return false;
  
  const hmac = crypto.createHmac('sha256', CONFIG.webhookSecret);
  const digest = hmac.update(JSON.stringify(payload)).digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(digest)
  );
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
           sh.error_message as last_sync_error
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
  
  try {
    console.log(`🔄 Starting sync for ${repo.name}...`);
    
    // Sanitize repository name for local path
    const localPath = path.join(CONFIG.reposPath, sanitizeRepoName(repo.path));
    
    // Ensure parent directory exists
    const parentDir = path.dirname(localPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
    
    const git = simpleGit();
    
    // Clone or update local repository
    if (!fs.existsSync(localPath)) {
      console.log(`  📥 Cloning ${repo.name}...`);
      
      // Construct authenticated source URL
      const sourceUrl = new URL(repo.http_url);
      sourceUrl.username = 'oauth2';
      sourceUrl.password = CONFIG.source.token;
      
      await git.clone(sourceUrl.toString(), localPath, {
        '--mirror': null
      });
    } else {
      console.log(`  🔃 Updating ${repo.name}...`);
      const repoGit = simpleGit(localPath);
      await repoGit.fetch(['--all', '--prune']);
    }
    
    // Get target repository or create it
    let targetRepo;
    try {
      if (CONFIG.target.groupId) {
        // Try to find existing project in specific group
        const targetProjects = await targetGitlab.GroupProjects.all(CONFIG.target.groupId);
        targetRepo = targetProjects.find(p => p.path === repo.path.split('/').pop());
      } else {
        // Try to find existing project among all accessible projects
        const targetProjects = await targetGitlab.Projects.all({
          perPage: 100,
          membership: true,
          search: repo.name
        });
        targetRepo = targetProjects.find(p => p.path === repo.path.split('/').pop());
      }
      
      if (!targetRepo) {
        console.log(`  ➕ Creating target repository ${repo.name}...`);
        const createParams = {
          name: repo.name,
          description: repo.description,
          visibility: 'private'
        };
        
        // Add namespace only if group ID is provided
        if (CONFIG.target.groupId) {
          createParams.namespaceId = CONFIG.target.groupId;
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
    
    const log = await repoGit.log();
    const commitCount = log.total || 0;
    
    updateSyncHistory(syncId, 'success', null, commitCount);
    
    console.log(`✅ Successfully synced ${repo.name} (${commitCount} commits)`);
    
    emitToClients('sync_completed', {
      repositoryId: repoId,
      repositoryName: repo.name,
      syncId,
      status: 'success',
      commitCount
    });
    
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

// Webhook endpoint (Phase 2 - for future approval workflow)
app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-gitlab-token'];
  
  if (!verifyWebhookSignature(req.body, signature)) {
    console.warn('⚠️ Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  const event = req.headers['x-gitlab-event'];
  console.log(`📨 Received webhook: ${event}`);
  
  // Phase 2: Handle webhook for approval workflow
  // For now, just log it
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
