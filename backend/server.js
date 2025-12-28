require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cron = require('node-cron');

// Security utilities
const validator = require('./utils/input-validator');
const passwordValidator = require('./utils/password-validator');
const jwtManager = require('./utils/jwt-manager');

// Middleware
const { requireAuth, requireAdmin } = require('./middleware/auth');
const { validateWebhook } = require('./middleware/webhook-auth');
const { 
  apiLimiter, 
  authLimiter, 
  webhookLimiter, 
  strictLimiter 
} = require('./middleware/rate-limit');

// Services
const DatabaseManager = require('./database-secure');
const GitLabService = require('./gitlab-service');
const SecureSyncEngine = require('./sync-engine-secure');

// Initialize Express
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE']
  }
});

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "ws:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Additional security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Cache control for API
  if (req.path.startsWith('/api')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  
  next();
});

// CORS
app.use(cors());

// Body parser with size limits
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Logging (sanitized)
morgan.token('sanitized-body', (req) => {
  if (req.body && Object.keys(req.body).length > 0) {
    const sanitized = validator.sanitizeForLog(req.body);
    return JSON.stringify(sanitized);
  }
  return '-';
});

app.use(morgan(':method :url :status :response-time ms - :sanitized-body'));

// Initialize database
const db = new DatabaseManager(process.env.DB_PATH || '/data/sync-monitor.db');

// Initialize sync engine
const syncEngine = new SecureSyncEngine(db);

// Apply global API rate limiting
app.use('/api', apiLimiter);

// Scheduler
let scheduledTask = null;

// ==========================================
// HEALTH & STATUS ENDPOINTS
// ==========================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    database: 'connected'
  });
});

app.get('/api/status', requireAuth, (req, res) => {
  res.json({
    status: 'running',
    version: '2.0.0',
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role
    },
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Register new user
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Validate inputs
    validator.validateUsername(username);
    validator.validateEmail(email);
    passwordValidator.validate(password);
    passwordValidator.validateAgainstUsername(password, username);

    // Hash password
    const passwordHash = await passwordValidator.hash(password);

    // Create user
    const userId = db.createUser({
      username,
      email,
      password_hash: passwordHash,
      role: role === 'admin' ? 'admin' : 'user' // Only allow admin if explicitly set
    });

    // Log audit
    db.createAuditLog({
      userId: userId,
      action: 'USER_REGISTERED',
      resource_type: 'user',
      resource_id: userId.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({ 
      success: true, 
      userId,
      message: 'User created successfully' 
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Get user
    const user = db.getUserByUsername(username);
    
    if (!user) {
      // Log failed attempt
      db.createAuditLog({
        action: 'LOGIN_FAILED',
        resource_type: 'auth',
        details: `Failed login attempt for username: ${username}`,
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValid = await passwordValidator.verify(password, user.password_hash);
    
    if (!isValid) {
      // Log failed attempt
      db.createAuditLog({
        userId: user.id,
        action: 'LOGIN_FAILED',
        resource_type: 'auth',
        details: 'Invalid password',
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if password needs rehashing
    if (passwordValidator.needsRehash(user.password_hash)) {
      const newHash = await passwordValidator.hash(password);
      db.updateUserPassword(user.id, newHash);
    }

    // Generate session
    const sessionId = jwtManager.generateSessionId();
    
    // Create session in database
    db.createSession({
      sessionId,
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
    });

    // Generate tokens
    const tokens = jwtManager.generateTokenPair(user, sessionId);

    // Log successful login
    db.createAuditLog({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      resource_type: 'auth',
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/auth/logout', requireAuth, (req, res) => {
  try {
    // Delete session
    db.deleteSession(req.user.sessionId);
    
    // Log logout
    db.createAuditLog({
      userId: req.user.id,
      action: 'LOGOUT',
      resource_type: 'auth',
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = jwtManager.verifyRefreshToken(refreshToken);
    
    // Check session still valid
    const session = db.getSession(decoded.sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired' });
    }

    // Get user
    const user = db.getUserById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Generate new access token
    const accessToken = jwtManager.generateAccessToken(user, decoded.sessionId);

    res.json({
      success: true,
      accessToken,
      expiresIn: 900 // 15 minutes
    });
  } catch (error) {
    console.error('Token refresh error:', error.message);
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

// ==========================================
// CONFIGURATION ENDPOINTS
// ==========================================

// Get configuration
app.get('/api/config', requireAuth, (req, res) => {
  try {
    const config = db.getConfig();
    
    // NEVER send tokens to client
    if (config) {
      delete config.source_token;
      delete config.target_token;
    }
    
    res.json(config || {});
  } catch (error) {
    console.error('Error fetching config:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Update configuration
app.post('/api/config', requireAuth, requireAdmin, strictLimiter, async (req, res) => {
  try {
    const config = req.body;

    // Validate required fields
    validator.validateString(config.source_gitlab_url, 2048, 'source_gitlab_url');
    validator.validateString(config.target_gitlab_url, 2048, 'target_gitlab_url');

    // Validate cron expression if provided
    if (config.cron_schedule) {
      validator.validateCronExpression(config.cron_schedule);
      
      if (!cron.validate(config.cron_schedule)) {
        return res.status(400).json({ error: 'Invalid cron schedule expression' });
      }
    }

    // Save configuration (tokens come from env vars, not request)
    db.upsertConfig({
      source_gitlab_url: config.source_gitlab_url,
      source_group_id: config.source_group_id || null,
      target_gitlab_url: config.target_gitlab_url,
      target_group_id: config.target_group_id || null,
      cron_schedule: config.cron_schedule || '0 */6 * * *',
      retry_attempts: config.retry_attempts || 3,
      retry_delay_seconds: config.retry_delay_seconds || 60,
      enabled: config.enabled !== undefined ? (config.enabled ? 1 : 0) : 1
    });

    // Log configuration change
    db.createAuditLog({
      userId: req.user.id,
      action: 'CONFIG_UPDATED',
      resource_type: 'config',
      details: JSON.stringify({ cron_schedule: config.cron_schedule }),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Update scheduler
    setupScheduler();

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating config:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ==========================================
// WEBHOOK ENDPOINT
// ==========================================

app.post('/api/webhook', webhookLimiter, validateWebhook, async (req, res) => {
  try {
    const payload = req.body;
    
    // Create pending repository from webhook
    const repoId = db.createPendingRepository({
      repository_id: payload.project.id.toString(),
      repository_name: payload.project.name,
      repository_url: payload.project.http_url_to_repo || payload.project.web_url,
      event_type: payload.object_kind,
      author_name: payload.user_name || payload.user?.name,
      author_email: payload.user_email || payload.user?.email,
      commit_message: payload.commits?.[0]?.message,
      commit_sha: payload.commits?.[0]?.id,
      webhook_payload: JSON.stringify(payload)
    });

    // Emit to connected clients
    io.emit('new_pending_repository', {
      id: repoId,
      repository: payload.project.name,
      author: payload.user_name || payload.user?.name,
      event: payload.object_kind,
      timestamp: new Date().toISOString()
    });

    console.log('Webhook processed:', {
      repository: payload.project.name,
      event: payload.object_kind,
      id: repoId
    });

    res.json({ success: true, id: repoId });
  } catch (error) {
    console.error('Webhook processing error:', error.message);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

// ==========================================
// PENDING REPOSITORIES ENDPOINTS
// ==========================================

// Get pending repositories
app.get('/api/pending', requireAuth, (req, res) => {
  try {
    const status = req.query.status || 'pending';
    
    // Validate status
    validator.validateEnum(
      status,
      ['pending', 'approved', 'declined', 'synced', 'failed'],
      'status'
    );

    const repos = db.getPendingRepositories(status);
    res.json(repos);
  } catch (error) {
    console.error('Error fetching pending repos:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Approve repository
app.post('/api/pending/:id/approve', requireAuth, strictLimiter, async (req, res) => {
  try {
    const id = validator.validateId(req.params.id);

    // Update status
    db.updatePendingRepository(id, {
      status: 'approved',
      approved_by: req.user.id,
      approved_at: new Date().toISOString()
    });

    // Log approval
    db.createAuditLog({
      userId: req.user.id,
      action: 'REPOSITORY_APPROVED',
      resource_type: 'pending_repository',
      resource_id: id.toString(),
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Emit to connected clients
    io.emit('repository_approved', { id });

    res.json({ success: true });
  } catch (error) {
    console.error('Error approving repository:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Decline repository
app.post('/api/pending/:id/decline', requireAuth, strictLimiter, async (req, res) => {
  try {
    const id = validator.validateId(req.params.id);
    const { reason } = req.body;

    // Update status
    db.updatePendingRepository(id, {
      status: 'declined',
      declined_by: req.user.id,
      declined_at: new Date().toISOString(),
      decline_reason: reason || null
    });

    // Log decline
    db.createAuditLog({
      userId: req.user.id,
      action: 'REPOSITORY_DECLINED',
      resource_type: 'pending_repository',
      resource_id: id.toString(),
      details: reason,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Emit to connected clients
    io.emit('repository_declined', { id });

    res.json({ success: true });
  } catch (error) {
    console.error('Error declining repository:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ==========================================
// SYNC ENDPOINTS
// ==========================================

// Get sync history
app.get('/api/sync/history', requireAuth, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.offset) || 0;

    const history = db.getSyncHistory(limit, offset);
    res.json(history);
  } catch (error) {
    console.error('Error fetching sync history:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get sync details
app.get('/api/sync/:id', requireAuth, (req, res) => {
  try {
    const id = validator.validateId(req.params.id);

    const sync = db.getSyncById(id);
    if (!sync) {
      return res.status(404).json({ error: 'Sync not found' });
    }

    const details = db.getRepoSyncDetailsBySyncId(id);
    const logs = db.getSyncLogs(id);

    res.json({
      ...sync,
      details,
      logs
    });
  } catch (error) {
    console.error('Error fetching sync details:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Trigger manual sync
app.post('/api/sync/manual', requireAuth, strictLimiter, async (req, res) => {
  try {
    // Log sync trigger
    db.createAuditLog({
      userId: req.user.id,
      action: 'MANUAL_SYNC_TRIGGERED',
      resource_type: 'sync',
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Run sync in background
    runSync().catch(error => {
      console.error('Manual sync error:', error);
    });

    res.json({ 
      success: true,
      message: 'Sync started' 
    });
  } catch (error) {
    console.error('Error triggering manual sync:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// AUDIT LOG ENDPOINTS
// ==========================================

app.get('/api/audit', requireAuth, requireAdmin, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;

    const logs = db.getAuditLogs(limit, offset);
    res.json(logs);
  } catch (error) {
    console.error('Error fetching audit logs:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// SYNC ENGINE
// ==========================================

async function runSync() {
  console.log('Starting sync operation...');

  try {
    // Validate prerequisites
    const validation = await syncEngine.validatePrerequisites();
    if (!validation.valid) {
      console.error('Sync prerequisites not met:', validation.errors);
      throw new Error('Prerequisites not met: ' + validation.errors.join(', '));
    }

    // Get config
    const config = db.getConfig();
    if (!config || !config.enabled) {
      console.log('Sync disabled or not configured');
      return;
    }

    // Get tokens from environment (NEVER from database)
    const sourceToken = process.env.SOURCE_GITLAB_TOKEN;
    const targetToken = process.env.TARGET_GITLAB_TOKEN;

    if (!sourceToken || !targetToken) {
      throw new Error('GitLab tokens not configured in environment');
    }

    // Initialize GitLab service
    const gitlabService = new GitLabService(config.source_gitlab_url, sourceToken);

    // Get repositories
    const repositories = await gitlabService.getGroupRepositories(config.source_group_id);

    console.log(`Found ${repositories.length} repositories to sync`);

    // Emit sync started event
    io.emit('sync_started', {
      total: repositories.length,
      timestamp: new Date().toISOString()
    });

    // Perform sync
    const results = await syncEngine.performFullSync(repositories, sourceToken, targetToken);

    // Emit sync completed event
    io.emit('sync_completed', {
      ...results,
      timestamp: new Date().toISOString()
    });

    console.log('Sync completed:', results);

    return results;
  } catch (error) {
    console.error('Sync error:', error.message);
    
    io.emit('sync_failed', {
      error: error.message,
      timestamp: new Date().toISOString()
    });

    throw error;
  }
}

// ==========================================
// SCHEDULER
// ==========================================

function setupScheduler() {
  // Stop existing task
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }

  const config = db.getConfig();
  
  if (!config || !config.enabled) {
    console.log('Scheduler disabled');
    return;
  }

  const schedule = config.cron_schedule || '0 */6 * * *';
  
  if (!cron.validate(schedule)) {
    console.error('Invalid cron schedule:', schedule);
    return;
  }

  scheduledTask = cron.schedule(schedule, () => {
    console.log('Running scheduled sync at', new Date().toISOString());
    runSync().catch(error => {
      console.error('Scheduled sync error:', error.message);
    });
  });

  console.log('Scheduler configured with schedule:', schedule);
}

// Initialize scheduler on startup
setupScheduler();

// ==========================================
// WEBSOCKET
// ==========================================

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ==========================================
// ERROR HANDLING
// ==========================================

// 404 handler
app.get('/', (req, res) => { return res.redirect('/api'); });
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((error, req, res, next) => {
  // Log full error server-side
  console.error('Error:', {
    message: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    user: req.user?.username,
    ip: req.ip
  });
  
  // Send sanitized error to client
  const isProduction = process.env.NODE_ENV === 'production';
  
  res.status(error.status || 500).json({
    error: isProduction ? 'Internal server error' : error.message,
    ...(isProduction ? {} : { stack: error.stack })
  });
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('GitLab Sync Monitor - Secure v2.0.0');
  console.log('========================================');
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DB_PATH || '/data/sync-monitor.db'}`);
  console.log('========================================');
});

// ==========================================
// GRACEFUL SHUTDOWN
// ==========================================

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  
  if (scheduledTask) {
    scheduledTask.stop();
  }
  
  db.close();
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = { app, server, io };
