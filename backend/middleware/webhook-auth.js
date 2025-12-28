const crypto = require('crypto');
const validator = require('../utils/input-validator');

/**
 * Webhook Authentication Middleware
 * Validates GitLab webhook requests
 */

/**
 * Middleware to validate GitLab webhook secret token
 * Uses constant-time comparison to prevent timing attacks
 */
function validateWebhookSecret(req, res, next) {
  const webhookSecret = process.env.GITLAB_WEBHOOK_SECRET;

  // Check if webhook secret is configured
  if (!webhookSecret) {
    console.error('SECURITY ERROR: GITLAB_WEBHOOK_SECRET not configured');
    return res.status(500).json({ 
      error: 'Webhook authentication not configured' 
    });
  }

  // Get token from header
  const receivedToken = req.headers['x-gitlab-token'];

  if (!receivedToken) {
    console.warn('Webhook received without X-Gitlab-Token header', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString()
    });

    return res.status(401).json({ 
      error: 'Missing X-Gitlab-Token header' 
    });
  }

  // Perform constant-time comparison to prevent timing attacks
  try {
    const expectedToken = Buffer.from(webhookSecret, 'utf8');
    const actualToken = Buffer.from(receivedToken, 'utf8');

    // Check length first (also in constant time)
    if (expectedToken.length !== actualToken.length) {
      console.warn('Webhook authentication failed: invalid token length', {
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      
      return res.status(401).json({ 
        error: 'Invalid webhook token' 
      });
    }

    // Use crypto.timingSafeEqual for constant-time comparison
    const isValid = crypto.timingSafeEqual(expectedToken, actualToken);

    if (!isValid) {
      console.warn('Webhook authentication failed: token mismatch', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
      });

      return res.status(401).json({ 
        error: 'Invalid webhook token' 
      });
    }

    // Authentication successful
    next();
  } catch (error) {
    console.error('Webhook authentication error:', error);
    return res.status(500).json({ 
      error: 'Authentication failed' 
    });
  }
}

/**
 * Middleware to validate webhook payload structure
 */
function validateWebhookPayload(req, res, next) {
  const payload = req.body;

  // Check that we have a payload
  if (!payload || typeof payload !== 'object') {
    console.warn('Webhook received with invalid payload', {
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    return res.status(400).json({ 
      error: 'Invalid webhook payload' 
    });
  }

  // Validate required fields based on GitLab webhook structure
  const requiredFields = ['object_kind', 'project'];

  for (const field of requiredFields) {
    if (!payload[field]) {
      console.warn(`Webhook missing required field: ${field}`, {
        ip: req.ip,
        timestamp: new Date().toISOString()
      });

      return res.status(400).json({ 
        error: `Missing required field: ${field}` 
      });
    }
  }

  // Validate object_kind
  const validObjectKinds = ['push', 'tag_push', 'merge_request'];
  
  if (!validObjectKinds.includes(payload.object_kind)) {
    console.warn(`Webhook with unsupported object_kind: ${payload.object_kind}`, {
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    return res.status(400).json({ 
      error: 'Unsupported webhook event type' 
    });
  }

  // Validate project structure
  if (!payload.project || !payload.project.name || !payload.project.web_url) {
    return res.status(400).json({ 
      error: 'Invalid project information in webhook payload' 
    });
  }

  // Sanitize and validate project name
  try {
    payload.project.name = validator.validateString(
      payload.project.name, 
      255, 
      'project name'
    );
  } catch (error) {
    console.warn('Invalid project name in webhook:', error.message);
    return res.status(400).json({ 
      error: 'Invalid project name: ' + error.message 
    });
  }

  // Validate project URL
  try {
    payload.project.web_url = validator.validateString(
      payload.project.web_url,
      2048,
      'project URL'
    );

    // Basic URL validation
    new URL(payload.project.web_url);
  } catch (error) {
    console.warn('Invalid project URL in webhook:', error.message);
    return res.status(400).json({ 
      error: 'Invalid project URL' 
    });
  }

  // Payload is valid
  next();
}

/**
 * Middleware to log webhook requests
 */
function logWebhookRequest(req, res, next) {
  const payload = req.body;
  
  console.log('Webhook received:', {
    event: payload.object_kind,
    project: payload.project?.name,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    timestamp: new Date().toISOString()
  });

  next();
}

/**
 * Combined webhook validation middleware
 * Use this in your routes
 */
function validateWebhook(req, res, next) {
  // Chain of validation
  validateWebhookSecret(req, res, (err) => {
    if (err) return next(err);
    
    validateWebhookPayload(req, res, (err) => {
      if (err) return next(err);
      
      logWebhookRequest(req, res, next);
    });
  });
}

/**
 * Verify GitLab webhook signature (alternative/additional method)
 * GitLab can also send X-Gitlab-Event header
 */
function verifyGitLabEvent(req, res, next) {
  const gitlabEvent = req.headers['x-gitlab-event'];
  
  if (!gitlabEvent) {
    console.warn('Webhook missing X-Gitlab-Event header');
    return res.status(400).json({ 
      error: 'Missing X-Gitlab-Event header' 
    });
  }

  // Log the event type
  console.log('GitLab event type:', gitlabEvent);

  next();
}

module.exports = {
  validateWebhook,
  validateWebhookSecret,
  validateWebhookPayload,
  logWebhookRequest,
  verifyGitLabEvent
};
