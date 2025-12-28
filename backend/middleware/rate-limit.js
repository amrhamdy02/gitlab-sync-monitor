const rateLimit = require('express-rate-limit');

/**
 * Rate Limiting Configuration
 * Prevents brute force, DoS, and API abuse
 */

/**
 * Strict rate limiter for authentication endpoints
 * Prevents brute force attacks
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many login attempts',
    message: 'Please try again in 15 minutes',
    retryAfter: 900 // seconds
  },
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  skipSuccessfulRequests: true, // Don't count successful logins
  skipFailedRequests: false, // Count failed attempts
  
  // Custom key generator - rate limit by IP + username
  keyGenerator: (req) => {
    const username = req.body?.username || 'unknown';
    return `${req.ip}-${username}`;
  },
  
  // Custom handler for when limit is exceeded
  handler: (req, res) => {
    console.warn('Rate limit exceeded for login', {
      ip: req.ip,
      username: req.body?.username,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'Too many login attempts',
      message: 'Please try again in 15 minutes'
    });
  }
});

/**
 * Webhook rate limiter
 * Prevents webhook flooding
 */
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 webhooks per minute
  message: {
    error: 'Webhook rate limit exceeded',
    message: 'Too many webhook requests'
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    // Rate limit by IP and project name
    const projectName = req.body?.project?.name || 'unknown';
    return `${req.ip}-${projectName}`;
  },
  
  handler: (req, res) => {
    console.warn('Webhook rate limit exceeded', {
      ip: req.ip,
      project: req.body?.project?.name,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'Webhook rate limit exceeded',
      message: 'Too many webhook requests'
    });
  }
});

/**
 * General API rate limiter
 * Prevents API abuse
 */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: {
    error: 'API rate limit exceeded',
    message: 'Too many requests'
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  // Skip rate limiting for certain paths
  skip: (req) => {
    const skipPaths = ['/health', '/api/health'];
    return skipPaths.includes(req.path);
  },
  
  handler: (req, res) => {
    console.warn('API rate limit exceeded', {
      ip: req.ip,
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'API rate limit exceeded',
      message: 'Too many requests. Please slow down.'
    });
  }
});

/**
 * Strict rate limiter for sensitive operations
 * Used for config changes, manual sync triggers, etc.
 */
const strictLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: {
    error: 'Rate limit exceeded',
    message: 'Too many requests for this operation'
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  handler: (req, res) => {
    console.warn('Strict rate limit exceeded', {
      ip: req.ip,
      path: req.path,
      user: req.user?.username,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests. Please wait before trying again.'
    });
  }
});

/**
 * Registration rate limiter
 * Prevents account creation spam
 */
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per hour per IP
  message: {
    error: 'Too many accounts created',
    message: 'Please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  
  handler: (req, res) => {
    console.warn('Registration rate limit exceeded', {
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'Too many accounts created',
      message: 'Registration limit reached. Please try again later.'
    });
  }
});

/**
 * Password reset rate limiter
 * Prevents password reset spam
 */
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 reset attempts per hour
  message: {
    error: 'Too many password reset attempts',
    message: 'Please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    // Rate limit by IP + email
    const email = req.body?.email || 'unknown';
    return `${req.ip}-${email}`;
  },
  
  handler: (req, res) => {
    console.warn('Password reset rate limit exceeded', {
      ip: req.ip,
      email: req.body?.email,
      timestamp: new Date().toISOString()
    });
    
    res.status(429).json({
      error: 'Too many password reset attempts',
      message: 'Please try again in an hour'
    });
  }
});

/**
 * Create a custom rate limiter with specific options
 * @param {object} options - Rate limiter options
 * @returns {function} Rate limiter middleware
 */
function createCustomLimiter(options) {
  return rateLimit({
    windowMs: options.windowMs || 60 * 1000,
    max: options.max || 100,
    message: options.message || { error: 'Rate limit exceeded' },
    standardHeaders: true,
    legacyHeaders: false,
    ...options
  });
}

module.exports = {
  authLimiter,
  webhookLimiter,
  apiLimiter,
  strictLimiter,
  registrationLimiter,
  passwordResetLimiter,
  createCustomLimiter
};
