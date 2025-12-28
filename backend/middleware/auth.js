const jwtManager = require('../utils/jwt-manager');

/**
 * Authentication Middleware
 * Protects API endpoints with JWT validation
 */

/**
 * Middleware to require authentication on routes
 * Validates JWT token and attaches user to request
 */
function requireAuth(req, res, next) {
  // Extract token from Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ 
      error: 'Missing authorization header',
      message: 'Please provide a Bearer token in the Authorization header'
    });
  }

  // Extract token
  const token = jwtManager.extractTokenFromHeader(authHeader);

  if (!token) {
    return res.status(401).json({ 
      error: 'Invalid authorization header format',
      message: 'Authorization header must be: Bearer <token>'
    });
  }

  try {
    // Verify token
    const decoded = jwtManager.verifyAccessToken(token);

    // Attach user info to request
    req.user = {
      id: decoded.userId,
      username: decoded.username,
      role: decoded.role,
      sessionId: decoded.sessionId
    };

    // Optionally validate session in database
    // This would require database access in middleware
    // For now, we trust the JWT

    next();
  } catch (error) {
    console.warn('Authentication failed:', {
      error: error.message,
      ip: req.ip,
      path: req.path,
      timestamp: new Date().toISOString()
    });

    return res.status(401).json({ 
      error: 'Authentication failed',
      message: error.message
    });
  }
}

/**
 * Middleware to require admin role
 * Must be used after requireAuth
 */
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required' 
    });
  }

  if (req.user.role !== 'admin') {
    console.warn('Authorization failed: admin required', {
      user: req.user.username,
      role: req.user.role,
      path: req.path,
      timestamp: new Date().toISOString()
    });

    return res.status(403).json({ 
      error: 'Forbidden',
      message: 'Admin access required' 
    });
  }

  next();
}

/**
 * Middleware to require specific role
 * @param {string|string[]} allowedRoles - Role(s) that are allowed
 */
function requireRole(allowedRoles) {
  // Normalize to array
  if (!Array.isArray(allowedRoles)) {
    allowedRoles = [allowedRoles];
  }

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required' 
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      console.warn('Authorization failed: insufficient role', {
        user: req.user.username,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path,
        timestamp: new Date().toISOString()
      });

      return res.status(403).json({ 
        error: 'Forbidden',
        message: `Requires one of: ${allowedRoles.join(', ')}` 
      });
    }

    next();
  };
}

/**
 * Middleware for optional authentication
 * Attaches user if token is valid, but doesn't reject if missing
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // No auth provided, continue without user
    return next();
  }

  const token = jwtManager.extractTokenFromHeader(authHeader);

  if (!token) {
    // Invalid format, continue without user
    return next();
  }

  try {
    const decoded = jwtManager.verifyAccessToken(token);

    req.user = {
      id: decoded.userId,
      username: decoded.username,
      role: decoded.role,
      sessionId: decoded.sessionId
    };
  } catch (error) {
    // Invalid token, but don't reject - just continue without user
    console.debug('Optional auth failed:', error.message);
  }

  next();
}

/**
 * Middleware to validate session is still active in database
 * Requires database manager to be passed in
 */
function requireValidSession(db) {
  return (req, res, next) => {
    if (!req.user || !req.user.sessionId) {
      return res.status(401).json({ 
        error: 'Authentication required' 
      });
    }

    try {
      // Check if session exists and is valid
      const session = db.getSession(req.user.sessionId);

      if (!session) {
        console.warn('Session not found:', {
          sessionId: req.user.sessionId,
          user: req.user.username,
          timestamp: new Date().toISOString()
        });

        return res.status(401).json({ 
          error: 'Session invalid or expired',
          message: 'Please log in again'
        });
      }

      // Check if session belongs to the user
      if (session.user_id !== req.user.id) {
        console.error('Session user mismatch:', {
          sessionUserId: session.user_id,
          tokenUserId: req.user.id,
          timestamp: new Date().toISOString()
        });

        return res.status(401).json({ 
          error: 'Session invalid'
        });
      }

      // Check if session is expired
      const expiresAt = new Date(session.expires_at);
      if (new Date() > expiresAt) {
        console.warn('Session expired:', {
          sessionId: req.user.sessionId,
          expiresAt: expiresAt.toISOString(),
          timestamp: new Date().toISOString()
        });

        // Delete expired session
        db.deleteSession(req.user.sessionId);

        return res.status(401).json({ 
          error: 'Session expired',
          message: 'Please log in again'
        });
      }

      // Attach full session to request
      req.session = session;

      next();
    } catch (error) {
      console.error('Session validation error:', error);
      return res.status(500).json({ 
        error: 'Session validation failed' 
      });
    }
  };
}

/**
 * Middleware to check resource ownership
 * Ensures users can only access their own resources
 */
function requireOwnership(getResourceUserId) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required' 
      });
    }

    try {
      // Get the user ID that owns the resource
      const resourceUserId = await getResourceUserId(req);

      // Admins can access any resource
      if (req.user.role === 'admin') {
        return next();
      }

      // Check if user owns the resource
      if (resourceUserId !== req.user.id) {
        console.warn('Authorization failed: not resource owner', {
          user: req.user.username,
          userId: req.user.id,
          resourceUserId,
          path: req.path,
          timestamp: new Date().toISOString()
        });

        return res.status(403).json({ 
          error: 'Forbidden',
          message: 'You do not have access to this resource'
        });
      }

      next();
    } catch (error) {
      console.error('Ownership check error:', error);
      return res.status(500).json({ 
        error: 'Authorization check failed' 
      });
    }
  };
}

module.exports = {
  requireAuth,
  requireAdmin,
  requireRole,
  optionalAuth,
  requireValidSession,
  requireOwnership
};
