const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * JWT Manager for secure token generation and verification
 * Implements best practices for JWT security
 */
class JWTManager {
  constructor() {
    // Load secrets from environment
    this.accessSecret = process.env.JWT_SECRET;
    this.refreshSecret = process.env.JWT_REFRESH_SECRET;

    // Validate secrets are configured
    if (!this.accessSecret || this.accessSecret.length < 32) {
      throw new Error(
        'JWT_SECRET must be set and at least 32 characters. ' +
        'Generate with: openssl rand -hex 64'
      );
    }

    if (!this.refreshSecret || this.refreshSecret.length < 32) {
      throw new Error(
        'JWT_REFRESH_SECRET must be set and at least 32 characters. ' +
        'Generate with: openssl rand -hex 64'
      );
    }

    // Token expiration times
    this.accessTokenExpiry = '15m'; // 15 minutes
    this.refreshTokenExpiry = '7d'; // 7 days

    // JWT options
    this.issuer = 'gitlab-sync-monitor';
    this.audience = 'sync-monitor-api';
    this.algorithm = 'HS256';

    console.log('JWT Manager initialized');
  }

  /**
   * Generate an access token
   * @param {object} user - User object
   * @param {string} sessionId - Session ID
   * @returns {string} JWT access token
   */
  generateAccessToken(user, sessionId) {
    if (!user || !user.id) {
      throw new Error('User object with id is required');
    }

    if (!sessionId) {
      throw new Error('Session ID is required');
    }

    const payload = {
      userId: user.id,
      username: user.username,
      role: user.role || 'user',
      sessionId: sessionId,
      type: 'access'
    };

    try {
      const token = jwt.sign(payload, this.accessSecret, {
        expiresIn: this.accessTokenExpiry,
        algorithm: this.algorithm,
        issuer: this.issuer,
        audience: this.audience,
        jwtid: crypto.randomUUID() // Unique token ID
      });

      return token;
    } catch (error) {
      throw new Error('Failed to generate access token: ' + error.message);
    }
  }

  /**
   * Generate a refresh token
   * @param {object} user - User object
   * @param {string} sessionId - Session ID
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(user, sessionId) {
    if (!user || !user.id) {
      throw new Error('User object with id is required');
    }

    if (!sessionId) {
      throw new Error('Session ID is required');
    }

    const payload = {
      userId: user.id,
      sessionId: sessionId,
      type: 'refresh'
    };

    try {
      const token = jwt.sign(payload, this.refreshSecret, {
        expiresIn: this.refreshTokenExpiry,
        algorithm: this.algorithm,
        issuer: this.issuer,
        audience: this.audience,
        jwtid: crypto.randomUUID()
      });

      return token;
    } catch (error) {
      throw new Error('Failed to generate refresh token: ' + error.message);
    }
  }

  /**
   * Generate both access and refresh tokens
   * @param {object} user - User object
   * @param {string} sessionId - Session ID
   * @returns {object} Object with accessToken and refreshToken
   */
  generateTokenPair(user, sessionId) {
    return {
      accessToken: this.generateAccessToken(user, sessionId),
      refreshToken: this.generateRefreshToken(user, sessionId),
      expiresIn: 900 // 15 minutes in seconds
    };
  }

  /**
   * Verify an access token
   * @param {string} token - JWT token to verify
   * @returns {object} Decoded token payload
   * @throws {Error} If token is invalid
   */
  verifyAccessToken(token) {
    if (!token || typeof token !== 'string') {
      throw new Error('Token is required');
    }

    try {
      const decoded = jwt.verify(token, this.accessSecret, {
        algorithms: [this.algorithm], // Explicitly deny 'none' algorithm
        issuer: this.issuer,
        audience: this.audience,
        complete: false
      });

      // Verify token type
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      } else if (error.name === 'NotBeforeError') {
        throw new Error('Token not yet valid');
      } else {
        throw new Error('Token verification failed: ' + error.message);
      }
    }
  }

  /**
   * Verify a refresh token
   * @param {string} token - JWT refresh token to verify
   * @returns {object} Decoded token payload
   * @throws {Error} If token is invalid
   */
  verifyRefreshToken(token) {
    if (!token || typeof token !== 'string') {
      throw new Error('Token is required');
    }

    try {
      const decoded = jwt.verify(token, this.refreshSecret, {
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience,
        complete: false
      });

      // Verify token type
      if (decoded.type !== 'refresh') {
        throw new Error('Not a refresh token');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      } else {
        throw new Error('Token verification failed: ' + error.message);
      }
    }
  }

  /**
   * Decode token without verifying (use cautiously)
   * @param {string} token - JWT token
   * @returns {object} Decoded token payload
   */
  decode(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get expiry time from token
   * @param {string} token - JWT token
   * @returns {Date|null} Expiry date or null if invalid
   */
  getExpiry(token) {
    const decoded = this.decode(token);
    
    if (!decoded || !decoded.exp) {
      return null;
    }

    return new Date(decoded.exp * 1000);
  }

  /**
   * Check if token is expired
   * @param {string} token - JWT token
   * @returns {boolean} True if expired
   */
  isExpired(token) {
    const expiry = this.getExpiry(token);
    
    if (!expiry) {
      return true;
    }

    return new Date() > expiry;
  }

  /**
   * Get remaining time until token expires
   * @param {string} token - JWT token
   * @returns {number} Milliseconds until expiry, or 0 if expired/invalid
   */
  getTimeUntilExpiry(token) {
    const expiry = this.getExpiry(token);
    
    if (!expiry) {
      return 0;
    }

    const remaining = expiry.getTime() - Date.now();
    return Math.max(0, remaining);
  }

  /**
   * Generate a secure session ID
   * @returns {string} UUID v4 session ID
   */
  generateSessionId() {
    return crypto.randomUUID();
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} Extracted token or null
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader || typeof authHeader !== 'string') {
      return null;
    }

    // Check for Bearer token
    const parts = authHeader.split(' ');
    
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Validate token structure without verifying signature
   * @param {string} token - Token to validate
   * @returns {boolean} True if structure is valid
   */
  hasValidStructure(token) {
    if (!token || typeof token !== 'string') {
      return false;
    }

    // JWT should have 3 parts separated by dots
    const parts = token.split('.');
    
    if (parts.length !== 3) {
      return false;
    }

    // Each part should be base64url encoded
    try {
      for (const part of parts) {
        Buffer.from(part, 'base64');
      }
      return true;
    } catch (error) {
      return false;
    }
  }
}

// Export singleton instance
module.exports = new JWTManager();
