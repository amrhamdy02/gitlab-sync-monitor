const { URL } = require('url');
const path = require('path');
const crypto = require('crypto');

/**
 * Input Validation Utility
 * Prevents: Command Injection, Path Traversal, SQL Injection
 */
class InputValidator {
  constructor() {
    // Whitelist of allowed GitLab domains
    this.allowedDomains = (process.env.ALLOWED_GITLAB_DOMAINS || '').split(',').filter(Boolean);
    
    if (this.allowedDomains.length === 0) {
      console.warn('WARNING: No ALLOWED_GITLAB_DOMAINS configured. All domains will be rejected.');
    }
    
    console.log('Allowed GitLab domains:', this.allowedDomains);
  }

  /**
   * Validate Git URL to prevent command injection
   * @param {string} url - Git URL to validate
   * @returns {string} Validated URL
   * @throws {Error} If URL is invalid
   */
  validateGitUrl(url) {
    if (!url || typeof url !== 'string') {
      throw new Error('Git URL is required');
    }

    // Remove whitespace
    url = url.trim();

    // Basic format validation - must end in .git
    const gitUrlPattern = /^https:\/\/[a-zA-Z0-9.-]+\/[\w\/-]+\.git$/;
    
    if (!gitUrlPattern.test(url)) {
      throw new Error('Invalid Git URL format. Must be: https://domain/path/repo.git');
    }

    // Parse URL
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (error) {
      throw new Error('Malformed URL');
    }

    // Check protocol - only HTTPS allowed
    if (urlObj.protocol !== 'https:') {
      throw new Error('Only HTTPS protocol is allowed');
    }

    // Check domain whitelist
    if (!this.allowedDomains.includes(urlObj.hostname)) {
      throw new Error(
        `Domain '${urlObj.hostname}' is not in the allowed list. ` +
        `Allowed domains: ${this.allowedDomains.join(', ')}`
      );
    }

    // Check for command injection attempts
    const suspiciousChars = ['`', '$', ';', '|', '&', '\n', '\r', '$(', '${'];
    for (const char of suspiciousChars) {
      if (url.includes(char)) {
        throw new Error(`URL contains suspicious character: '${char}'`);
      }
    }

    // Check for shell metacharacters in path
    const urlPath = urlObj.pathname;
    if (/[<>"|*?]/.test(urlPath)) {
      throw new Error('URL path contains invalid characters');
    }

    return url;
  }

  /**
   * Validate repository name to prevent path traversal
   * @param {string} name - Repository name
   * @returns {string} Sanitized name
   * @throws {Error} If name is invalid
   */
  validateRepositoryName(name) {
    if (!name || typeof name !== 'string') {
      throw new Error('Repository name is required');
    }

    // Remove leading/trailing whitespace
    name = name.trim();

    // Check length
    if (name.length === 0) {
      throw new Error('Repository name cannot be empty');
    }

    if (name.length > 255) {
      throw new Error('Repository name too long (max 255 characters)');
    }

    // Allow only safe characters: alphanumeric, hyphen, underscore
    // No dots, slashes, or other special characters
    const safePattern = /^[a-zA-Z0-9_-]+$/;
    
    if (!safePattern.test(name)) {
      throw new Error(
        'Repository name can only contain letters, numbers, hyphens, and underscores'
      );
    }

    // Prevent directory traversal attempts
    if (name.includes('..') || name === '.' || name === '..') {
      throw new Error('Invalid repository name: directory traversal detected');
    }

    // Prevent names starting with hyphen (could be interpreted as command flag)
    if (name.startsWith('-')) {
      throw new Error('Repository name cannot start with a hyphen');
    }

    return name;
  }

  /**
   * Validate and sanitize file path to prevent traversal
   * @param {string} filePath - File path to validate
   * @param {string} allowedBase - Base directory that must contain the path
   * @returns {string} Validated absolute path
   * @throws {Error} If path escapes allowed directory
   */
  validateFilePath(filePath, allowedBase) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('File path is required');
    }

    if (!allowedBase || typeof allowedBase !== 'string') {
      throw new Error('Allowed base directory is required');
    }

    // Resolve to absolute paths
    const resolvedPath = path.resolve(filePath);
    const resolvedBase = path.resolve(allowedBase);

    // Ensure path is within allowed directory
    if (!resolvedPath.startsWith(resolvedBase)) {
      throw new Error(
        'Path traversal attempt detected. Path must be within allowed directory.'
      );
    }

    // Additional check for null bytes
    if (filePath.includes('\0')) {
      throw new Error('Path contains null byte');
    }

    return resolvedPath;
  }

  /**
   * Create a safe temporary directory for Git operations
   * @param {string} repoName - Repository name
   * @returns {string} Safe absolute path
   */
  createSafeClonePath(repoName) {
    // Validate repository name first
    const safeName = this.validateRepositoryName(repoName);
    
    // Base directory for clones
    const baseDir = process.env.GIT_CLONE_BASE || '/tmp/git-clones';
    
    // Create unique subdirectory using UUID
    const uniqueId = crypto.randomUUID();
    const fullPath = path.join(baseDir, uniqueId, safeName);
    
    // Validate the constructed path
    const safePath = this.validateFilePath(fullPath, baseDir);
    
    return safePath;
  }

  /**
   * Validate database ID parameter
   * @param {*} id - ID to validate
   * @returns {number} Validated integer ID
   * @throws {Error} If ID is invalid
   */
  validateId(id) {
    const numId = parseInt(id, 10);
    
    if (!Number.isInteger(numId) || numId < 1) {
      throw new Error('Invalid ID: must be a positive integer');
    }
    
    if (numId > Number.MAX_SAFE_INTEGER) {
      throw new Error('Invalid ID: too large');
    }
    
    return numId;
  }

  /**
   * Validate enum value against allowed list
   * @param {string} value - Value to validate
   * @param {string[]} allowedValues - List of allowed values
   * @param {string} fieldName - Field name for error messages
   * @returns {string} Validated value
   * @throws {Error} If value not in allowed list
   */
  validateEnum(value, allowedValues, fieldName = 'value') {
    if (!allowedValues.includes(value)) {
      throw new Error(
        `Invalid ${fieldName}. Allowed values: ${allowedValues.join(', ')}`
      );
    }
    return value;
  }

  /**
   * Validate and sanitize string input
   * @param {string} input - Input to validate
   * @param {number} maxLength - Maximum allowed length
   * @param {string} fieldName - Field name for error messages
   * @returns {string} Validated string
   * @throws {Error} If input is invalid
   */
  validateString(input, maxLength = 255, fieldName = 'input') {
    if (typeof input !== 'string') {
      throw new Error(`${fieldName} must be a string`);
    }

    // Remove leading/trailing whitespace
    input = input.trim();

    if (input.length === 0) {
      throw new Error(`${fieldName} cannot be empty`);
    }

    if (input.length > maxLength) {
      throw new Error(`${fieldName} exceeds maximum length of ${maxLength}`);
    }

    // Check for null bytes
    if (input.includes('\0')) {
      throw new Error(`${fieldName} contains null byte`);
    }

    return input;
  }

  /**
   * Validate email address
   * @param {string} email - Email to validate
   * @returns {string} Validated email
   * @throws {Error} If email is invalid
   */
  validateEmail(email) {
    if (!email || typeof email !== 'string') {
      throw new Error('Email is required');
    }

    email = email.trim().toLowerCase();

    // Basic email validation
    const emailPattern = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
    
    if (!emailPattern.test(email)) {
      throw new Error('Invalid email address');
    }

    if (email.length > 320) { // RFC 5321
      throw new Error('Email address too long');
    }

    return email;
  }

  /**
   * Validate username
   * @param {string} username - Username to validate
   * @returns {string} Validated username
   * @throws {Error} If username is invalid
   */
  validateUsername(username) {
    if (!username || typeof username !== 'string') {
      throw new Error('Username is required');
    }

    username = username.trim();

    // Username rules: 3-32 characters, alphanumeric + underscore
    if (username.length < 3 || username.length > 32) {
      throw new Error('Username must be 3-32 characters');
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      throw new Error('Username can only contain letters, numbers, and underscores');
    }

    // Must start with a letter
    if (!/^[a-zA-Z]/.test(username)) {
      throw new Error('Username must start with a letter');
    }

    return username;
  }

  /**
   * Validate cron expression
   * @param {string} cron - Cron expression to validate
   * @returns {string} Validated cron expression
   * @throws {Error} If cron expression is invalid
   */
  validateCronExpression(cron) {
    if (!cron || typeof cron !== 'string') {
      throw new Error('Cron expression is required');
    }

    cron = cron.trim();

    // Basic cron validation (5 fields)
    const parts = cron.split(/\s+/);
    
    if (parts.length !== 5) {
      throw new Error('Cron expression must have 5 fields');
    }

    // Additional validation would require cron-parser library
    // For now, just ensure no suspicious characters
    if (/[;&|`$()]/.test(cron)) {
      throw new Error('Cron expression contains invalid characters');
    }

    return cron;
  }

  /**
   * Sanitize log output to prevent log injection
   * @param {string} input - Input to sanitize
   * @returns {string} Sanitized string
   */
  sanitizeLogOutput(input) {
    if (typeof input !== 'string') {
      input = String(input);
    }

    // Remove control characters including newlines
    return input.replace(/[\x00-\x1F\x7F]/g, '');
  }

  /**
   * Sanitize object for logging (remove sensitive fields)
   * @param {object} obj - Object to sanitize
   * @returns {object} Sanitized object
   */
  sanitizeForLog(obj) {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const sanitized = Array.isArray(obj) ? [...obj] : { ...obj };
    const sensitiveKeys = [
      'token', 'password', 'secret', 'authorization',
      'source_token', 'target_token', 'jwt_secret',
      'webhook_secret', 'api_key', 'private_key'
    ];

    const sanitizeRecursive = (obj) => {
      if (!obj || typeof obj !== 'object') {
        return obj;
      }

      if (Array.isArray(obj)) {
        return obj.map(item => sanitizeRecursive(item));
      }

      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        // Check if key contains sensitive term
        const isSensitive = sensitiveKeys.some(k => 
          key.toLowerCase().includes(k)
        );

        if (isSensitive) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object') {
          result[key] = sanitizeRecursive(value);
        } else {
          result[key] = value;
        }
      }

      return result;
    };

    return sanitizeRecursive(sanitized);
  }
}

// Export singleton instance
module.exports = new InputValidator();
