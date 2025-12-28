const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

/**
 * Password Validation and Hashing Utility
 * Enforces strong password policies
 */
class PasswordValidator {
  constructor() {
    this.minLength = 12;
    this.maxLength = 128;
    this.bcryptRounds = 12; // Good balance of security and performance
    
    // Load common passwords list (10k most common)
    this.commonPasswords = new Set();
    this.loadCommonPasswords();
  }

  loadCommonPasswords() {
    try {
      // In production, load from file
      // For now, include top 100 most common
      const common = [
        'password', '123456', '123456789', '12345678', '12345', '1234567',
        'password1', '1234567890', 'abc123', 'qwerty', 'monkey', '1234',
        'letmein', 'trustno1', 'dragon', 'baseball', '111111', 'iloveyou',
        'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
        'superman', 'qazwsx', 'michael', 'football', 'welcome', 'jesus',
        'ninja', 'mustang', 'password123', 'admin', 'administrator',
        'root', 'test', 'guest', 'changeme', 'default', 'temp', 'demo'
      ];
      
      common.forEach(pwd => this.commonPasswords.add(pwd.toLowerCase()));
      
      console.log(`Loaded ${this.commonPasswords.size} common passwords`);
    } catch (error) {
      console.error('Failed to load common passwords:', error);
    }
  }

  /**
   * Validate password against security policy
   * @param {string} password - Password to validate
   * @returns {boolean} True if valid
   * @throws {Error} If password doesn't meet requirements
   */
  validate(password) {
    const errors = [];

    // Type check
    if (typeof password !== 'string') {
      throw new Error('Password must be a string');
    }

    // Length checks
    if (password.length < this.minLength) {
      errors.push(`Password must be at least ${this.minLength} characters`);
    }

    if (password.length > this.maxLength) {
      errors.push(`Password must not exceed ${this.maxLength} characters`);
    }

    // Complexity checks
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter (A-Z)');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter (a-z)');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number (0-9)');
    }

    if (!/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*, etc.)');
    }

    // Check against common passwords
    if (this.commonPasswords.has(password.toLowerCase())) {
      errors.push('Password is too common. Please choose a more unique password.');
    }

    // Check for repeated characters (3+ in a row)
    if (/(.)\1{2,}/.test(password)) {
      errors.push('Password contains too many repeated characters in a row');
    }

    // Check for sequential characters
    if (this.hasSequentialChars(password)) {
      errors.push('Password contains sequential characters (e.g., abc, 123, qwerty)');
    }

    // Check for username in password (if provided)
    // This will be done at registration time with actual username

    if (errors.length > 0) {
      throw new Error(errors.join('; '));
    }

    return true;
  }

  /**
   * Check if password contains sequential characters
   * @param {string} password - Password to check
   * @returns {boolean} True if sequential chars found
   */
  hasSequentialChars(password) {
    // Define sequences to check
    const sequences = [
      'abcdefghijklmnopqrstuvwxyz',
      '0123456789',
      'qwertyuiop',
      'asdfghjkl',
      'zxcvbnm'
    ];

    const lowerPassword = password.toLowerCase();

    // Check each sequence
    for (const seq of sequences) {
      // Check forward sequence (3+ chars)
      for (let i = 0; i <= seq.length - 3; i++) {
        const substring = seq.substring(i, i + 3);
        if (lowerPassword.includes(substring)) {
          return true;
        }
      }

      // Check reverse sequence
      const reversed = seq.split('').reverse().join('');
      for (let i = 0; i <= reversed.length - 3; i++) {
        const substring = reversed.substring(i, i + 3);
        if (lowerPassword.includes(substring)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Validate that password doesn't contain username
   * @param {string} password - Password to check
   * @param {string} username - Username to check against
   * @returns {boolean} True if valid
   * @throws {Error} If password contains username
   */
  validateAgainstUsername(password, username) {
    if (!username || !password) {
      return true;
    }

    const lowerPassword = password.toLowerCase();
    const lowerUsername = username.toLowerCase();

    if (lowerPassword.includes(lowerUsername)) {
      throw new Error('Password cannot contain your username');
    }

    return true;
  }

  /**
   * Hash a password using bcrypt
   * @param {string} password - Password to hash
   * @returns {Promise<string>} Hashed password
   */
  async hash(password) {
    // Validate before hashing
    this.validate(password);

    try {
      const hash = await bcrypt.hash(password, this.bcryptRounds);
      return hash;
    } catch (error) {
      throw new Error('Failed to hash password: ' + error.message);
    }
  }

  /**
   * Verify a password against a hash
   * @param {string} password - Plain text password
   * @param {string} hash - Bcrypt hash to compare against
   * @returns {Promise<boolean>} True if password matches
   */
  async verify(password, hash) {
    if (!password || !hash) {
      return false;
    }

    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      console.error('Password verification error:', error);
      return false;
    }
  }

  /**
   * Check if hash needs rehashing (e.g., if rounds changed)
   * @param {string} hash - Bcrypt hash to check
   * @returns {boolean} True if rehash needed
   */
  needsRehash(hash) {
    try {
      const rounds = bcrypt.getRounds(hash);
      return rounds < this.bcryptRounds;
    } catch (error) {
      return true; // If we can't parse it, assume it needs rehashing
    }
  }

  /**
   * Generate a strong random password
   * @param {number} length - Password length (default 16)
   * @returns {string} Generated password
   */
  generatePassword(length = 16) {
    if (length < this.minLength) {
      length = this.minLength;
    }

    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const all = uppercase + lowercase + numbers + special;

    let password = '';

    // Ensure at least one of each type
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += all[Math.floor(Math.random() * all.length)];
    }

    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');

    return password;
  }

  /**
   * Get password strength score
   * @param {string} password - Password to evaluate
   * @returns {object} Strength analysis
   */
  getStrength(password) {
    let score = 0;
    const feedback = [];

    // Length
    if (password.length >= this.minLength) score += 20;
    if (password.length >= 16) score += 10;
    if (password.length >= 20) score += 10;

    // Complexity
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/\d/.test(password)) score += 10;
    if (/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password)) score += 15;

    // Multiple character types
    const types = [
      /[a-z]/.test(password),
      /[A-Z]/.test(password),
      /\d/.test(password),
      /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password)
    ].filter(Boolean).length;

    if (types >= 4) score += 15;

    // Penalize common patterns
    if (this.commonPasswords.has(password.toLowerCase())) {
      score = Math.min(score, 20);
      feedback.push('Password is too common');
    }

    if (/(.)\1{2,}/.test(password)) {
      score -= 10;
      feedback.push('Contains repeated characters');
    }

    if (this.hasSequentialChars(password)) {
      score -= 15;
      feedback.push('Contains sequential characters');
    }

    // Determine strength level
    let strength;
    if (score < 30) {
      strength = 'weak';
      feedback.push('Consider using a longer, more complex password');
    } else if (score < 60) {
      strength = 'fair';
      feedback.push('Password is acceptable but could be stronger');
    } else if (score < 80) {
      strength = 'good';
    } else {
      strength = 'strong';
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      strength,
      feedback
    };
  }
}

// Export singleton instance
module.exports = new PasswordValidator();
