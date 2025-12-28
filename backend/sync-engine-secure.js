const simpleGit = require('simple-git');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const validator = require('./utils/input-validator');

/**
 * Secure Sync Engine
 * Performs Git operations with comprehensive security validation
 */
class SecureSyncEngine {
  constructor(db) {
    this.db = db;
    this.baseCloneDir = process.env.GIT_CLONE_BASE || '/tmp/git-clones';
    this.cloneTimeout = 5 * 60 * 1000; // 5 minutes
    this.pushTimeout = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Sync a single repository from source to target
   * @param {object} repo - Repository object
   * @param {string} sourceToken - Source GitLab token
   * @param {string} targetToken - Target GitLab token
   * @returns {Promise<object>} Sync result
   */
  async syncRepository(repo, sourceToken, targetToken) {
    let clonePath = null;

    try {
      // Validate repository object
      if (!repo || !repo.http_url_to_repo) {
        throw new Error('Invalid repository object');
      }

      // Validate Git URLs
      const validSourceUrl = validator.validateGitUrl(repo.http_url_to_repo);
      
      // Build target URL (assuming same path on target GitLab)
      const sourceUrl = new URL(validSourceUrl);
      const targetGitLabUrl = process.env.TARGET_GITLAB_URL;
      
      if (!targetGitLabUrl) {
        throw new Error('TARGET_GITLAB_URL not configured');
      }

      const targetUrl = `${targetGitLabUrl}${sourceUrl.pathname}`;
      const validTargetUrl = validator.validateGitUrl(targetUrl);

      // Validate repository name
      const validRepoName = validator.validateRepositoryName(
        repo.name || repo.path_with_namespace.split('/').pop()
      );

      // Create safe clone path
      clonePath = validator.createSafeClonePath(validRepoName);

      console.log('Starting sync:', {
        repo: validRepoName,
        source: validSourceUrl,
        target: validTargetUrl
      });

      // Ensure base directory exists
      await fs.mkdir(path.dirname(clonePath), { recursive: true });

      // Build authenticated URLs
      const authSourceUrl = this.buildAuthenticatedUrl(validSourceUrl, sourceToken);
      const authTargetUrl = this.buildAuthenticatedUrl(validTargetUrl, targetToken);

      // Clone from source
      await this.cloneRepository(authSourceUrl, clonePath);

      // Push to target
      await this.pushRepository(clonePath, authTargetUrl);

      console.log('Sync completed successfully:', validRepoName);

      return {
        success: true,
        repository: validRepoName,
        sourceUrl: validSourceUrl, // Return non-authenticated URL
        targetUrl: validTargetUrl
      };

    } catch (error) {
      console.error('Sync failed:', {
        repo: repo?.name,
        error: error.message
      });

      return {
        success: false,
        repository: repo?.name,
        error: error.message
      };

    } finally {
      // Cleanup - always delete cloned directory
      if (clonePath) {
        await this.cleanup(clonePath);
      }
    }
  }

  /**
   * Build authenticated Git URL
   * @param {string} url - Git URL
   * @param {string} token - GitLab token
   * @returns {string} Authenticated URL
   */
  buildAuthenticatedUrl(url, token) {
    if (!token) {
      throw new Error('Token is required');
    }

    const urlObj = new URL(url);
    
    // GitLab uses 'oauth2' as username with token as password
    urlObj.username = 'oauth2';
    urlObj.password = encodeURIComponent(token);

    return urlObj.toString();
  }

  /**
   * Clone repository with timeout and validation
   * @param {string} url - Git URL (authenticated)
   * @param {string} localPath - Local path to clone to
   * @returns {Promise<void>}
   */
  async cloneRepository(url, localPath) {
    const git = simpleGit();

    try {
      // Clone with timeout
      await Promise.race([
        git.clone(url, localPath, ['--mirror']),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Clone operation timed out')), this.cloneTimeout)
        )
      ]);

      console.log('Clone completed:', localPath);
    } catch (error) {
      // Sanitize error message (might contain URL with token)
      const sanitizedError = this.sanitizeGitError(error.message);
      throw new Error(`Clone failed: ${sanitizedError}`);
    }
  }

  /**
   * Push repository to target with timeout
   * @param {string} localPath - Local repository path
   * @param {string} targetUrl - Target Git URL (authenticated)
   * @returns {Promise<void>}
   */
  async pushRepository(localPath, targetUrl) {
    const git = simpleGit(localPath);

    try {
      // Push with timeout
      await Promise.race([
        git.push(targetUrl, '--mirror'),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Push operation timed out')), this.pushTimeout)
        )
      ]);

      console.log('Push completed:', localPath);
    } catch (error) {
      // Sanitize error message
      const sanitizedError = this.sanitizeGitError(error.message);
      throw new Error(`Push failed: ${sanitizedError}`);
    }
  }

  /**
   * Cleanup cloned repository
   * @param {string} localPath - Path to cleanup
   * @returns {Promise<void>}
   */
  async cleanup(localPath) {
    try {
      // Validate path is within allowed directory before deletion
      validator.validateFilePath(localPath, this.baseCloneDir);

      // Delete the directory and its parent (UUID directory)
      const parentDir = path.dirname(localPath);
      await fs.rm(parentDir, { recursive: true, force: true });

      console.log('Cleanup completed:', localPath);
    } catch (error) {
      console.error('Cleanup failed:', {
        path: localPath,
        error: error.message
      });
      // Don't throw - cleanup failure shouldn't fail the sync
    }
  }

  /**
   * Sanitize Git error messages to remove sensitive information
   * @param {string} errorMessage - Error message from Git
   * @returns {string} Sanitized error message
   */
  sanitizeGitError(errorMessage) {
    if (!errorMessage) return 'Unknown error';

    // Remove URLs that might contain tokens
    let sanitized = errorMessage
      .replace(/https:\/\/[^@\s]+@[^\s]+/g, 'https://[REDACTED]')
      .replace(/oauth2:[^@\s]+@/g, 'oauth2:[REDACTED]@')
      .replace(/password=[^\s&]+/g, 'password=[REDACTED]');

    return sanitized;
  }

  /**
   * Perform full sync of all repositories
   * @param {Array} repositories - List of repositories to sync
   * @param {string} sourceToken - Source GitLab token
   * @param {string} targetToken - Target GitLab token
   * @returns {Promise<object>} Sync summary
   */
  async performFullSync(repositories, sourceToken, targetToken) {
    const syncId = this.db.createSyncHistory();
    const results = {
      total: repositories.length,
      synced: 0,
      failed: 0,
      errors: []
    };

    console.log(`Starting full sync of ${repositories.length} repositories`);

    for (const repo of repositories) {
      const repoSyncId = this.db.createRepoSyncDetail({
        sync_id: syncId,
        source_repo_id: repo.id.toString(),
        source_repo_name: repo.name,
        source_repo_url: repo.http_url_to_repo,
        status: 'syncing'
      });

      try {
        const result = await this.syncRepository(repo, sourceToken, targetToken);

        if (result.success) {
          this.db.updateRepoSyncDetail(repoSyncId, {
            status: 'synced',
            action: 'update',
            synced_at: new Date().toISOString()
          });

          results.synced++;
        } else {
          throw new Error(result.error);
        }

      } catch (error) {
        this.db.updateRepoSyncDetail(repoSyncId, {
          status: 'failed',
          action: 'error',
          error_message: error.message
        });

        this.db.createSyncLog({
          sync_id: syncId,
          repo_id: repoSyncId,
          level: 'error',
          message: `Sync failed for ${repo.name}`,
          details: error.message
        });

        results.failed++;
        results.errors.push({
          repository: repo.name,
          error: error.message
        });

        console.error(`Sync failed for ${repo.name}:`, error.message);
      }
    }

    // Update sync history
    const status = results.failed === 0 ? 'completed' : 
                   results.synced === 0 ? 'failed' : 'partial';

    this.db.updateSyncHistory(syncId, {
      completed_at: new Date().toISOString(),
      status,
      total_repos: results.total,
      synced_repos: results.synced,
      failed_repos: results.failed
    });

    console.log('Full sync completed:', {
      total: results.total,
      synced: results.synced,
      failed: results.failed
    });

    return results;
  }

  /**
   * Validate sync prerequisites
   * @returns {object} Validation result
   */
  async validatePrerequisites() {
    const errors = [];

    // Check base directory is accessible
    try {
      await fs.access(this.baseCloneDir);
    } catch (error) {
      errors.push(`Base clone directory not accessible: ${this.baseCloneDir}`);
    }

    // Check if git is available
    try {
      const git = simpleGit();
      await git.version();
    } catch (error) {
      errors.push('Git is not available or not properly configured');
    }

    // Check tokens are configured
    if (!process.env.SOURCE_GITLAB_TOKEN) {
      errors.push('SOURCE_GITLAB_TOKEN not configured');
    }

    if (!process.env.TARGET_GITLAB_TOKEN) {
      errors.push('TARGET_GITLAB_TOKEN not configured');
    }

    // Check GitLab URLs are configured
    if (!process.env.SOURCE_GITLAB_URL) {
      errors.push('SOURCE_GITLAB_URL not configured');
    }

    if (!process.env.TARGET_GITLAB_URL) {
      errors.push('TARGET_GITLAB_URL not configured');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = SecureSyncEngine;
