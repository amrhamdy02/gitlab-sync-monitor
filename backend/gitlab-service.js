const { Gitlab } = require('@gitbeaker/node');

/**
 * GitLab Service
 * Wrapper for GitLab API operations
 */
class GitLabService {
  constructor(url, token) {
    this.api = new Gitlab({
      host: url,
      token: token
    });
  }

  /**
   * Get all repositories in a group
   * @param {string} groupId - GitLab group ID
   * @returns {Promise<Array>} Array of repositories
   */
  async getGroupRepositories(groupId) {
    try {
      if (!groupId) {
        // Get all projects if no group specified
        return await this.api.Projects.all({ membership: true });
      }

      // Get projects in specific group
      return await this.api.Groups.projects(groupId);
    } catch (error) {
      console.error('Error fetching repositories:', error.message);
      throw error;
    }
  }

  /**
   * Get repository details
   * @param {string} projectId - GitLab project ID
   * @returns {Promise<object>} Project details
   */
  async getRepository(projectId) {
    try {
      return await this.api.Projects.show(projectId);
    } catch (error) {
      console.error('Error fetching repository:', error.message);
      throw error;
    }
  }

  /**
   * Get repository commits
   * @param {string} projectId - GitLab project ID
   * @param {number} limit - Number of commits to fetch
   * @returns {Promise<Array>} Array of commits
   */
  async getCommits(projectId, limit = 10) {
    try {
      return await this.api.Commits.all(projectId, { per_page: limit });
    } catch (error) {
      console.error('Error fetching commits:', error.message);
      throw error;
    }
  }
}

module.exports = GitLabService;
