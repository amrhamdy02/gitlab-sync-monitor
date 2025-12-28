import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || '';
const socket = io(API_URL);

function App() {
  const [repositories, setRepositories] = useState([]);
  const [syncHistory, setSyncHistory] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState({});
  const [activeTab, setActiveTab] = useState('repositories');
  const [monitorSubTab, setMonitorSubTab] = useState('main');
  const [notification, setNotification] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  
  // Repository view settings
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'

  // Show notification
  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  // Fetch configuration
  const fetchConfig = async () => {
    try {
      const response = await fetch(`${API_URL}/api/config`);
      const data = await response.json();
      setConfig(data);
    } catch (error) {
      console.error('Error fetching config:', error);
      showNotification('Failed to load configuration', 'error');
    }
  };

  // Fetch repositories
  const fetchRepositories = async () => {
    try {
      const response = await fetch(`${API_URL}/api/repositories`);
      const data = await response.json();
      setRepositories(data);
    } catch (error) {
      console.error('Error fetching repositories:', error);
      showNotification('Failed to load repositories', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Fetch sync history
  const fetchSyncHistory = async () => {
    try {
      const response = await fetch(`${API_URL}/api/sync/history?limit=50`);
      const data = await response.json();
      setSyncHistory(data);
    } catch (error) {
      console.error('Error fetching sync history:', error);
      showNotification('Failed to load sync history', 'error');
    }
  };

  // Fetch audit log
  const fetchAuditLog = async () => {
    try {
      const response = await fetch(`${API_URL}/api/audit/commits`);
      const data = await response.json();
      setAuditLog(data);
    } catch (error) {
      console.error('Error fetching audit log:', error);
      // Don't show error notification as this is a new feature
    }
  };

  // Refresh repository list from GitLab
  const refreshRepositories = async () => {
    setLoading(true);
    showNotification('Refreshing repository list from GitLab...', 'info');
    
    try {
      const response = await fetch(`${API_URL}/api/repositories/refresh`, {
        method: 'POST'
      });
      const data = await response.json();
      
      showNotification(`Refreshed ${data.count} repositories`, 'success');
      await fetchRepositories();
    } catch (error) {
      console.error('Error refreshing repositories:', error);
      showNotification('Failed to refresh repositories', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Sync single repository
  const syncRepository = async (repoId, repoName) => {
    setSyncing(prev => ({ ...prev, [repoId]: true }));
    showNotification(`Starting sync for ${repoName}...`, 'info');
    
    try {
      const response = await fetch(`${API_URL}/api/sync/${repoId}`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        throw new Error('Sync failed');
      }
    } catch (error) {
      console.error('Error syncing repository:', error);
      showNotification(`Failed to sync ${repoName}`, 'error');
      setSyncing(prev => ({ ...prev, [repoId]: false }));
    }
  };

  // Sync all repositories
  const syncAllRepositories = async () => {
    showNotification('Starting sync for all repositories...', 'info');
    
    try {
      const response = await fetch(`${API_URL}/api/sync/all`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        throw new Error('Sync all failed');
      }
      
      showNotification('Bulk sync started in background', 'success');
    } catch (error) {
      console.error('Error syncing all repositories:', error);
      showNotification('Failed to start bulk sync', 'error');
    }
  };

  // Filter repositories based on search
  const filteredRepositories = repositories.filter(repo => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      repo.name.toLowerCase().includes(query) ||
      repo.path.toLowerCase().includes(query) ||
      (repo.description && repo.description.toLowerCase().includes(query))
    );
  });

  // Filter audit log by branch type
  const filteredAuditLog = auditLog.filter(commit => {
    if (monitorSubTab === 'main') {
      return commit.branch === 'main' || commit.branch === 'master';
    } else {
      return commit.branch !== 'main' && commit.branch !== 'master';
    }
  });

  // WebSocket event handlers
  useEffect(() => {
    socket.on('connect', () => {
      console.log('WebSocket connected');
      setConnectionStatus('connected');
      showNotification('Connected to sync monitor', 'success');
    });

    socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setConnectionStatus('disconnected');
      showNotification('Disconnected from server', 'warning');
    });

    socket.on('repositories_updated', (data) => {
      console.log('Repositories updated:', data);
      fetchRepositories();
    });

    socket.on('sync_started', (data) => {
      console.log('Sync started:', data);
      setSyncing(prev => ({ ...prev, [data.repositoryId]: true }));
    });

    socket.on('sync_completed', (data) => {
      console.log('Sync completed:', data);
      setSyncing(prev => ({ ...prev, [data.repositoryId]: false }));
      
      if (data.status === 'success') {
        showNotification(
          `✅ ${data.repositoryName} synced successfully (${data.commitCount} commits)`,
          'success'
        );
      } else {
        showNotification(
          `❌ ${data.repositoryName} sync failed: ${data.error}`,
          'error'
        );
      }
      
      fetchRepositories();
      fetchSyncHistory();
      fetchAuditLog();
    });

    socket.on('sync_all_completed', (data) => {
      console.log('Sync all completed:', data);
      showNotification(
        `Bulk sync completed: ${data.success} successful, ${data.failed} failed`,
        data.failed > 0 ? 'warning' : 'success'
      );
      fetchRepositories();
      fetchSyncHistory();
      fetchAuditLog();
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('repositories_updated');
      socket.off('sync_started');
      socket.off('sync_completed');
      socket.off('sync_all_completed');
    };
  }, []);

  // Initial data load
  useEffect(() => {
    fetchConfig();
    fetchRepositories();
    fetchSyncHistory();
    fetchAuditLog();
  }, []);

  // Format date/time
  const formatDateTime = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Get status badge
  const getStatusBadge = (status) => {
    const badges = {
      success: { class: 'status-success', icon: '✓', text: 'Success' },
      failed: { class: 'status-failed', icon: '✗', text: 'Failed' },
      running: { class: 'status-running', icon: '⟳', text: 'Running' },
      pending: { class: 'status-pending', icon: '○', text: 'Pending' }
    };
    
    const badge = badges[status] || { class: 'status-unknown', icon: '?', text: 'Unknown' };
    
    return (
      <span className={`status-badge ${badge.class}`}>
        <span className="status-icon">{badge.icon}</span>
        {badge.text}
      </span>
    );
  };

  // Get commit type badge
  const getCommitTypeBadge = (type) => {
    const types = {
      push: { class: 'commit-push', icon: '↑', text: 'Push' },
      merge: { class: 'commit-merge', icon: '⇄', text: 'Merge' },
      force: { class: 'commit-force', icon: '⚠', text: 'Force Push' }
    };
    
    const badge = types[type] || types.push;
    
    return (
      <span className={`commit-type-badge ${badge.class}`}>
        <span className="commit-icon">{badge.icon}</span>
        {badge.text}
      </span>
    );
  };

  // Repositories Tab - continues in next message due to length
  const renderRepositories = () => (
    <div className="repositories-section">
      <div className="section-header">
        <h2>Repositories</h2>
        <div className="header-actions">
          <div className="search-container">
            <input
              type="text"
              placeholder="🔍 Search repositories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
            />
            {searchQuery && (
              <button 
                className="clear-search"
                onClick={() => setSearchQuery('')}
                title="Clear search"
              >
                ×
              </button>
            )}
          </div>
          
          <div className="view-toggle">
            <button
              className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
              onClick={() => setViewMode('grid')}
              title="Grid view"
            >
              ⊞
            </button>
            <button
              className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
              onClick={() => setViewMode('list')}
              title="List view"
            >
              ☰
            </button>
          </div>
          
          <button 
            className="btn btn-secondary"
            onClick={refreshRepositories}
            disabled={loading}
          >
            {loading ? '⟳ Refreshing...' : '↻ Refresh from GitLab'}
          </button>
          <button 
            className="btn btn-primary"
            onClick={syncAllRepositories}
            disabled={Object.keys(syncing).some(id => syncing[id])}
          >
            🔄 Sync All
          </button>
        </div>
      </div>

      {searchQuery && (
        <div className="search-results-info">
          Found {filteredRepositories.length} of {repositories.length} repositories
        </div>
      )}

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading repositories...</p>
        </div>
      ) : filteredRepositories.length === 0 ? (
        <div className="empty-state">
          {searchQuery ? (
            <>
              <p>No repositories found matching "{searchQuery}"</p>
              <button className="btn btn-secondary" onClick={() => setSearchQuery('')}>
                Clear Search
              </button>
            </>
          ) : (
            <>
              <p>No repositories found</p>
              <button className="btn btn-primary" onClick={refreshRepositories}>
                Refresh Repository List
              </button>
            </>
          )}
        </div>
      ) : (
        <div className={`repositories-${viewMode}`}>
          {filteredRepositories.map(repo => (
            <div key={repo.id} className="repo-card">
              <div className="repo-header">
                <h3 className="repo-name">{repo.name}</h3>
                {repo.last_sync_status && getStatusBadge(repo.last_sync_status)}
              </div>
              
              <p className="repo-path">{repo.path}</p>
              {repo.description && <p className="repo-description">{repo.description}</p>}
              
              <div className="repo-meta">
                <div className="meta-item">
                  <span className="meta-label">Last Activity:</span>
                  <span className="meta-value">{formatDateTime(repo.last_activity)}</span>
                </div>
                {repo.last_sync_time && (
                  <div className="meta-item">
                    <span className="meta-label">Last Sync:</span>
                    <span className="meta-value">{formatDateTime(repo.last_sync_time)}</span>
                  </div>
                )}
                {repo.last_sync_error && (
                  <div className="error-message">
                    ⚠️ {repo.last_sync_error}
                  </div>
                )}
              </div>

              <div className="repo-actions">
                <a 
                  href={repo.web_url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="btn btn-link"
                >
                  View in GitLab →
                </a>
                <button
                  className="btn btn-primary"
                  onClick={() => syncRepository(repo.id, repo.name)}
                  disabled={syncing[repo.id]}
                >
                  {syncing[repo.id] ? '⟳ Syncing...' : '🔄 Sync Now'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  // Monitor Tab
  const renderMonitor = () => (
    <div className="monitor-section">
      <div className="section-header">
        <h2>Commit Monitor & Audit Log</h2>
        <button 
          className="btn btn-secondary"
          onClick={fetchAuditLog}
        >
          ↻ Refresh
        </button>
      </div>

      <div className="monitor-tabs">
        <button
          className={`monitor-tab-btn ${monitorSubTab === 'main' ? 'active' : ''}`}
          onClick={() => setMonitorSubTab('main')}
        >
          📌 Main Branch
        </button>
        <button
          className={`monitor-tab-btn ${monitorSubTab === 'other' ? 'active' : ''}`}
          onClick={() => setMonitorSubTab('other')}
        >
          🌿 Other Branches
        </button>
      </div>

      {auditLog.length === 0 ? (
        <div className="empty-state">
          <p>No commit activity yet</p>
          <p className="empty-state-hint">Audit log will populate after repositories are synced</p>
        </div>
      ) : filteredAuditLog.length === 0 ? (
        <div className="empty-state">
          <p>No commits found for {monitorSubTab === 'main' ? 'main branch' : 'other branches'}</p>
        </div>
      ) : (
        <div className="audit-log-container">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Branch</th>
                <th>Author</th>
                <th>Commit</th>
                <th>Message</th>
                <th>Type</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredAuditLog.map((commit, index) => (
                <tr key={index} className={commit.is_force ? 'force-push-row' : ''}>
                  <td className="repo-name-cell">{commit.repository}</td>
                  <td>
                    <span className="branch-tag">{commit.branch}</span>
                  </td>
                  <td className="author-cell">
                    <div className="author-info">
                      <div className="author-name">{commit.author_name}</div>
                      <div className="author-email">{commit.author_email}</div>
                    </div>
                  </td>
                  <td className="commit-sha">
                    <code>{commit.sha ? commit.sha.substring(0, 8) : 'N/A'}</code>
                  </td>
                  <td className="commit-message">{commit.message}</td>
                  <td>{getCommitTypeBadge(commit.type)}</td>
                  <td className="timestamp-cell">{formatDateTime(commit.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );

  // History & Config tabs continue...
  const renderSyncHistory = () => (
    <div className="history-section">
      <div className="section-header">
        <h2>Sync History</h2>
        <button 
          className="btn btn-secondary"
          onClick={fetchSyncHistory}
        >
          ↻ Refresh
        </button>
      </div>

      {syncHistory.length === 0 ? (
        <div className="empty-state">
          <p>No sync history yet</p>
        </div>
      ) : (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Status</th>
                <th>Started</th>
                <th>Completed</th>
                <th>Duration</th>
                <th>Commits</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {syncHistory.map(sync => {
                const started = new Date(sync.started_at);
                const completed = sync.completed_at ? new Date(sync.completed_at) : null;
                const duration = completed 
                  ? Math.round((completed - started) / 1000) + 's'
                  : 'Running';

                return (
                  <tr key={sync.id}>
                    <td className="repo-name-cell">{sync.repository_name}</td>
                    <td>{getStatusBadge(sync.status)}</td>
                    <td>{formatDateTime(sync.started_at)}</td>
                    <td>{formatDateTime(sync.completed_at)}</td>
                    <td>{duration}</td>
                    <td className="commits-cell">{sync.commits_synced || '-'}</td>
                    <td className="error-cell">
                      {sync.error_message && (
                        <span className="error-tooltip" title={sync.error_message}>
                          ⚠️
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );

  const renderConfiguration = () => (
    <div className="config-section">
      <h2>Configuration</h2>
      
      {config ? (
        <div className="config-grid">
          <div className="config-card">
            <h3>Source GitLab</h3>
            <div className="config-details">
              <div className="config-item">
                <span className="config-label">URL:</span>
                <span className="config-value">{config.source.url}</span>
              </div>
              <div className="config-item">
                <span className="config-label">Group ID:</span>
                <span className="config-value">{config.source.groupId || 'All projects'}</span>
              </div>
            </div>
          </div>

          <div className="config-card">
            <h3>Target GitLab</h3>
            <div className="config-details">
              <div className="config-item">
                <span className="config-label">URL:</span>
                <span className="config-value">{config.target.url}</span>
              </div>
              <div className="config-item">
                <span className="config-label">Group ID:</span>
                <span className="config-value">{config.target.groupId || 'User namespace'}</span>
              </div>
            </div>
          </div>

          <div className="config-card">
            <h3>Sync Schedule</h3>
            <div className="config-details">
              <div className="config-item">
                <span className="config-label">Cron Expression:</span>
                <span className="config-value">{config.syncSchedule}</span>
              </div>
              <div className="config-item">
                <span className="config-label">Description:</span>
                <span className="config-value">Daily at 2:00 AM</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading configuration...</p>
        </div>
      )}
    </div>
  );

  return (
    <div className="App">
      <header className="app-header">
        <h1>🔄 GitLab Sync Monitor</h1>
        <div className="header-info">
          <span className={`connection-status ${connectionStatus}`}>
            {connectionStatus === 'connected' ? '🟢 Connected' : '🔴 Disconnected'}
          </span>
          <span className="repo-count">
            {repositories.length} {repositories.length === 1 ? 'Repository' : 'Repositories'}
          </span>
        </div>
      </header>

      {notification && (
        <div className={`notification notification-${notification.type}`}>
          {notification.message}
          <button 
            className="notification-close"
            onClick={() => setNotification(null)}
          >
            ×
          </button>
        </div>
      )}

      <nav className="app-nav">
        <button
          className={`nav-button ${activeTab === 'repositories' ? 'active' : ''}`}
          onClick={() => setActiveTab('repositories')}
        >
          📚 Repositories
        </button>
        <button
          className={`nav-button ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitor')}
        >
          👁️ Monitor
        </button>
        <button
          className={`nav-button ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          📜 Sync History
        </button>
        <button
          className={`nav-button ${activeTab === 'config' ? 'active' : ''}`}
          onClick={() => setActiveTab('config')}
        >
          ⚙️ Configuration
        </button>
      </nav>

      <main className="app-main">
        {activeTab === 'repositories' && renderRepositories()}
        {activeTab === 'monitor' && renderMonitor()}
        {activeTab === 'history' && renderSyncHistory()}
        {activeTab === 'config' && renderConfiguration()}
      </main>

      <footer className="app-footer">
        <p>GitLab Sync Monitor v1.1 - Enhanced UI & Audit Features</p>
      </footer>
    </div>
  );
}

export default App;
