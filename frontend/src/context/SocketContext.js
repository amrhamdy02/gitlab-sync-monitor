import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || '';
const socket = io(API_URL);

function App() {
  const [repositories, setRepositories] = useState([]);
  const [syncHistory, setSyncHistory] = useState([]);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState({});
  const [activeTab, setActiveTab] = useState('repositories');
  const [notification, setNotification] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connecting');

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
      
      // Don't show success notification here - will come from WebSocket
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
    });

    socket.on('sync_all_completed', (data) => {
      console.log('Sync all completed:', data);
      showNotification(
        `Bulk sync completed: ${data.success} successful, ${data.failed} failed`,
        data.failed > 0 ? 'warning' : 'success'
      );
      fetchRepositories();
      fetchSyncHistory();
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

  // Repositories Tab
  const renderRepositories = () => (
    <div className="repositories-section">
      <div className="section-header">
        <h2>Repositories</h2>
        <div className="header-actions">
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

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading repositories...</p>
        </div>
      ) : repositories.length === 0 ? (
        <div className="empty-state">
          <p>No repositories found</p>
          <button className="btn btn-primary" onClick={refreshRepositories}>
            Refresh Repository List
          </button>
        </div>
      ) : (
        <div className="repositories-grid">
          {repositories.map(repo => (
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

  // Sync History Tab
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

  // Configuration Tab
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
                <span className="config-value">{config.source.groupId}</span>
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
                <span className="config-value">{config.target.groupId}</span>
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

      <div className="env-instructions">
        <h3>Environment Variables</h3>
        <p>This application uses environment variables for configuration. Required variables:</p>
        <ul>
          <li><code>SOURCE_GITLAB_URL</code> - Source GitLab instance URL</li>
          <li><code>SOURCE_GITLAB_TOKEN</code> - Source GitLab personal access token</li>
          <li><code>SOURCE_GROUP_ID</code> - Source group ID to sync from</li>
          <li><code>TARGET_GITLAB_URL</code> - Target GitLab instance URL</li>
          <li><code>TARGET_GITLAB_TOKEN</code> - Target GitLab personal access token</li>
          <li><code>TARGET_GROUP_ID</code> - Target group ID to sync to</li>
          <li><code>WEBHOOK_SECRET</code> - Secret for webhook signature verification (optional)</li>
          <li><code>JWT_SECRET</code> - Secret for JWT token generation (optional)</li>
        </ul>
      </div>
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
        {activeTab === 'history' && renderSyncHistory()}
        {activeTab === 'config' && renderConfiguration()}
      </main>

      <footer className="app-footer">
        <p>GitLab Sync Monitor v1.0 - Phase 1 (Security Hardened)</p>
      </footer>
    </div>
  );
}

export default App;import React, { createContext, useContext, useEffect, useState } from 'react';
import { io } from 'socket.io-client';

const SocketContext = createContext();

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const newSocket = io(window.location.origin, {
      transports: ['websocket', 'polling']
    });

    newSocket.on('connect', () => {
      console.log('Socket connected');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('Socket disconnected');
      setConnected(false);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  const value = {
    socket,
    connected
  };

  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>;
};
