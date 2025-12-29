import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './App.css';

function App() {
  const [config, setConfig] = useState(null);
  const [repositories, setRepositories] = useState([]);
  const [syncHistory, setSyncHistory] = useState([]);
  const [commitAudit, setCommitAudit] = useState([]);
  const [activeTab, setActiveTab] = useState('repositories'); // Changed default to repositories
  const [monitorTab, setMonitorTab] = useState('main');
  const [connected, setConnected] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState('grid');
  const [socket, setSocket] = useState(null);
  const [notification, setNotification] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 50;

  // Initialize dark mode from localStorage
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      setDarkMode(true);
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  }, []);

  // Toggle dark mode
  const toggleDarkMode = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    
    if (newMode) {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('theme', 'light');
    }
  };

  // Initialize socket connection
  useEffect(() => {
    const socketInstance = io(window.location.origin, {
      transports: ['websocket', 'polling']
    });

    socketInstance.on('connect', () => {
      console.log('Connected to server');
      setConnected(true);
    });

    socketInstance.on('disconnect', () => {
      console.log('Disconnected from server');
      setConnected(false);
    });

    socketInstance.on('repositories_updated', () => {
      fetchRepositories();
    });

    socketInstance.on('sync_completed', (data) => {
      showNotification('Sync completed for ' + data.repositoryName, 'success');
      fetchRepositories();
      fetchSyncHistory();
    });

    socketInstance.on('audit_updated', () => {
      fetchCommitAudit();
    });

    setSocket(socketInstance);

    return () => {
      socketInstance.disconnect();
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    fetchConfig();
    fetchRepositories();
    fetchSyncHistory();
    fetchCommitAudit();
  }, []);

  const fetchConfig = async () => {
    try {
      const response = await fetch('/api/config');
      const data = await response.json();
      setConfig(data);
    } catch (error) {
      console.error('Error fetching config:', error);
    }
  };

  const fetchRepositories = async () => {
    try {
      const response = await fetch('/api/repositories');
      const data = await response.json();
      setRepositories(data);
    } catch (error) {
      console.error('Error fetching repositories:', error);
    }
  };

  const fetchSyncHistory = async () => {
    try {
      const response = await fetch('/api/sync/history?limit=20');
      const data = await response.json();
      setSyncHistory(data);
    } catch (error) {
      console.error('Error fetching sync history:', error);
    }
  };

  const fetchCommitAudit = async () => {
    try {
      const response = await fetch('/api/audit/commits?limit=500'); // Fetch more for pagination
      const data = await response.json();
      setCommitAudit(data);
    } catch (error) {
      console.error('Error fetching commit audit:', error);
    }
  };

  const handleRefresh = async () => {
    try {
      showNotification('Refreshing repository list...', 'info');
      const response = await fetch('/api/repositories/refresh', { method: 'POST' });
      const data = await response.json();
      showNotification(`Refreshed ${data.count} repositories`, 'success');
      fetchRepositories();
    } catch (error) {
      showNotification('Failed to refresh repositories', 'error');
    }
  };

  const handleSync = async (repoId) => {
    try {
      showNotification('Starting sync...', 'info');
      await fetch(`/api/sync/${repoId}`, { method: 'POST' });
    } catch (error) {
      showNotification('Failed to start sync', 'error');
    }
  };

  const handleSyncAll = async () => {
    try {
      showNotification('Starting sync for all repositories...', 'info');
      await fetch('/api/sync/all', { method: 'POST' });
    } catch (error) {
      showNotification('Failed to start sync', 'error');
    }
  };

  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const filteredRepositories = repositories.filter(repo =>
    repo.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    repo.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const mainBranchCommits = commitAudit.filter(c => 
    ['main', 'master', 'develop'].includes(c.branch?.toLowerCase())
  );
  
  const otherBranchCommits = commitAudit.filter(c => 
    !['main', 'master', 'develop'].includes(c.branch?.toLowerCase())
  );

  // Pagination logic
  const getCurrentPageData = (data) => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return data.slice(startIndex, endIndex);
  };

  const getTotalPages = (data) => {
    return Math.ceil(data.length / itemsPerPage);
  };

  const handlePageChange = (page) => {
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const getCommitUrl = (commit) => {
    if (!config) return '#';
    
    // Try to find the repository in our list
    const repo = repositories.find(r => r.name === commit.repository);
    if (repo && commit.sha) {
      // Construct GitLab commit URL
      const baseUrl = repo.web_url || config.source.url;
      return `${baseUrl}/-/commit/${commit.sha}`;
    }
    return '#';
  };

  const renderStatusBadge = (repo) => {
    if (repo.has_new_commits) {
      return <span className="status-badge pending">Pending Changes</span>;
    }
    
    if (!repo.last_sync_status) {
      return <span className="status-badge none">Not Synced</span>;
    }
    
    if (repo.last_sync_status === 'running') {
      return <span className="status-badge running">Syncing</span>;
    }
    
    if (repo.last_sync_status === 'success') {
      return <span className="status-badge success">Synced</span>;
    }
    
    if (repo.last_sync_status === 'failed') {
      return <span className="status-badge failed">Failed</span>;
    }
    
    return null;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const formatTimeAgo = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  // Get last committer from audit log for a repository
  const getLastCommitter = (repoName) => {
    const repoCommits = commitAudit.filter(c => c.repository === repoName);
    if (repoCommits.length > 0) {
      return repoCommits[0].author_name;
    }
    return null;
  };

  const renderPagination = (totalItems) => {
    const totalPages = getTotalPages(totalItems);
    
    if (totalPages <= 1) return null;

    const pages = [];
    const maxVisible = 7;
    
    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      if (currentPage <= 4) {
        for (let i = 1; i <= 5; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 3) {
        pages.push(1);
        pages.push('...');
        for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i);
      } else {
        pages.push(1);
        pages.push('...');
        for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      }
    }

    return (
      <div className="pagination">
        <button
          className="pagination-btn"
          onClick={() => handlePageChange(currentPage - 1)}
          disabled={currentPage === 1}
        >
          Previous
        </button>
        
        {pages.map((page, index) => (
          page === '...' ? (
            <span key={`ellipsis-${index}`} className="pagination-info">...</span>
          ) : (
            <button
              key={page}
              className={`pagination-btn ${currentPage === page ? 'active' : ''}`}
              onClick={() => handlePageChange(page)}
            >
              {page}
            </button>
          )
        ))}
        
        <button
          className="pagination-btn"
          onClick={() => handlePageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
        >
          Next
        </button>
        
        <span className="pagination-info">
          {totalItems} total
        </span>
      </div>
    );
  };

  return (
    <div className="App">
      {/* Header */}
      <header className="app-header">
        <h1>GitLab Sync Monitor</h1>
        <div className="header-info">
          <div className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
            {connected ? 'Connected' : 'Disconnected'}
          </div>
          <div className="repo-count">
            {repositories.length} Repositories
          </div>
          <div className="header-controls">
            <button
              className={`icon-btn ${darkMode ? 'active' : ''}`}
              onClick={toggleDarkMode}
              title={darkMode ? 'Light mode' : 'Dark mode'}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button
              className={`icon-btn ${showSettings ? 'active' : ''}`}
              onClick={() => setShowSettings(!showSettings)}
              title="Settings"
            >
              ⚙️
            </button>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="app-nav">
        <button
          className={`nav-tab ${activeTab === 'repositories' ? 'active' : ''}`}
          onClick={() => setActiveTab('repositories')}
        >
          Repositories
        </button>
        <button
          className={`nav-tab ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => { setActiveTab('monitor'); setCurrentPage(1); }}
        >
          Monitor
        </button>
        <button
          className={`nav-tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          History
        </button>
      </nav>

      {/* Main Content */}
      <main className="app-content">
        {/* Repositories Tab */}
        {activeTab === 'repositories' && (
          <>
            <div className="sync-controls">
              <div className="search-container">
                <input
                  type="text"
                  className="search-input"
                  placeholder="Search repositories..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                {searchTerm && (
                  <button className="search-clear" onClick={() => setSearchTerm('')}>
                    ✕
                  </button>
                )}
              </div>
              <div className="view-toggle">
                <button
                  className={viewMode === 'grid' ? 'active' : ''}
                  onClick={() => setViewMode('grid')}
                  title="Grid view"
                >
                  Grid
                </button>
                <button
                  className={viewMode === 'list' ? 'active' : ''}
                  onClick={() => setViewMode('list')}
                  title="List view"
                >
                  List
                </button>
              </div>
              <button className="btn btn-secondary" onClick={handleRefresh}>
                Refresh
              </button>
              <button className="btn btn-primary" onClick={handleSyncAll}>
                Sync All
              </button>
            </div>

            {filteredRepositories.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-title">No repositories found</div>
                <div className="empty-state-text">
                  {searchTerm ? 'Try a different search term' : 'Click Refresh to load repositories'}
                </div>
              </div>
            ) : (
              <div className={viewMode === 'grid' ? 'repositories-grid' : 'repositories-list'}>
                {filteredRepositories.map((repo) => {
                  const lastCommitter = getLastCommitter(repo.name);
                  
                  return (
                    <div key={repo.id} className="repo-card">
                      <div className="repo-info">
                        <div className="repo-details">
                          <div className="repo-card-header">
                            <div>
                              <div className="repo-name">{repo.name}</div>
                              <div className="repo-path">{repo.path}</div>
                            </div>
                            {renderStatusBadge(repo)}
                          </div>
                          {repo.description && (
                            <div className="repo-description">{repo.description}</div>
                          )}
                          <div className="repo-meta">
                            <span>Last activity: {formatTimeAgo(repo.last_activity)}</span>
                            {repo.last_sync_time && (
                              <span>Last sync: {formatTimeAgo(repo.last_sync_time)}</span>
                            )}
                            {lastCommitter && (
                              <span className="last-committer">
                                👤 {lastCommitter}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="repo-actions">
                        <button
                          className="btn btn-small btn-primary"
                          onClick={() => handleSync(repo.id)}
                          disabled={repo.last_sync_status === 'running'}
                        >
                          {repo.last_sync_status === 'running' ? 'Syncing...' : 'Sync Now'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}

        {/* Monitor Tab */}
        {activeTab === 'monitor' && (
          <>
            <div className="monitor-tabs">
              <button
                className={`monitor-tab ${monitorTab === 'main' ? 'active' : ''}`}
                onClick={() => { setMonitorTab('main'); setCurrentPage(1); }}
              >
                Main Branches ({mainBranchCommits.length})
              </button>
              <button
                className={`monitor-tab ${monitorTab === 'other' ? 'active' : ''}`}
                onClick={() => { setMonitorTab('other'); setCurrentPage(1); }}
              >
                Other Branches ({otherBranchCommits.length})
              </button>
            </div>

            <div className="audit-table-container">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Branch</th>
                    <th>Author</th>
                    <th>Commit</th>
                    <th>Message</th>
                    <th>Type</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const data = monitorTab === 'main' ? mainBranchCommits : otherBranchCommits;
                    const pageData = getCurrentPageData(data);
                    
                    if (pageData.length === 0) {
                      return (
                        <tr>
                          <td colSpan="7" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                            No commits recorded yet
                          </td>
                        </tr>
                      );
                    }
                    
                    return pageData.map((commit, index) => (
                      <tr key={index} className={commit.is_force ? 'force-push' : ''}>
                        <td><strong>{commit.repository}</strong></td>
                        <td><span className="branch-tag">{commit.branch}</span></td>
                        <td>
                          <div className="author-info">
                            <span className="author-name">{commit.author_name}</span>
                            <span className="author-email">{commit.author_email}</span>
                          </div>
                        </td>
                        <td>
                          <a 
                            href={getCommitUrl(commit)} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="commit-link"
                          >
                            <code className="commit-sha">{commit.sha?.substring(0, 8) || 'N/A'}</code>
                          </a>
                        </td>
                        <td><div className="commit-message">{commit.message}</div></td>
                        <td>
                          <span className={`commit-type-badge ${commit.type}`}>
                            {commit.is_force ? 'Force' : commit.type}
                          </span>
                        </td>
                        <td>{formatTimeAgo(commit.timestamp)}</td>
                      </tr>
                    ));
                  })()}
                </tbody>
              </table>
            </div>

            {renderPagination(monitorTab === 'main' ? mainBranchCommits : otherBranchCommits)}
          </>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="history-list">
            {syncHistory.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-title">No sync history</div>
                <div className="empty-state-text">
                  Sync history will appear here after repositories are synced
                </div>
              </div>
            ) : (
              syncHistory.map((item) => (
                <div key={item.id} className="history-item">
                  <div className="history-header">
                    <div className="history-repo">{item.repository_name}</div>
                    <div className="history-time">{formatDate(item.started_at)}</div>
                  </div>
                  <div className="history-details">
                    {renderStatusBadge({ last_sync_status: item.status })}
                    {item.completed_at && (
                      <span>Duration: {Math.round((new Date(item.completed_at) - new Date(item.started_at)) / 1000)}s</span>
                    )}
                    {item.error_message && (
                      <span style={{ color: 'var(--error)' }}>{item.error_message}</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </main>

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay" onClick={() => setShowSettings(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Configuration</h2>
              <button className="modal-close" onClick={() => setShowSettings(false)}>×</button>
            </div>
            
            {config && (
              <div className="config-section">
                <div className="config-card">
                  <h3>Source GitLab</h3>
                  <div className="config-details">
                    <div className="config-item">
                      <span className="config-label">URL</span>
                      <span className="config-value">{config.source.url}</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Group ID</span>
                      <span className="config-value">{config.source.groupId || 'All projects'}</span>
                    </div>
                  </div>
                </div>

                <div className="config-card">
                  <h3>Target GitLab</h3>
                  <div className="config-details">
                    <div className="config-item">
                      <span className="config-label">URL</span>
                      <span className="config-value">{config.target.url}</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Group ID</span>
                      <span className="config-value">
                        {config.target.groupId ? config.target.groupId : 'Preserve source structure'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="config-card">
                  <h3>Sync Schedule</h3>
                  <div className="config-details">
                    <div className="config-item">
                      <span className="config-label">Schedule</span>
                      <span className="config-value">{config.syncSchedule}</span>
                    </div>
                    <div className="config-item">
                      <span className="config-label">Description</span>
                      <span className="config-value">Daily at 2:00 AM</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Notifications */}
      {notification && (
        <div className={`notification ${notification.type}`}>
          <div>{notification.message}</div>
        </div>
      )}
    </div>
  );
}

export default App;
