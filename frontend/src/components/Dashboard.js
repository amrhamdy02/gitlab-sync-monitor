import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useSocket } from '../context/SocketContext';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [message, setMessage] = useState(null);
  const { socket } = useSocket();

  useEffect(() => {
    loadStats();
  }, []);

  useEffect(() => {
    if (socket) {
      socket.on('stats_update', (data) => {
        setStats(data);
      });

      socket.on('sync_update', (data) => {
        if (data.status === 'completed' || data.status === 'failed') {
          setSyncing(false);
          setMessage({
            type: data.status === 'completed' ? 'success' : 'error',
            text: `Complete sync ${data.status}: ${data.synced_repos} of ${data.total_repos} repositories synced`
          });
          loadStats();
        }
      });
    }
  }, [socket]);

  const loadStats = async () => {
    try {
      const response = await axios.get('/api/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const handleCompleteSync = async () => {
    if (!window.confirm('Start a complete sync of all repositories from the source GitLab group?\n\nThis will sync ALL repositories, not just approved ones.')) {
      return;
    }

    setSyncing(true);
    setMessage(null);

    try {
      const response = await axios.post('/api/sync/start');
      setMessage({ 
        type: 'info', 
        text: `Complete sync started: ${response.data.total_repos} repositories to sync` 
      });
    } catch (error) {
      setSyncing(false);
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to start sync' 
      });
    }
  };

  if (!stats) return <div className="loading"><div className="spinner"></div></div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>Dashboard</h2>
        <button 
          onClick={handleCompleteSync} 
          className="btn btn-primary"
          disabled={syncing}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          {syncing ? '🔄 Syncing...' : '🔄 Complete Group Sync'}
        </button>
      </div>

      {message && (
        <div className={`alert alert-${message.type}`} style={{ marginBottom: '20px' }}>
          {message.text}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
        <div className="card">
          <h3>Pending</h3>
          <div style={{ fontSize: '32px', color: '#f39c12' }}>{stats.pending_repositories || 0}</div>
          <small style={{ color: '#666' }}>Awaiting approval</small>
        </div>
        <div className="card">
          <h3>Approved</h3>
          <div style={{ fontSize: '32px', color: '#3498db' }}>{stats.approved_repositories || 0}</div>
          <small style={{ color: '#666' }}>Ready to mirror</small>
        </div>
        <div className="card">
          <h3>Mirrored</h3>
          <div style={{ fontSize: '32px', color: '#2ecc71' }}>{stats.mirrored_repositories || 0}</div>
          <small style={{ color: '#666' }}>Successfully mirrored</small>
        </div>
        <div className="card">
          <h3>Failed</h3>
          <div style={{ fontSize: '32px', color: '#e74c3c' }}>{stats.failed_mirrors || 0}</div>
          <small style={{ color: '#666' }}>Mirror failed</small>
        </div>
      </div>

      <div className="card" style={{ marginTop: '20px' }}>
        <h3>📊 Phase 1 Stats (Group Sync)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px' }}>
          <div>
            <strong>Total Syncs:</strong> {stats.total_syncs || 0}
          </div>
          <div>
            <strong>Successful:</strong> <span style={{ color: '#2ecc71' }}>{stats.successful_syncs || 0}</span>
          </div>
          <div>
            <strong>Failed:</strong> <span style={{ color: '#e74c3c' }}>{stats.failed_syncs || 0}</span>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: '20px' }}>
        <h3>ℹ️ Sync Modes</h3>
        <div style={{ display: 'grid', gap: '15px' }}>
          <div>
            <strong>🔄 Complete Group Sync (Phase 1):</strong>
            <p style={{ margin: '5px 0 0 0', color: '#666' }}>
              Syncs ALL repositories from source GitLab group to target. Requires source_group_id configured.
            </p>
          </div>
          <div>
            <strong>🚀 Repository Mirror (Phase 2):</strong>
            <p style={{ margin: '5px 0 0 0', color: '#666' }}>
              Webhook-triggered, approval-based mirroring of individual repositories. See Pending/Approved tabs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
