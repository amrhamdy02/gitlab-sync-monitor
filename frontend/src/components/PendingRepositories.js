import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useSocket } from '../context/SocketContext';

const PendingRepositories = () => {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const { socket } = useSocket();

  useEffect(() => {
    loadRepositories();
  }, []);

  useEffect(() => {
    if (socket) {
      socket.on('new_pending_repository', () => {
        loadRepositories();
      });
    }
  }, [socket]);

  const loadRepositories = async () => {
    try {
      const response = await axios.get('/api/repositories/pending');
      setRepositories(response.data.repositories);
    } catch (error) {
      console.error('Error loading repositories:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (id) => {
    try {
      await axios.post(`/api/repositories/${id}/approve`);
      loadRepositories();
    } catch (error) {
      alert('Failed to approve: ' + error.response?.data?.error);
    }
  };

  const handleDecline = async (id) => {
    const reason = prompt('Decline reason (optional):');
    try {
      await axios.post(`/api/repositories/${id}/decline`, { reason });
      loadRepositories();
    } catch (error) {
      alert('Failed to decline: ' + error.response?.data?.error);
    }
  };

  if (loading) return <div className="loading"><div className="spinner"></div></div>;

  return (
    <div>
      <h2>Pending Repositories ({repositories.length})</h2>
      {repositories.length === 0 ? (
        <div className="empty-state">
          <h3>No pending repositories</h3>
          <p>Push events will appear here for approval</p>
        </div>
      ) : (
        <div>
          {repositories.map(repo => (
            <div key={repo.id} className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div style={{ flex: 1 }}>
                  <h3>📦 {repo.repository_name}</h3>
                  <p><strong>Commits:</strong> {repo.commit_count}</p>
                  <p><strong>Author:</strong> {repo.last_commit_author}</p>
                  <p><strong>Message:</strong> {repo.last_commit_message}</p>
                  <p><strong>Branch:</strong> {repo.branch}</p>
                  <p><strong>Time:</strong> {new Date(repo.push_timestamp).toLocaleString()}</p>
                  {repo.is_force_push && <span className="badge badge-failed">⚠️ Force Push</span>}
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button onClick={() => handleApprove(repo.id)} className="btn btn-success">
                    ✅ Approve
                  </button>
                  <button onClick={() => handleDecline(repo.id)} className="btn btn-danger">
                    ❌ Decline
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default PendingRepositories;
