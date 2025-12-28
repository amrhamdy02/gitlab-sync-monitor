import React, { useEffect, useState } from 'react';
import axios from 'axios';

const ApprovedRepositories = () => {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [mirroring, setMirroring] = useState(false);

  useEffect(() => {
    loadRepositories();
  }, []);

  const loadRepositories = async () => {
    try {
      const response = await axios.get('/api/repositories/approved');
      setRepositories(response.data.repositories);
    } catch (error) {
      console.error('Error loading repositories:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleMirrorAll = async () => {
    if (!window.confirm(`Mirror ${repositories.length} repositories?`)) return;
    
    setMirroring(true);
    try {
      await axios.post('/api/mirror/sync-approved');
      alert('Mirror started! Check history for progress.');
      setTimeout(loadRepositories, 2000);
    } catch (error) {
      alert('Failed to start mirror: ' + error.response?.data?.error);
    } finally {
      setMirroring(false);
    }
  };

  if (loading) return <div className="loading"><div className="spinner"></div></div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>Approved Repositories ({repositories.length})</h2>
        {repositories.length > 0 && (
          <button 
            onClick={handleMirrorAll} 
            className="btn btn-primary"
            disabled={mirroring}
          >
            {mirroring ? '🔄 Mirroring...' : '🚀 Mirror All Now'}
          </button>
        )}
      </div>
      
      {repositories.length === 0 ? (
        <div className="empty-state">
          <h3>No approved repositories</h3>
          <p>Approve repositories from the Pending tab</p>
        </div>
      ) : (
        <div>
          {repositories.map(repo => (
            <div key={repo.id} className="card">
              <h3>✅ {repo.repository_name}</h3>
              <p><strong>Approved by:</strong> {repo.approved_by}</p>
              <p><strong>Approved at:</strong> {new Date(repo.approved_at).toLocaleString()}</p>
              <p><strong>Commits:</strong> {repo.commit_count}</p>
              <span className="badge badge-approved">Ready for Mirror</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ApprovedRepositories;
