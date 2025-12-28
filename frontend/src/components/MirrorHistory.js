import React, { useEffect, useState } from 'react';
import axios from 'axios';

const MirrorHistory = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      const response = await axios.get('/api/repositories/history/all');
      setHistory(response.data.history);
    } catch (error) {
      console.error('Error loading history:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="loading"><div className="spinner"></div></div>;

  return (
    <div>
      <h2>Mirror History ({history.length})</h2>
      {history.length === 0 ? (
        <div className="empty-state">
          <h3>No mirror history</h3>
          <p>Mirrored repositories will appear here</p>
        </div>
      ) : (
        <div>
          {history.map(item => (
            <div key={item.id} className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <h3>{item.repository_name}</h3>
                  <p><strong>Approved by:</strong> {item.approved_by}</p>
                  <p><strong>Mirrored at:</strong> {new Date(item.mirrored_at || item.updated_at).toLocaleString()}</p>
                  {item.mirror_duration_seconds && (
                    <p><strong>Duration:</strong> {item.mirror_duration_seconds}s</p>
                  )}
                  {item.error_message && (
                    <p style={{ color: '#e74c3c' }}><strong>Error:</strong> {item.error_message}</p>
                  )}
                </div>
                <div>
                  <span className={`badge badge-${item.status === 'mirrored' ? 'mirrored' : 'failed'}`}>
                    {item.status}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default MirrorHistory;
