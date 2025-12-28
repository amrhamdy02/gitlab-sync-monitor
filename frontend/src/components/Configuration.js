import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Configuration = () => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  
  const [formData, setFormData] = useState({
    source_gitlab_url: '',
    source_token: '',
    source_group_id: '',
    target_gitlab_url: '',
    target_token: '',
    target_group_id: '',
    cron_schedule: '0 */6 * * *',
    retry_attempts: 3,
    retry_delay_seconds: 60,
    enabled: false
  });

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const response = await axios.get('/api/config');
      if (response.data && response.data.source_gitlab_url) {
        setConfig(response.data);
        // Mask tokens for display
        const maskedConfig = {
          ...response.data,
          source_token: '••••••••',
          target_token: '••••••••'
        };
        setFormData(maskedConfig);
      }
    } catch (error) {
      console.error('Error loading config:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    try {
      // Don't send masked tokens
      const dataToSend = { ...formData };
      if (dataToSend.source_token === '••••••••') {
        delete dataToSend.source_token;
      }
      if (dataToSend.target_token === '••••••••') {
        delete dataToSend.target_token;
      }

      const response = await axios.post('/api/config', dataToSend);
      setMessage({ type: 'success', text: 'Configuration saved successfully!' });
      setEditing(false);
      await loadConfig();
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error.response?.data?.error || 'Failed to save configuration' 
      });
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setEditing(false);
    setMessage(null);
    if (config) {
      setFormData({
        ...config,
        source_token: '••••••••',
        target_token: '••••••••'
      });
    }
  };

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>;
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>Configuration</h2>
        {!editing && config && (
          <button onClick={() => setEditing(true)} className="btn btn-primary">
            ✏️ Edit Configuration
          </button>
        )}
      </div>

      {message && (
        <div className={`alert alert-${message.type}`} style={{ marginBottom: '20px' }}>
          {message.text}
        </div>
      )}

      {!config && !editing ? (
        <div className="card">
          <div className="empty-state">
            <h3>No Configuration Found</h3>
            <p>Please configure your GitLab settings to get started.</p>
            <button onClick={() => setEditing(true)} className="btn btn-primary">
              🔧 Configure Now
            </button>
          </div>
        </div>
      ) : editing ? (
        <form onSubmit={handleSubmit}>
          {/* Source GitLab */}
          <div className="card">
            <h3>Source GitLab (Read Access)</h3>
            <div style={{ display: 'grid', gap: '15px' }}>
              <div>
                <label>GitLab URL *</label>
                <input
                  type="url"
                  name="source_gitlab_url"
                  value={formData.source_gitlab_url}
                  onChange={handleChange}
                  placeholder="https://gitlab.example.com"
                  required
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
              </div>
              <div>
                <label>Access Token *</label>
                <input
                  type="password"
                  name="source_token"
                  value={formData.source_token}
                  onChange={handleChange}
                  placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                  required={!config}
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>
                  Required scopes: read_api, read_repository
                </small>
              </div>
              <div>
                <label>Group ID (Optional)</label>
                <input
                  type="text"
                  name="source_group_id"
                  value={formData.source_group_id}
                  onChange={handleChange}
                  placeholder="Leave empty for webhook-only mode"
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>
                  For scheduled complete group sync (Phase 1 feature)
                </small>
              </div>
            </div>
          </div>

          {/* Target GitLab */}
          <div className="card">
            <h3>Target GitLab (Write Access)</h3>
            <div style={{ display: 'grid', gap: '15px' }}>
              <div>
                <label>GitLab URL *</label>
                <input
                  type="url"
                  name="target_gitlab_url"
                  value={formData.target_gitlab_url}
                  onChange={handleChange}
                  placeholder="https://gitlab-target.example.com"
                  required
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
              </div>
              <div>
                <label>Access Token *</label>
                <input
                  type="password"
                  name="target_token"
                  value={formData.target_token}
                  onChange={handleChange}
                  placeholder="glpat-yyyyyyyyyyyyyyyyyyyy"
                  required={!config}
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>
                  Required scopes: api, write_repository, read_repository
                </small>
              </div>
              <div>
                <label>Group ID (Optional)</label>
                <input
                  type="text"
                  name="target_group_id"
                  value={formData.target_group_id}
                  onChange={handleChange}
                  placeholder="Target group for mirrored repositories"
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>
                  All mirrors will be created in this group
                </small>
              </div>
            </div>
          </div>

          {/* Sync Settings */}
          <div className="card">
            <h3>Sync Settings</h3>
            <div style={{ display: 'grid', gap: '15px' }}>
              <div>
                <label>Cron Schedule</label>
                <input
                  type="text"
                  name="cron_schedule"
                  value={formData.cron_schedule}
                  onChange={handleChange}
                  placeholder="0 */6 * * *"
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>
                  Format: minute hour day month weekday (e.g., "0 */6 * * *" = every 6 hours)
                </small>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                <div>
                  <label>Retry Attempts</label>
                  <input
                    type="number"
                    name="retry_attempts"
                    value={formData.retry_attempts}
                    onChange={handleChange}
                    min="1"
                    max="10"
                    style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                  />
                </div>
                <div>
                  <label>Retry Delay (seconds)</label>
                  <input
                    type="number"
                    name="retry_delay_seconds"
                    value={formData.retry_delay_seconds}
                    onChange={handleChange}
                    min="10"
                    max="300"
                    style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                  />
                </div>
              </div>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    name="enabled"
                    checked={formData.enabled}
                    onChange={handleChange}
                    style={{ marginRight: '10px' }}
                  />
                  Enable Scheduled Sync (Phase 1 Complete Group Sync)
                </label>
                <small style={{ color: '#666', fontSize: '12px', marginLeft: '30px' }}>
                  When enabled, syncs all repositories from source group on schedule
                </small>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
            <button 
              type="button" 
              onClick={handleCancel} 
              className="btn btn-secondary"
              disabled={saving}
            >
              Cancel
            </button>
            <button 
              type="submit" 
              className="btn btn-primary"
              disabled={saving}
            >
              {saving ? 'Saving...' : '💾 Save Configuration'}
            </button>
          </div>
        </form>
      ) : (
        <>
          {/* Display Mode */}
          <div className="card">
            <h3>Source GitLab</h3>
            <p><strong>URL:</strong> {config.source_gitlab_url}</p>
            <p><strong>Token:</strong> ••••••••••••</p>
            {config.source_group_id && (
              <p><strong>Group ID:</strong> {config.source_group_id}</p>
            )}
          </div>

          <div className="card">
            <h3>Target GitLab</h3>
            <p><strong>URL:</strong> {config.target_gitlab_url}</p>
            <p><strong>Token:</strong> ••••••••••••</p>
            {config.target_group_id && (
              <p><strong>Group ID:</strong> {config.target_group_id}</p>
            )}
          </div>

          <div className="card">
            <h3>Sync Settings</h3>
            <p><strong>Schedule:</strong> {config.cron_schedule}</p>
            <p><strong>Retry Attempts:</strong> {config.retry_attempts}</p>
            <p><strong>Retry Delay:</strong> {config.retry_delay_seconds} seconds</p>
            <p><strong>Scheduled Sync:</strong> {config.enabled ? '✅ Enabled' : '❌ Disabled'}</p>
          </div>
        </>
      )}

      {/* Webhook Info - Always visible */}
      <div className="card">
        <h3>Webhook Information</h3>
        <p>Configure GitLab webhooks to point to:</p>
        <code style={{ 
          display: 'block', 
          padding: '10px', 
          background: '#f5f5f5', 
          borderRadius: '4px',
          marginTop: '10px'
        }}>
          {window.location.origin}/api/webhook/gitlab
        </code>
        <p style={{ marginTop: '15px' }}>
          <strong>Webhook Secret:</strong> Use the WEBHOOK_SECRET from your ConfigMap
        </p>
        <small style={{ color: '#666' }}>
          Get it with: oc get configmap gitlab-sync-monitor-config -n gitlab-sync -o jsonpath='{'{.data.WEBHOOK_SECRET}'}'
        </small>
      </div>
    </div>
  );
};

export default Configuration;
