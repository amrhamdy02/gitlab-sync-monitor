import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './Navbar.css';

const Navbar = () => {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  if (!isAuthenticated) return null;

  const isActive = (path) => location.pathname === path ? 'active' : '';

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <h1>🔄 GitLab Sync Monitor v2</h1>
      </div>
      
      <div className="navbar-menu">
        <Link to="/" className={`nav-link ${isActive('/')}`}>
          Dashboard
        </Link>
        <Link to="/pending" className={`nav-link ${isActive('/pending')}`}>
          Pending
        </Link>
        <Link to="/approved" className={`nav-link ${isActive('/approved')}`}>
          Approved
        </Link>
        <Link to="/history" className={`nav-link ${isActive('/history')}`}>
          History
        </Link>
        <Link to="/config" className={`nav-link ${isActive('/config')}`}>
          Config
        </Link>
      </div>
      
      <div className="navbar-user">
        <span className="user-name">{user?.username}</span>
        <span className="user-role badge badge-approved">{user?.role}</span>
        <button onClick={handleLogout} className="btn btn-secondary btn-sm">
          Logout
        </button>
      </div>
    </nav>
  );
};

export default Navbar;
