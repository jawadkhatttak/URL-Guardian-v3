import React from 'react';
import { Shield, LayoutDashboard, Search, History, FileText } from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyzer', label: 'URL Analyzer', icon: Search },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'reports', label: 'Reports', icon: FileText }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <span className="sidebar-logo-mark">
          <Shield className="sidebar-logo-icon" size={20} />
        </span>
        <span className="sidebar-logo-text">URL GUARDIAN</span>
        <span className="version-chip version-chip-sm">v3</span>
      </div>

      <p className="workspace-label">Workspace</p>

      <nav className="sidebar-menu">
        {navItems.map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`sidebar-link ${activeTab === item.id ? 'active' : ''}`}
            >
              <IconComponent className="sidebar-link-icon" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="engine-block">
          <span className="engine-block-label">Scoring Engine</span>
          <span className="engine-block-value">
            <span className="engine-dot" />
            Hybrid · Heuristic + ML
          </span>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;