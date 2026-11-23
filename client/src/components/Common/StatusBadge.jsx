import React from 'react';
import { getRiskBadgeClass } from '../../utils/formatters';

const StatusBadge = ({ label }) => {
  const badgeClass = getRiskBadgeClass(label);
  
  return (
    <span className={`badge ${badgeClass}`}>
      {label || 'UNKNOWN'}
    </span>
  );
};

export default StatusBadge;
