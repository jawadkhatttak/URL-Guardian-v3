import React from 'react';
import { getRiskColor } from '../../utils/formatters';

const ScoreGauge = ({ score = 0, risk = 'UNKNOWN' }) => {
  // Clamp score between 0 and 100
  const normalizedScore = Math.max(0, Math.min(100, score));
  
  // Circle details for SVG gauge
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  const color = getRiskColor(risk);

  return (
    <div className="gauge-wrapper">
      <svg className="gauge-svg" viewBox="0 0 120 120">
        {/* Track circle */}
        <circle
          className="gauge-track"
          cx="60"
          cy="60"
          r={radius}
        />
        {/* Fill circle */}
        <circle
          className="gauge-fill"
          cx="60"
          cy="60"
          r={radius}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
        />
      </svg>
      <div className="gauge-center-text">
        <span className="gauge-score" style={{ color }}>{normalizedScore}</span>
        <div className="gauge-label">Score</div>
      </div>
    </div>
  );
};

export default ScoreGauge;
