import React from 'react';

export const DeadButtonComponent: React.FC = () => {
  // Planted Flaw: Actionable button rendered with no onClick handler or navigation
  return (
    <div className="export-actions">
      <button>
        Export Resume
      </button>
      <a href="#">
        Download PDF
      </a>
    </div>
  );
};
