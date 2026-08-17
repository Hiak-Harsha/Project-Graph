import React from 'react';
import { ResumeGenerator } from '../components/ResumeGenerator';
import { DeadButtonComponent } from '../components/DeadButtonComponent';

export const Dashboard: React.FC = () => {
  return (
    <div className="dashboard-container">
      <header>
        <h1>Career Platform Dashboard</h1>
      </header>
      <main>
        <ResumeGenerator />
        <DeadButtonComponent />
      </main>
    </div>
  );
};
