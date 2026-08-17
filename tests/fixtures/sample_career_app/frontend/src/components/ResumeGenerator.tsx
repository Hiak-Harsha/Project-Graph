import React, { useState } from 'react';
import axios from 'axios';

export const ResumeGenerator: React.FC = () => {
  const [prompt, setPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [resume, setResume] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/resume/generate', { prompt });
      setResume(response.data.content);
    } catch (err) {
      console.error('Failed to generate resume', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="resume-generator-card">
      <h2>Generate AI Resume</h2>
      <textarea
        placeholder="Enter your experience, skills, and target role..."
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
      />
      <button onClick={handleGenerate} disabled={loading}>
        {loading ? 'Generating...' : 'Generate Resume'}
      </button>
      {resume && (
        <div className="resume-preview">
          <h3>Generated Output</h3>
          <pre>{resume}</pre>
        </div>
      )}
    </div>
  );
};
