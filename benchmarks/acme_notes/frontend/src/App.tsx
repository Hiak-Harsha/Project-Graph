import React, { useState, useEffect } from 'react';

export interface Note {
  id: number;
  title: str;
  content: str;
}

export function App() {
  const [notes, setNotes] = useState<Note[]>([]);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchNotes = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/notes');
      const data = await res.json();
      setNotes(data);
    } catch (err: any) {
      setError('Failed to load notes');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title) return;
    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: Date.now(), title, content }),
      });
      if (res.ok) {
        setTitle('');
        setContent('');
        fetchNotes();
      }
    } catch (err) {
      setError('Failed to create note');
    }
  };

  const handleDelete = async (id: number) => {
    await fetch(`/api/notes/${id}`, { method: 'DELETE' });
    fetchNotes();
  };

  useEffect(() => {
    fetchNotes();
  }, []);

  return (
    <div className="container">
      <h1>Acme Notes</h1>
      <div className="search-bar">
        <input 
          type="text" 
          placeholder="Search notes..." 
          value={search} 
          onChange={(e) => setSearch(e.target.value)} 
        />
      </div>

      <form onSubmit={handleCreateNote}>
        <input 
          type="text" 
          placeholder="Note title" 
          value={title} 
          onChange={(e) => setTitle(e.target.value)} 
        />
        <textarea 
          placeholder="Write your note..." 
          value={content} 
          onChange={(e) => setContent(e.target.value)} 
        />
        <button type="submit">Create Note</button>
      </form>

      {loading && <p>Loading notes...</p>}
      {error && <p className="error">{error}</p>}

      <div className="notes-grid">
        {notes.filter(n => n.title.toLowerCase().includes(search.toLowerCase())).map(note => (
          <div key={note.id} className="note-card">
            <h3>{note.title}</h3>
            <p>{note.content}</p>
            <button onClick={() => handleDelete(note.id)}>Delete Note</button>
          </div>
        ))}
      </div>
    </div>
  );
}
