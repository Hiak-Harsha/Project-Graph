from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Acme Notes API")

class Note(BaseModel):
    id: int
    title: str
    content: str
    tags: List[str] = []

fake_notes_db = [
    {"id": 1, "title": "Welcome Note", "content": "Welcome to Acme Notes!", "tags": ["welcome"]}
]

@app.get("/api/notes", response_model=List[Note])
def list_notes():
    return fake_notes_db

@app.post("/api/notes", response_model=Note)
def create_note(note: Note):
    fake_notes_db.append(note.dict())
    return note

@app.delete("/api/notes/{note_id}")
def delete_note(note_id: int):
    for i, n in enumerate(fake_notes_db):
        if n["id"] == note_id:
            return fake_notes_db.pop(i)
    raise HTTPException(status_code=404, detail="Note not found")
