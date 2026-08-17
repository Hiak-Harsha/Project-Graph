import openai
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Career Platform Backend")

class LoginRequest(BaseModel):
    email: str
    password: str

class GenerateResumeRequest(BaseModel):
    prompt: str

# In-memory mock database
MOCK_RESUMES = {
    "101": {"id": "101", "user_id": "user_a", "title": "Software Engineer", "content": "Confidential Resume of User A"},
    "102": {"id": "102", "user_id": "user_b", "title": "Data Scientist", "content": "Confidential Resume of User B"},
}

@app.post("/api/auth/login")
def login(req: LoginRequest):
    # Planted Flaw: No rate limiting on authentication endpoint
    if req.email == "user@example.com" and req.password == "password123":
        return {"access_token": "mock-token-xyz", "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/resume/generate")
def generate_resume(req: GenerateResumeRequest):
    # Planted Flaw: Calling external AI provider without timeout or retry handling
    client = openai.OpenAI(api_key="mock-key")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": req.prompt}]
    )
    return {"content": response.choices[0].message.content}

@app.get("/api/resume/{id}")
def get_resume(id: str):
    # Planted Flaw: Broken Object-Level Authorization (BOLA / IDOR)
    # Queries by resource id without validating if requesting user owns the resume!
    if id in MOCK_RESUMES:
        return MOCK_RESUMES[id]
    raise HTTPException(status_code=404, detail="Resume not found")

@app.post("/api/resumes/upload")
def upload_resume():
    # Planted Flaw: Missing file size limits & MIME-type validation
    return {"status": "uploaded"}
