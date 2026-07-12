import uvicorn
from fastapi import FastAPI, Form, Query

app = FastAPI(title="Mock Target Backend Server")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "message": "Welcome to the Mock Backend Server! This service is running behind WebGuard.",
        "available_endpoints": {
            "GET /": "Root details",
            "POST /login": "Simulate login authentication",
            "GET /search?q=value": "Simulate a database/site search",
            "GET /profile?user_id=123": "Simulate viewing a user profile",
            "GET /get-file?file=filename.txt": "Simulate file downloading/traversal"
        }
    }

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    return {
        "authenticated": True,
        "username": username,
        "message": f"Successfully authenticated {username}. Session established."
    }

@app.get("/search")
def search(q: str = Query(default="")):
    return {
        "query": q,
        "results": [
            {"id": 1, "text": f"Search matching for '{q}' index 1"},
            {"id": 2, "text": f"Search matching for '{q}' index 2"}
        ]
    }

@app.get("/profile")
def profile(user_id: str = Query(default="123")):
    return {
        "user_id": user_id,
        "name": "Alex Mercer",
        "status": "Active",
        "role": "Developer"
    }

@app.get("/get-file")
def get_file(file: str = Query(default="")):
    return {
        "filename": file,
        "content": f"Faux file content retrieved for path: {file}"
    }

if __name__ == "__main__":
    uvicorn.run("mock_backend:app", host="127.0.0.1", port=8000, reload=True)
