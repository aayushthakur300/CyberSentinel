import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse #

# Load Environment Variables
load_dotenv()

from app.database import Base, engine
from routes.analyze import router

# Setup Database
Base.metadata.create_all(bind=engine)

# --- PATH SETUP ---
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
frontend_dir = os.path.join(current_dir, "../frontend") # Adjust this if your folder name is different
frontend_dir = os.path.abspath(frontend_dir)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"🚀  CyberSentinel Backend Running")
    print(f"📂  Serving Frontend from: {frontend_dir}")
    print(f"🔗  Dashboard: http://127.0.0.1:8001")
    yield

app = FastAPI(title="AI Malware Analyzer", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# --- 1. ROUTE: Landing Page (Dashboard) ---
@app.get("/")
async def read_dashboard():
    return FileResponse(os.path.join(frontend_dir, "dashboard.html"))

# --- 2. ROUTE: The Vault (Analysis App) ---
@app.get("/analyze")
async def read_app():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

# --- 3. MOUNT: Static Files (CSS/JS) ---
# This must come AFTER specific routes so it doesn't override them.
# It serves style.css, app.js, and images.
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)