import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


# Load Environment Variables
load_dotenv()

from app.database import Base, engine
from routes.analyze import router

# Setup Database
Base.metadata.create_all(bind=engine)

# --- DEBUG PATH LOGIC ---
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
frontend_dir = os.path.join(current_dir, "../frontend")
frontend_dir = os.path.abspath(frontend_dir) # Normalize path

# Check immediately if it exists
frontend_exists = os.path.exists(frontend_dir)
index_exists = os.path.exists(os.path.join(frontend_dir, "index.html"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "="*60)
    print("🚀  DEBUG MODE: PATH CHECK")
    print(f"📂  Current Backend Dir: {current_dir}")
    print(f"📂  Looking for Frontend at: {frontend_dir}")
    
    if frontend_exists:
        print("✅  Frontend Directory FOUND.")
        if index_exists:
            print("✅  index.html FOUND inside frontend.")
            print("🔗  CLICK TO OPEN: http://127.0.0.1:8001")
        else:
            print("❌  ERROR: index.html is MISSING inside the frontend folder!")
    else:
        print("❌  ERROR: Frontend Directory NOT FOUND at that path.")
        print("    Please check your folder structure.")
    
    print("="*60 + "\n")
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

# --- Mount Frontend ---
if frontend_exists:
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
    
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # This prints the exact reason for the 422 error in your terminal
    print(f"❌ 422 Validation Error: {exc.errors()}")
    print(f"📦 Payload received: {await request.body()}")
    
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(await request.body())},
    )