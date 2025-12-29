
# import os
# import sys
# import uvicorn
# import asyncio
# import psutil
# from fastapi import FastAPI, WebSocket
# from fastapi.staticfiles import StaticFiles
# from fastapi.responses import FileResponse, JSONResponse
# from fastapi.middleware.cors import CORSMiddleware
# from dotenv import load_dotenv

# # --- PATH SETUP ---
# current_dir = os.path.dirname(os.path.abspath(__file__))
# sys.path.append(current_dir)

# load_dotenv()

# # --- IMPORTS ---
# try:
#     from app.database import Base, engine
#     from routes.analyze import router as analyze_router
# except ImportError as e:
#     print(f"❌ Import Error: {e}")
#     sys.exit(1)

# Base.metadata.create_all(bind=engine)

# # --- FRONTEND FOLDER ---
# # Looks for 'frontend' folder one level up
# static_dir = os.path.abspath(os.path.join(current_dir, "../frontend"))

# app = FastAPI(title="CyberSentinel AI")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# app.include_router(analyze_router)

# # --- SYSTEM MONITOR ---
# @app.websocket("/ws/system")
# async def system_monitor(websocket: WebSocket):
#     await websocket.accept()
#     try:
#         while True:
#             data = {
#                 "cpu": psutil.cpu_percent(),
#                 "ram": psutil.virtual_memory().percent,
#                 "net_sent": psutil.net_io_counters().bytes_sent,
#                 "net_recv": psutil.net_io_counters().bytes_recv
#             }
#             await websocket.send_json(data)
#             await asyncio.sleep(2)
#     except Exception as e:
#         print(f"Monitor Disconnected: {e}")

# # --- 🚀 ROUTING FIX ---

# # 1. LANDING PAGE -> DASHBOARD
# @app.get("/")
# async def serve_landing():
#     dash_path = os.path.join(static_dir, "dashboard.html")
#     if os.path.exists(dash_path):
#         return FileResponse(dash_path)
#     return JSONResponse(content={"error": "dashboard.html not found", "path": dash_path}, status_code=404)

# # 2. APP PAGE -> INDEX (Old CyberSentinel)
# @app.get("/analyze") 
# async def serve_analyze():
#     index_path = os.path.join(static_dir, "index.html")
#     if os.path.exists(index_path):
#         return FileResponse(index_path)
#     return JSONResponse(content={"error": "index.html not found", "path": index_path}, status_code=404)

# # 3. STATIC FILES
# if os.path.exists(static_dir):
#     app.mount("/static", StaticFiles(directory=static_dir), name="static")
#     app.mount("/", StaticFiles(directory=static_dir), name="root_static")

# if __name__ == "__main__":
#     print("🚀 Server running on: http://127.0.0.1:8001")
#     uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)

import os
import sys
import uvicorn
import asyncio
import psutil
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- 1. PATH & ENVIRONMENT SETUP ---
# Ensure Python sees the 'backend' folder as the root for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Load .env (local development only; Render uses Environment Variables settings)
load_dotenv()

# --- 2. IMPORTS (Database & Routes) ---
try:
    from app.database import Base, engine
    from routes.analyze import router as analyze_router
    print("[BOOT] ✅ Imports Successful (Database & Routes)")
except ImportError as e:
    print(f"\n[FATAL] ❌ Import Error: {e}")
    print(f"         Ensure 'routes/analyze.py' exists in {current_dir}")
    sys.exit(1)

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# --- 3. FRONTEND PATH LOGIC ---
# Locate the 'frontend' folder relative to this file
# In this structure: /backend/main.py -> ../frontend
static_dir = os.path.abspath(os.path.join(current_dir, "../frontend"))

if os.path.exists(static_dir):
    print(f"[BOOT] ✅ Frontend Folder Found: {static_dir}")
else:
    print(f"[FATAL] ❌ Frontend Folder NOT FOUND at: {static_dir}")
    # Fallback to avoid immediate crash, though UI won't load
    static_dir = current_dir

# --- 4. APP CONFIGURATION ---
app = FastAPI(title="CyberSentinel AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the Analysis Logic Router
app.include_router(analyze_router)

# --- 5. WEBSOCKET SYSTEM MONITOR ---
@app.websocket("/ws/system")
async def system_monitor(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = {
                "cpu": psutil.cpu_percent(),
                "ram": psutil.virtual_memory().percent,
                "net_sent": psutil.net_io_counters().bytes_sent,
                "net_recv": psutil.net_io_counters().bytes_recv
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except Exception as e:
        print(f"[WS] Monitor Disconnected: {e}")

# --- 6. ROUTING LOGIC ---

@app.get("/")
async def serve_landing():
    """
    Serves dashboard.html as the landing page.
    """
    target_file = os.path.join(static_dir, "dashboard.html")
    if os.path.exists(target_file):
        return FileResponse(target_file)
    return JSONResponse(status_code=404, content={"error": "dashboard.html not found", "path": target_file})

@app.get("/analyze") 
async def serve_analyze():
    """
    Serves index.html (Main Tool) when button is clicked.
    """
    target_file = os.path.join(static_dir, "index.html")
    if os.path.exists(target_file):
        return FileResponse(target_file)
    return JSONResponse(status_code=404, content={"error": "index.html not found", "path": target_file})

# --- 7. STATIC FILE MOUNTING ---
# This serves CSS, JS, and Images
if os.path.exists(static_dir):
    # Mount /static for specific assets
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    # Mount root / to serve styles/scripts relative to HTML files
    app.mount("/", StaticFiles(directory=static_dir), name="root_static")

# --- 8. SERVER STARTUP (CLOUD READY) ---
if __name__ == "__main__":
    # Get PORT from environment (Render sets this dynamically)
    # Default to 8001 if running locally
    port = int(os.environ.get("PORT", 8001))
    
    print(f"\n[READY] 🚀 Server starting on port {port}...")
    print(f"[INFO]  Cloud Mode: Host set to 0.0.0.0")
    
    # HOST MUST BE 0.0.0.0 for Render/Docker/Cloud
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)