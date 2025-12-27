# import os
# import uvicorn
# import asyncio
# import psutil
# from contextlib import asynccontextmanager
# from fastapi import FastAPI, WebSocket
# from fastapi.staticfiles import StaticFiles
# from fastapi.responses import FileResponse
# from fastapi.middleware.cors import CORSMiddleware
# from dotenv import load_dotenv

# load_dotenv()
# from app.database import Base, engine
# from routes.analyze import router as analyze_router

# Base.metadata.create_all(bind=engine)

# # Path Logic
# current_dir = os.path.dirname(os.path.abspath(__file__))
# frontend_dir = os.path.abspath(os.path.join(current_dir, "../frontend"))

# app = FastAPI(title="CyberSentinel AI")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# app.include_router(analyze_router)

# # --- 🔥 LIVE HARDWARE NEURAL LINK ---
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
#             await asyncio.sleep(2) # Update every 2 seconds
#     except Exception as e:
#         print(f"Monitor Disconnected: {e}")

# # --- PAGE SERVING ---
# @app.get("/")
# async def serve_landing():
#     return FileResponse(os.path.join(frontend_dir, "index.html"))

# @app.get("/analyze")
# async def serve_dashboard():
#     return FileResponse(os.path.join(frontend_dir, "dashboard.html"))

# if os.path.exists(frontend_dir):
#     app.mount("/", StaticFiles(directory=frontend_dir), name="static")

# if __name__ == "__main__":
#     # Restored the clickable link
#     print("Server running on: http://127.0.0.1:8001") 
#     uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
import os
import sys
import uvicorn
import asyncio
import psutil
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- 🔥 FIX 1: PATH SETUP ---
# This ensures Python sees the 'backend' folder as the root.
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

load_dotenv()

# --- 🔥 FIX 2: CORRECT IMPORTS ---
# We use 'app.routers.analyze' because the file is inside backend/app/routers/
try:
    from app.database import Base, engine
    # ✅ CORRECTED LINE BELOW (Changed 'routes' to 'app.routers')
    from routes.analyze import router as analyze_router
except ImportError as e:
    print("\n❌ IMPORT ERROR:")
    print(f"   {e}")
    print("   --------------------------------------------------------")
    print("   CHECK THIS: 1. Does 'backend/app/routers/analyze.py' exist?")
    print("   2. Does 'backend/app/__init__.py' exist?")
    print("   --------------------------------------------------------\n")
    sys.exit(1)

# Initialize DB
Base.metadata.create_all(bind=engine)

# --- FIX 3: STATIC FILES PATH ---
static_dir = os.path.abspath(os.path.join(current_dir, "../static"))
if not os.path.exists(static_dir):
    # Fallback: Try 'frontend' if 'static' doesn't exist
    static_dir = os.path.abspath(os.path.join(current_dir, "../frontend"))

app = FastAPI(title="CyberSentinel AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)

# --- SYSTEM MONITOR ---
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
        print(f"Monitor Disconnected: {e}")

# --- PAGE SERVING ---
@app.get("/")
async def serve_landing():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": f"index.html not found in {static_dir}"}

@app.get("/dashboard") 
async def serve_dashboard():
    dash_path = os.path.join(static_dir, "dashboard.html")
    if os.path.exists(dash_path):
        return FileResponse(dash_path)
    return {"error": "dashboard.html not found"}

# Mount Static Files
if os.path.exists(static_dir):
    print(f"📂 Serving static files from: {static_dir}")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static_root")
else:
    print(f"⚠️ WARNING: Could not find 'static' or 'frontend' folder at {static_dir}")

if __name__ == "__main__":
    print(f"🚀 Server running on: http://127.0.0.1:8001")
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)