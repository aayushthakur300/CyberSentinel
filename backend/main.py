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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- PATH SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

load_dotenv()

# --- IMPORTS ---
try:
    from app.database import Base, engine
    from routes.analyze import router as analyze_router
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

Base.metadata.create_all(bind=engine)

# --- FRONTEND FOLDER ---
# Looks for 'frontend' folder one level up
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

# --- 🚀 ROUTING FIX ---

# 1. LANDING PAGE -> DASHBOARD
@app.get("/")
async def serve_landing():
    dash_path = os.path.join(static_dir, "dashboard.html")
    if os.path.exists(dash_path):
        return FileResponse(dash_path)
    return JSONResponse(content={"error": "dashboard.html not found", "path": dash_path}, status_code=404)

# 2. APP PAGE -> INDEX (Old CyberSentinel)
@app.get("/analyze") 
async def serve_analyze():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(content={"error": "index.html not found", "path": index_path}, status_code=404)

# 3. STATIC FILES
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.mount("/", StaticFiles(directory=static_dir), name="root_static")

if __name__ == "__main__":
    print("🚀 Server running on: http://127.0.0.1:8001")
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)