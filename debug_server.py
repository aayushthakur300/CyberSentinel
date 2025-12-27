import sys
import os
import uvicorn

# 🔥 FIX: Force Python to see the current folder as the project root
# This fixes "ModuleNotFoundError: No module named 'app'"
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app.main import app
except ImportError as e:
    print("\n❌ CRITICAL ERROR: Could not import 'app.main'")
    print(f"   Error Details: {e}")
    print(f"   Current Directory: {os.getcwd()}")
    print("   Make sure the folder 'app' exists next to this script!")
    sys.exit(1)

print("\n" + "="*50)
print("🔍 SCANNING ALL REGISTERED ROUTES...")
print("="*50)

# Loop through all routes known to FastAPI
found_binary = False
for route in app.routes:
    if hasattr(route, "path"):
        methods = ", ".join(route.methods) if hasattr(route, "methods") else "ANY"
        print(f"  ✅ FOUND: {methods} -> {route.path}")
        
        if route.path == "/analyze/binary":
            found_binary = True

print("="*50)

if found_binary:
    print("🎉 GOOD NEWS: The route '/analyze/binary' exists!")
    print("   Your Frontend URL 'http://127.0.0.1:8001/analyze/binary' SHOULD work.")
else:
    print("❌ BAD NEWS: The route '/analyze/binary' is MISSING.")
    print("   Check if you have a double prefix (e.g., /analyze/analyze/binary)")
    print("   or if 'app.include_router(...)' is missing in main.py.")

print("\n🚀 STARTING SERVER NOW...")
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)