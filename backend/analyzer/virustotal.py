import os
import aiohttp
import logging
import traceback
from dotenv import load_dotenv

# Load API Key from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
logger = logging.getLogger(__name__)

async def check_virustotal(file_hash: str):
    """
    Queries VirusTotal API v3 for a file hash (SHA256).
    """
    # Check if key is missing or default
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_key_here":
        return {
            "success": False,
            "found": False, 
            "error": "API Key missing. Check .env file."
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                
                # 1. File Found in Database
                if response.status == 200:
                    data = await response.json()
                    # Use .get() to avoid crashes if keys are missing
                    attributes = data.get('data', {}).get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    return {
                        "success": True,  # Added for Frontend compatibility
                        "found": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "reputation": attributes.get('reputation', 0),
                        "scan_date": attributes.get('last_analysis_date', 'Unknown'),
                        "link": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
                
                # 2. File Not Found (It's a new or unique file)
                elif response.status == 404:
                    return {
                        "success": True,
                        "found": False, 
                        "message": "Hash not found in VirusTotal (File might be new/unique)"
                    }
                
                # 3. Quota Exceeded or Permission Denied
                elif response.status == 401:
                    return {"success": False, "found": False, "error": "Invalid API Key"}
                elif response.status == 429:
                    return {"success": False, "found": False, "error": "API Quota Exceeded (Wait 1 min)"}
                
                else:
                    return {"success": False, "found": False, "error": f"API Error {response.status}"}

    except Exception as e:
        logger.error(f"VirusTotal Connection Failed: {e}")
        traceback.print_exc()  # 🔥 Traceback added
        return {"success": False, "found": False, "error": str(e)}