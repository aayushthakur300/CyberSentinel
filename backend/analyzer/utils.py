import re
import base64
import os
import aiohttp

# --- De-obfuscation Logic ---
def attempt_deobfuscation(code: str):
    results = []
    
    # 1. Base64 Pattern
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, code)
    
    for m in matches:
        try:
            decoded = base64.b64decode(m).decode('utf-8')
            if len(decoded) > 5 and all(c.isprintable() or c.isspace() for c in decoded):
                results.append(f"Decoded Base64: {decoded[:100]}...")
        except:
            continue

    # 2. Hex Pattern
    hex_pattern = r'(\\x[0-9a-fA-F]{2}){5,}'
    hex_matches = re.findall(hex_pattern, code)
    if hex_matches:
        results.append("Hex-encoded strings detected (Automated decoding complex).")

    return results if results else ["No simple obfuscation patterns detected."]

# --- VirusTotal Logic ---
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files"

async def check_virustotal(file_hash: str):
    # 🔥 STRICT MODE: If no key, tell user to get one
    if not VT_API_KEY:
        return {
            "error": "VirusTotal API Key is missing. Please set your own key in environment variables to use this feature."
        }

    # REAL MODE: Call the actual API
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{VT_URL}/{file_hash}", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    return {
                        "malicious": stats['malicious'],
                        "suspicious": stats['suspicious'],
                        "harmless": stats['harmless'],
                        # 🔥 FIX: Return the Website Link (GUI) instead of the API Link
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
                elif resp.status == 404:
                    return {"status": "Clean/Unknown (Not found in VT database)"}
                elif resp.status == 401:
                    return {"error": "Invalid VirusTotal API Key. Please check your configuration."}
                else:
                    return {"error": f"VT API Error: {resp.status}"}
        except Exception as e:
            return {"error": f"Connection failed: {str(e)}"}