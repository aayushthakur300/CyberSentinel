# import re
# import base64
# import os
# import aiohttp

# # --- De-obfuscation Logic ---
# def attempt_deobfuscation(code: str):
#     results = []
    
#     # 1. Base64 Pattern
#     base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
#     matches = re.findall(base64_pattern, code)
    
#     for m in matches:
#         try:
#             decoded = base64.b64decode(m).decode('utf-8')
#             if len(decoded) > 5 and all(c.isprintable() or c.isspace() for c in decoded):
#                 results.append(f"Decoded Base64: {decoded[:100]}...")
#         except:
#             continue

#     # 2. Hex Pattern
#     hex_pattern = r'(\\x[0-9a-fA-F]{2}){5,}'
#     hex_matches = re.findall(hex_pattern, code)
#     if hex_matches:
#         results.append("Hex-encoded strings detected (Automated decoding complex).")

#     return results if results else ["No simple obfuscation patterns detected."]

# # --- VirusTotal Logic ---
# VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
# VT_URL = "https://www.virustotal.com/api/v3/files"

# async def check_virustotal(file_hash: str):
#     # 🔥 STRICT MODE: If no key, tell user to get one
#     if not VT_API_KEY:
#         return {
#             "error": "VirusTotal API Key is missing. Please set your own key in environment variables to use this feature."
#         }

#     # REAL MODE: Call the actual API
#     headers = {"x-apikey": VT_API_KEY}
#     async with aiohttp.ClientSession() as session:
#         try:
#             async with session.get(f"{VT_URL}/{file_hash}", headers=headers) as resp:
#                 if resp.status == 200:
#                     data = await resp.json()
#                     stats = data['data']['attributes']['last_analysis_stats']
#                     return {
#                         "malicious": stats['malicious'],
#                         "suspicious": stats['suspicious'],
#                         "harmless": stats['harmless'],
#                         # 🔥 FIX: Return the Website Link (GUI) instead of the API Link
#                         "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
#                     }
#                 elif resp.status == 404:
#                     return {"status": "Clean/Unknown (Not found in VT database)"}
#                 elif resp.status == 401:
#                     return {"error": "Invalid VirusTotal API Key. Please check your configuration."}
#                 else:
#                     return {"error": f"VT API Error: {resp.status}"}
#         except Exception as e:
#             return {"error": f"Connection failed: {str(e)}"}

#current working <------
# import re
# import base64
# import os
# import aiohttp
# import string

# # =========================================================================
# # 1. RISK ENGINE & RADAR CHART CALCULATOR (8-AXIS)
# # =========================================================================

# # Maps generic keywords/Tags to Threat Scores (0-100)
# SEVERITY_MAP = {
#     "T1486": 95, "T1059": 90, "T1505": 90, "T1003": 95, "T1547": 85, # MITRE IDs
#     "CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20
# }

# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Analyzes behavior tags and calculates scores for 8 specific Radar Axes.
#     """
#     # The 8 Axes of the Radar Chart
#     matrix = {
#         "Exfiltration": 0, 
#         "Command & Control": 0, 
#         "Obfuscation": 0, 
#         "Spyware": 0, 
#         "Crypto/Ransom": 0, 
#         "Persistence": 0, 
#         "Privilege Esc": 0, 
#         "Reconnaissance": 0
#     }

#     # Keywords mapping to Axes
#     keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "exfil", "stealing", "T1041", "T1048"],
#         "Command & Control": ["c2", "socket", "connect", "reverse", "botnet", "bind", "listener", "T1095", "T1071", "T1572"],
#         "Obfuscation": ["base64", "xor", "packed", "rot13", "stego", "hidden", "T1027"],
#         "Spyware": ["keylog", "camera", "mic", "monitor", "screenshot", "clipboard", "T1056", "T1113"],
#         "Crypto/Ransom": ["encrypt", "wallet", "bitcoin", "miner", "ransom", "wannacry", "wipe", "delete", "T1486", "T1485"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "boot", "rootkit", "autorun", "T1547", "T1543"],
#         "Privilege Esc": ["admin", "root", "uac", "bypass", "sudo", "creds", "lsass", "mimikatz", "T1003", "T1078"],
#         "Reconnaissance": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "systeminfo", "T1082", "T1083"]
#     }

#     for tag in behaviors:
#         tag_lower = tag.lower()
        
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word.lower() in tag_lower:
#                     # Add score based on severity keyword in tag
#                     boost = 50 # Default hit
#                     if "critical" in tag_lower: boost = 90
#                     elif "high" in tag_lower: boost = 70
#                     elif "medium" in tag_lower: boost = 40
                    
#                     matrix[category] += boost
#                     break # Count once per category per tag

#     # Cap scores at 100 for the UI
#     for key in matrix:
#         if matrix[key] > 100: matrix[key] = 100
        
#     return matrix

# def calculate_risk(behaviors: list) -> int:
#     """
#     Calculates a single 0-100 Risk Score based on the most severe findings.
#     """
#     if not behaviors: return 0
    
#     scores = []
#     for behavior in behaviors:
#         score = 15 # Baseline noise
#         b_str = str(behavior).upper()
        
#         # Check Severity Map
#         for key, val in SEVERITY_MAP.items():
#             if key in b_str:
#                 score = max(score, val)
        
#         scores.append(score)

#     if not scores: return 0
    
#     # Formula: Max Score + (Density Boost)
#     max_risk = max(scores)
#     density = min(len(scores) * 2, 20) # Up to +20 for multiple findings
    
#     return int(min(max_risk + density, 100))


# # =========================================================================
# # 2. DE-OBFUSCATION LOGIC
# # =========================================================================
# def attempt_deobfuscation(code: str):
#     results = []
    
#     # 1. Base64 Pattern
#     base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
#     matches = re.findall(base64_pattern, code)
    
#     for m in matches:
#         try:
#             decoded = base64.b64decode(m).decode('utf-8')
#             # Filter out binary junk
#             if len(decoded) > 5 and all(c.isprintable() or c.isspace() for c in decoded):
#                 results.append(f"Decoded Base64: {decoded[:100]}...")
#         except:
#             continue

#     # 2. Hex Pattern
#     hex_pattern = r'(\\x[0-9a-fA-F]{2}){5,}'
#     hex_matches = re.findall(hex_pattern, code)
#     if hex_matches:
#         results.append("Hex-encoded strings detected (Automated decoding complex).")

#     return {"results": results, "pattern_found": len(results) > 0}


# # =========================================================================
# # 3. VIRUSTOTAL LOGIC
# # =========================================================================
# VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
# VT_URL = "https://www.virustotal.com/api/v3/files"

# async def check_virustotal(file_hash: str):
#     if not VT_API_KEY:
#         return {"error": "VirusTotal API Key is missing.", "success": False}

#     headers = {"x-apikey": VT_API_KEY}
    
#     async with aiohttp.ClientSession() as session:
#         try:
#             async with session.get(f"{VT_URL}/{file_hash}", headers=headers) as resp:
#                 if resp.status == 200:
#                     data = await resp.json()
#                     stats = data['data']['attributes']['last_analysis_stats']
#                     return {
#                         "success": True,
#                         "found": True,
#                         "malicious": stats['malicious'],
#                         "suspicious": stats['suspicious'],
#                         "harmless": stats['harmless'],
#                         "link": f"https://www.virustotal.com/gui/file/{file_hash}"
#                     }
#                 elif resp.status == 404:
#                     return {"success": True, "found": False, "status": "Clean/Unknown (Not found in VT)"}
#                 else:
#                     return {"success": False, "error": f"VT API Error: {resp.status}"}
#         except Exception as e:
#             return {"success": False, "error": f"Connection failed: {str(e)}"}

# import re
# import base64
# import os
# import aiohttp
# import string

# # =========================================================================
# # 1. RISK ENGINE & RADAR CHART CALCULATOR (8-AXIS)
# # =========================================================================

# # Maps generic keywords/Tags to Threat Scores (0-100)
# SEVERITY_MAP = {
#     "T1486": 95, "T1059": 90, "T1505": 90, "T1003": 95, "T1547": 85, 
#     "CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20
# }

# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Analyzes behavior tags and calculates scores for 8 specific Radar Axes.
#     🔥 KEYS NOW MATCH FRONTEND LABELS EXACTLY.
#     """
#     matrix = {
#         "Exfiltration": 0, 
#         "C2": 0, 
#         "Obfuscation": 0, 
#         "Spyware": 0, 
#         "Crypto": 0, 
#         "Persistence": 0, 
#         "PrivEsc": 0, 
#         "Recon": 0
#     }

#     # Keywords mapping to Axes
#     keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "exfil", "stealing", "T1041", "T1048"],
#         "C2": ["c2", "socket", "connect", "reverse", "botnet", "bind", "listener", "T1095", "T1071", "T1572"],
#         "Obfuscation": ["base64", "xor", "packed", "rot13", "stego", "hidden", "T1027"],
#         "Spyware": ["keylog", "camera", "mic", "monitor", "screenshot", "clipboard", "T1056", "T1113"],
#         "Crypto": ["encrypt", "wallet", "bitcoin", "miner", "ransom", "wannacry", "wipe", "delete", "T1486", "T1485"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "boot", "rootkit", "autorun", "T1547", "T1543"],
#         "PrivEsc": ["admin", "root", "uac", "bypass", "sudo", "creds", "lsass", "mimikatz", "T1003", "T1078"],
#         "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "systeminfo", "T1082", "T1083"]
#     }

#     for tag in behaviors:
#         tag_lower = str(tag).lower()
        
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word.lower() in tag_lower:
#                     # Add score based on severity keyword in tag
#                     boost = 50 
#                     if "critical" in tag_lower: boost = 90
#                     elif "high" in tag_lower: boost = 70
#                     elif "medium" in tag_lower: boost = 40
                    
#                     matrix[category] += boost
#                     break 

#     # Cap scores at 100
#     for key in matrix:
#         if matrix[key] > 100: matrix[key] = 100
        
#     return matrix

# def calculate_risk(behaviors: list) -> int:
#     """Calculates a single 0-100 Risk Score."""
#     if not behaviors: return 0
    
#     scores = []
#     for behavior in behaviors:
#         score = 15 # Baseline noise
#         b_str = str(behavior).upper()
#         for key, val in SEVERITY_MAP.items():
#             if key in b_str:
#                 score = max(score, val)
#         scores.append(score)

#     if not scores: return 0
    
#     max_risk = max(scores)
#     density = min(len(scores) * 2, 20) 
#     return int(min(max_risk + density, 100))


# # =========================================================================
# # 2. DE-OBFUSCATION LOGIC
# # =========================================================================
# def attempt_deobfuscation(code: str):
#     results = []
#     base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
#     matches = re.findall(base64_pattern, code)
    
#     for m in matches:
#         try:
#             decoded = base64.b64decode(m).decode('utf-8')
#             if len(decoded) > 5 and all(c.isprintable() or c.isspace() for c in decoded):
#                 results.append(f"Decoded Base64: {decoded[:100]}...")
#         except: continue

#     return {"results": results, "pattern_found": len(results) > 0}


# # =========================================================================
# # 3. VIRUSTOTAL LOGIC
# # =========================================================================
# VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
# VT_URL = "https://www.virustotal.com/api/v3/files"

# async def check_virustotal(file_hash: str):
#     if not VT_API_KEY:
#         return {"success": False, "error": "VirusTotal API Key missing on Server."}

#     headers = {"x-apikey": VT_API_KEY}
    
#     async with aiohttp.ClientSession() as session:
#         try:
#             async with session.get(f"{VT_URL}/{file_hash}", headers=headers) as resp:
#                 if resp.status == 200:
#                     data = await resp.json()
#                     stats = data['data']['attributes']['last_analysis_stats']
#                     return {
#                         "success": True,
#                         "found": True,
#                         "malicious": stats['malicious'],
#                         "suspicious": stats['suspicious'],
#                         "harmless": stats['harmless'],
#                         "link": f"https://www.virustotal.com/gui/file/{file_hash}"
#                     }
#                 elif resp.status == 404:
#                     return {"success": True, "found": False, "status": "Clean/Unknown (Not found in VT)"}
#                 else:
#                     return {"success": False, "error": f"VT API Error: {resp.status}"}
#         except Exception as e:
#             return {"success": False, "error": f"Connection failed: {str(e)}"}

import re
import base64
import os
import aiohttp
import string

# =========================================================================
# 1. PRECISE THREAT SCORING CONFIGURATION
# =========================================================================

# 🔥 MITRE T-CODE WEIGHTS (The Source of Truth)
# These are the "Anchor" scores. If a tag has [Txxxx], we use this baseline.
MITRE_SEVERITY_MAP = {
    # CRITICAL (90-100) - Active Destruction / Control
    "T1486": 100, # Data Encrypted for Impact (Ransomware)
    "T1485": 100, # Data Destruction (Wiper)
    "T1490": 100, # Inhibit System Recovery (Shadow Copy Delete)
    "T1059": 90,  # Command and Scripting Interpreter (Shells)
    "T1003": 95,  # Credential Dumping (Mimikatz)
    "T1505": 90,  # Server Software Component (Web Shell)
    
    # HIGH (70-89) - Persistence / Exfil / Evasion
    "T1547": 85,  # Boot or Logon Autostart Execution
    "T1055": 85,  # Process Injection
    "T1572": 80,  # Protocol Tunneling
    "T1041": 80,  # Exfiltration Over C2 Channel
    "T1048": 80,  # Exfiltration Over Alternative Protocol
    "T1071": 75,  # Application Layer Protocol (C2)
    "T1090": 75,  # Proxy
    "T1548": 80,  # Abuse Elevation Control Mechanism (UAC Bypass)
    
    # MEDIUM (40-69) - Obfuscation / Discovery (Active)
    "T1027": 60,  # Obfuscated Files or Information
    "T1140": 55,  # Deobfuscate/Decode Files or Information
    "T1056": 65,  # Input Capture (Keyloggers)
    "T1113": 60,  # Screen Capture
    "T1497": 50,  # Virtualization/Sandbox Evasion
    
    # LOW (10-39) - Reconnaissance / Noise
    "T1082": 30,  # System Information Discovery
    "T1083": 30,  # File and Directory Discovery
    "T1033": 25,  # System Owner/User Discovery
    "T1046": 30,  # Network Service Scanning
    "T1012": 20,  # Query Registry
    "T1057": 20,  # Process Discovery
}

# 🛡️ FALLBACK KEYWORDS (If MITRE ID is missing)
# Combined your comprehensive list with efficient lookup structure
FALLBACK_WEIGHTS = {
    # CRITICAL
    "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
    "REVERSE SHELL": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
    "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
    "METERPRETER": 95, "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,
    
    # HIGH
    "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
    "KEYLOGGER": 85, "SPYWARE": 80, "C2": 80, "BOTNET": 80, "EXFILTRATION": 80,
    "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75,
    
    # MEDIUM
    "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
    "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
    "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,
    
    # LOW
    "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10, "SCAN": 30
}

# =========================================================================
# 2. RISK ENGINE & RADAR CHART CALCULATOR (8-AXIS)
# =========================================================================

def calculate_risk_matrix(behaviors: list) -> dict:
    """
    Generates the 8-Axis Radar Chart Data.
    Standardized Keys: Exfil, C2, Obfuscation, Spyware, Crypto, Persistence, PrivEsc, Recon
    """
    matrix = {
        "Exfiltration": 0,  "C2": 0,           "Obfuscation": 0, "Spyware": 0, 
        "Crypto": 0,        "Persistence": 0,  "PrivEsc": 0,     "Recon": 0
    }

    # Precise Mapping of MITRE IDs to Radar Axes 
    # This prevents "Recon" keywords from polluting the "C2" axis.
    mitre_to_axis = {
        "T1041": "Exfiltration", "T1048": "Exfiltration", "T1020": "Exfiltration",
        "T1071": "C2", "T1090": "C2", "T1095": "C2", "T1572": "C2", "T1105": "C2",
        "T1027": "Obfuscation", "T1140": "Obfuscation", "T1006": "Obfuscation",
        "T1056": "Spyware", "T1113": "Spyware", "T1123": "Spyware",
        "T1486": "Crypto", "T1485": "Crypto", "T1490": "Crypto",
        "T1547": "Persistence", "T1543": "Persistence", "T1053": "Persistence",
        "T1548": "PrivEsc", "T1068": "PrivEsc", "T1003": "PrivEsc",
        "T1082": "Recon", "T1083": "Recon", "T1046": "Recon", "T1033": "Recon"
    }

    # Keyword Fallbacks for Axes
    keywords = {
        "Exfiltration": ["upload", "ftp", "smtp", "exfil", "steal", "transfer"],
        "C2": ["c2", "socket", "connect", "reverse", "bind", "shell", "botnet", "listener"],
        "Obfuscation": ["base64", "xor", "packed", "rot13", "hidden", "stego", "eval"],
        "Spyware": ["keylog", "hook", "camera", "mic", "clipboard", "monitor", "screen"],
        "Crypto": ["encrypt", "aes", "wallet", "bitcoin", "miner", "ransom", "wannacry", "wipe"],
        "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "rootkit"],
        "PrivEsc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "lsass", "mimikatz"],
        "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery", "systeminfo"]
    }

    for tag in behaviors:
        tag_upper = str(tag).upper()
        
        # A. MITRE ID PRIORITY (The Gold Standard)
        mitre_match = re.search(r"\[(T\d+)\]", tag_upper)
        if mitre_match:
            t_id = mitre_match.group(1)
            
            # 1. Update Axis based on Mapping
            if t_id in mitre_to_axis:
                axis = mitre_to_axis[t_id]
                score = MITRE_SEVERITY_MAP.get(t_id, 50) # Default to 50 if ID known but unweighted
                matrix[axis] = max(matrix[axis], score)
            
            # 2. Heuristic Categorization based on ID Range
            # (Fallback if ID isn't in specific map but is valid MITRE)
            elif t_id.startswith("T14"): matrix["Crypto"] = max(matrix["Crypto"], 90) # Impact
            elif t_id.startswith("T10"): matrix["C2"] = max(matrix["C2"], 50) # Command

        # B. KEYWORD FALLBACK (If no MITRE ID or to boost score)
        for category, distinct_words in keywords.items():
            for word in distinct_words:
                if word.upper() in tag_upper:
                    boost = 40
                    if "CRITICAL" in tag_upper: boost = 90
                    elif "HIGH" in tag_upper: boost = 75
                    elif "MEDIUM" in tag_upper: boost = 50
                    
                    # Accumulate score but cap carefully
                    matrix[category] = max(matrix[category], boost)
                    break 

    # Final Cap at 100
    for k in matrix:
        if matrix[k] > 100: matrix[k] = 100
        
    return matrix


def calculate_risk(behaviors: list) -> int:
    """
    Calculates overall Threat Score (0-100) with weighted logic.
    Prioritizes the HIGHEST single threat found.
    """
    if not behaviors: return 0
    scores = []
    
    for behavior in behaviors:
        score = 10 # Baseline noise
        b_str = str(behavior).upper()
        
        # 1. MITRE ID Lookup (Precise & Fast)
        mitre_match = re.search(r"\[(T\d+)\]", b_str)
        if mitre_match:
            t_id = mitre_match.group(1)
            if t_id in MITRE_SEVERITY_MAP:
                score = MITRE_SEVERITY_MAP[t_id]
        
        # 2. Keyword Lookup (Broad Coverage)
        for key, weight in FALLBACK_WEIGHTS.items():
            if key in b_str:
                score = max(score, weight)
        
        scores.append(score)

    if not scores: return 0
    
    # 3. Final Calculation Logic
    # We take the MAXIMUM single threat score found.
    # We add a small "Density Bonus" if multiple threats exist.
    max_risk = max(scores)
    density_bonus = min(len(scores) * 2, 15) # +2 per finding, max +15
    
    # A single Critical threat (e.g. Ransomware) makes the whole file Critical.
    # A bunch of Low threats (Recon) shouldn't sum up to Critical.
    final_score = max_risk 
    
    # Only add density if the base risk is already significant (>40)
    if max_risk > 40:
        final_score += density_bonus

    return int(min(final_score, 100))


# =========================================================================
# 3. DE-OBFUSCATION LOGIC
# =========================================================================
def attempt_deobfuscation(code: str):
    results = []
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, code)
    
    for m in matches:
        try:
            decoded = base64.b64decode(m).decode('utf-8')
            # Heuristic: Valid code/text usually has printable chars
            if len(decoded) > 5 and all(c.isprintable() or c.isspace() for c in decoded):
                results.append(f"Decoded Base64: {decoded[:100]}...")
        except: continue

    return {"results": results, "pattern_found": len(results) > 0}


# =========================================================================
# 4. VIRUSTOTAL LOGIC
# =========================================================================
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files"

async def check_virustotal(file_hash: str):
    if not VT_API_KEY:
        return {"success": False, "error": "VirusTotal API Key missing on Server."}

    headers = {"x-apikey": VT_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{VT_URL}/{file_hash}", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    return {
                        "success": True,
                        "found": True,
                        "malicious": stats['malicious'],
                        "suspicious": stats['suspicious'],
                        "harmless": stats['harmless'],
                        "link": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
                elif resp.status == 404:
                    return {"success": True, "found": False, "status": "Clean/Unknown (Not found in VT)"}
                else:
                    return {"success": False, "error": f"VT API Error: {resp.status}"}
        except Exception as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}