from stegano import lsb
from io import BytesIO
from PIL import Image
import re

# 🔥 CRITICAL: Connect to the MITRE Threat Brain
try:
    from .mitre_mapping import get_mitre_tag, MITRE_SIGNATURES
except ImportError:
    # Fallback for standalone testing
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"
    MITRE_SIGNATURES = {}

def scan_content_for_threats(text_content):
    """
    Scans a string for malicious signatures and returns a list of threat descriptions.
    """
    detected_threats = []
    if not text_content: 
        return detected_threats
        
    text_lower = text_content.lower()
    
    for signature in MITRE_SIGNATURES.keys():
        if signature.lower() in text_lower:
            tag = get_mitre_tag(signature, f"Hidden Artifact: '{signature}'")
            detected_threats.append(tag)
            
    return detected_threats

def analyze_steganography(file_content: bytes):
    # 1. Initialize the Dashboard-Ready Structure
    # This matches exactly what your Frontend needs to render the charts
    response_payload = {
        "has_hidden_data": False,
        "hidden_message": None,
        "threat_score": 0,         # UI needs this
        "status": "SAFE",          # UI needs this
        "mitre_tags": [],          # UI needs a list of objects
        "radar_chart": {           # UI needs these 5 axes
            "Exfiltration": 0,
            "Obfuscation": 0,
            "Crypto": 0,
            "Command": 0,
            "Spyware": 0
        },
        "details": []
    }

    all_behaviors = []
    found_signatures = []

    # =========================================================================
    # 2. LSB (Least Significant Bit) ANALYSIS
    # =========================================================================
    try:
        # Load image into memory
        img = Image.open(BytesIO(file_content))
        
        # FIX: Convert Transparent Images (RGBA/P) to RGB to prevent crashes
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # Save clean RGB version to buffer for scanning
        rgb_buffer = BytesIO()
        img.save(rgb_buffer, format="PNG")
        rgb_buffer.seek(0)

        # Attempt to reveal hidden LSB data
        secret = lsb.reveal(rgb_buffer)
        
        if secret:
            response_payload["has_hidden_data"] = True
            response_payload["hidden_message"] = secret[:200] + "..." if len(secret) > 200 else secret
            
            # Add basic Steganography tag
            all_behaviors.append("Steganography Detected (LSB)")
            
            # 🔥 CRITICAL: Scan the HIDDEN MESSAGE itself for code/threats
            hidden_threats = scan_content_for_threats(secret)
            found_signatures.extend(hidden_threats)
            
    except Exception:
        pass

    # =========================================================================
    # 3. RAW BYTE & METADATA ANALYSIS
    # =========================================================================
    try:
        # Decode binary to text to find appended scripts
        raw_text = file_content.decode('latin-1')
        found_signatures.extend(scan_content_for_threats(raw_text))

        # Check Metadata
        img = Image.open(BytesIO(file_content))
        if img.info:
            for key, val in img.info.items():
                found_signatures.extend(scan_content_for_threats(str(val)))
                
    except Exception:
        pass

    # =========================================================================
    # 4. CALCULATE DASHBOARD METRICS (The UI Fix)
    # =========================================================================
    
    # Clean up findings
    unique_threats = list(set(found_signatures))
    response_payload["details"] = unique_threats
    
    # Calculate Radar Chart values dynamically
    if response_payload["has_hidden_data"]:
        response_payload["radar_chart"]["Obfuscation"] = 95
        response_payload["radar_chart"]["Exfiltration"] = 80 # Stego is exfiltration by definition
        response_payload["threat_score"] = 75
        response_payload["status"] = "SUSPICIOUS"
        
        # Add a proper MITRE tag object for the UI
        response_payload["mitre_tags"].append({
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "desc": "Adversary is hiding data within digital images (Steganography)."
        })

    # If we found specific malicious code signatures (e.g. PHP, PowerShell)
    if unique_threats:
        response_payload["threat_score"] = 96
        response_payload["status"] = "CRITICAL"
        
        # Boost specific radar axes based on keywords
        for threat in unique_threats:
            t_str = str(threat).lower()
            if "cmd" in t_str or "exec" in t_str or "powershell" in t_str:
                response_payload["radar_chart"]["Command"] = 90
            if "crypto" in t_str or "aes" in t_str:
                response_payload["radar_chart"]["Crypto"] = 85
            if "socket" in t_str or "http" in t_str:
                response_payload["radar_chart"]["Spyware"] = 85

            # Convert string tags to UI objects if they aren't already
            if isinstance(threat, str):
                response_payload["mitre_tags"].append({
                    "id": "ALERT",
                    "name": "Malicious Signature",
                    "desc": threat
                })

    # If nothing found, provide the "Clean" state explicitly
    if not response_payload["has_hidden_data"] and not unique_threats:
        response_payload["mitre_tags"].append({
            "id": "N/A",
            "name": "No Threats Detected",
            "desc": "Image analysis passed LSB and signature checks."
        })

    return response_payload


# from stegano import lsb
# from io import BytesIO
# from PIL import Image
# import re

# # 🔥 CRITICAL FIX: Connect to the New MITRE Class Brain
# try:
#     from analyzer.mitre_mapping import MITRE_ENGINE
# except ImportError:
#     # Safe fallback if engine is missing during testing
#     MITRE_ENGINE = None

# def scan_content_for_threats(text_content):
#     """
#     Scans a string (hidden message) using the Central MITRE Engine.
#     Returns a list of formatted threat strings.
#     """
#     detected_threats = []
#     if not text_content: 
#         return detected_threats
    
#     # Use the Master Engine if available
#     if MITRE_ENGINE:
#         # The engine returns a list of dicts: [{'id': 'T1059', 'name': '...', ...}]
#         findings = MITRE_ENGINE.scan(text_content)
#         for f in findings:
#             # Format nicely for the Stego report
#             tag = f"[{f['id']}] Hidden Payload: {f['name']}"
#             detected_threats.append(tag)
            
#     return detected_threats

# def analyze_steganography(file_content: bytes):
#     # 1. Initialize the Dashboard-Ready Structure
#     # This matches exactly what your Frontend needs to render the charts
#     response_payload = {
#         "has_hidden_data": False,
#         "hidden_message": None,
#         "threat_score": 0,         # UI needs this
#         "status": "SAFE",          # UI needs this
#         "mitre_tags": [],          # UI needs a list of objects
#         "radar_chart": {           # UI needs these 5 axes
#             "Exfiltration": 0,
#             "Obfuscation": 0,
#             "Crypto/Ransom": 0,
#             "C2": 0,
#             "Spyware": 0,
#             "PrivlegeEsc": 0,
#             "Reconnaissance": 0,
#             "Persistence": 0
#         },
#         "details": []
#     }
#     all_behaviors = []
#     found_signatures = []

#     # =========================================================================
#     # 2. LSB (Least Significant Bit) ANALYSIS
#     # =========================================================================
#     try:
#         # Load image into memory
#         img = Image.open(BytesIO(file_content))
        
#         # FIX: Convert Transparent Images (RGBA/P) to RGB to prevent crashes
#         if img.mode != 'RGB':
#             img = img.convert('RGB')

#         # Save clean RGB version to buffer for scanning
#         rgb_buffer = BytesIO()
#         img.save(rgb_buffer, format="PNG")
#         rgb_buffer.seek(0)

#         # Attempt to reveal hidden LSB data
#         secret = lsb.reveal(rgb_buffer)
        
#         if secret:
#             response_payload["has_hidden_data"] = True
#             response_payload["hidden_message"] = secret[:200] + "..." if len(secret) > 200 else secret
            
#             # Add basic Steganography tag
#             all_behaviors.append("Steganography Detected (LSB)")
            
#             # 🔥 CRITICAL: Scan the HIDDEN MESSAGE itself for code/threats
#             hidden_threats = scan_content_for_threats(secret)
#             found_signatures.extend(hidden_threats)
            
#     except Exception:
#         pass

#     # =========================================================================
#     # 3. RAW BYTE & METADATA ANALYSIS
#     # =========================================================================
#     try:
#         # Decode binary to text to find appended scripts (e.g. PHP appended to JPG)
#         try:
#             raw_text = file_content.decode('latin-1')
#         except:
#             raw_text = file_content.decode('utf-8', errors='ignore')
            
#         found_signatures.extend(scan_content_for_threats(raw_text))

#         # Check Metadata (EXIF, etc.)
#         img = Image.open(BytesIO(file_content))
#         if hasattr(img, 'info') and img.info:
#             for key, val in img.info.items():
#                 found_signatures.extend(scan_content_for_threats(str(val)))
                
#     except Exception:
#         pass

#     # =========================================================================
#     # 4. CALCULATE DASHBOARD METRICS (The UI Fix)
#     # =========================================================================
    
#     # Clean up findings
#     unique_threats = list(set(found_signatures))
#     response_payload["details"] = unique_threats
    
#     # Calculate Radar Chart values dynamically
#     if response_payload["has_hidden_data"]:
#         response_payload["radar_chart"]["Obfuscation"] = 95
#         response_payload["radar_chart"]["Exfiltration"] = 80 # Stego is exfiltration by definition
#         response_payload["threat_score"] = 75
#         response_payload["status"] = "SUSPICIOUS"
        
#         # Add a proper MITRE tag object for the UI
#         response_payload["mitre_tags"].append({
#             "id": "T1027",
#             "name": "Obfuscated Files or Information",
#             "desc": "Adversary is hiding data within digital images (Steganography)."
#         })

#     # If we found specific malicious code signatures (e.g. PHP, PowerShell) inside the image
#     if unique_threats:
#         response_payload["threat_score"] = 96
#         response_payload["status"] = "CRITICAL"
        
#         # Boost specific radar axes based on keywords
#         for threat in unique_threats:
#             t_str = str(threat).lower()
#             if "cmd" in t_str or "exec" in t_str or "powershell" in t_str:
#                 response_payload["radar_chart"]["Command"] = 90
#             if "crypto" in t_str or "aes" in t_str or "ransom" in t_str:
#                 response_payload["radar_chart"]["Crypto"] = 85
#             if "socket" in t_str or "http" in t_str:
#                 response_payload["radar_chart"]["Spyware"] = 85

#             # Convert string tags to UI objects if they aren't already
#             if isinstance(threat, str):
#                 response_payload["mitre_tags"].append({
#                     "id": "ALERT",
#                     "name": "Malicious Signature",
#                     "desc": threat
#                 })

#     # If nothing found, provide the "Clean" state explicitly
#     if not response_payload["has_hidden_data"] and not unique_threats:
#         response_payload["mitre_tags"].append({
#             "id": "N/A",
#             "name": "No Threats Detected",
#             "desc": "Image analysis passed LSB and signature checks."
#         })

#     return response_payload

