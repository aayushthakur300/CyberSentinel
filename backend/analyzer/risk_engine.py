# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     # Fallback to prevent crash if file is missing during setup
#     MITRE_SIGNATURES = {}

# # --- COMPREHENSIVE FALLBACK WEIGHTS ---
# # Covers generic keywords for 50+ attacks across 20+ languages.
# FALLBACK_WEIGHTS = {
#     # 🔴 CRITICAL THREATS (90-100)
#     "RANSOMWARE": 100,
#     "WANNACRY": 100,
#     "ROOTKIT": 100,
#     "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95,
#     "REMOTE CODE EXECUTION": 95,
#     "RCE": 95,
#     "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95,
#     "PRIVILEGE ESCALATION": 95,
#     "SHADOW COPY": 95,
#     "MEMORY INJECTION": 95,
#     "PROCESS INJECTION": 95,
#     "CREATEREMOTETHREAD": 95,
#     "VIRTUALALLOC": 90,
#     "METERPRETER": 95,
#     "MIMIKATZ": 95,
#     "LSASS": 95,
#     "ETERNALBLUE": 95,
    
#     # 🟠 HIGH THREATS (70-89)
#     "BUFFER OVERFLOW": 85,
#     "HEAP OVERFLOW": 85,
#     "XXE": 85,
#     "SSRF": 85,
#     "CROSS-SITE SCRIPTING": 80,
#     "XSS": 80,
#     "PATH TRAVERSAL": 80,
#     "LOCAL FILE INCLUSION": 80,
#     "LFI": 80,
#     "KEYLOGGER": 85,
#     "SPYWARE": 80,
#     "C2": 80,
#     "COMMAND AND CONTROL": 80,
#     "BEACON": 80,
#     "BOTNET": 80,
#     "EXFILTRATION": 80,
#     "POWERSHELL -ENC": 80,
#     "BASE64 PAYLOAD": 75,
#     "BIND SHELL": 75,
#     "WIFI DUMP": 75,
#     "HASH DUMP": 75,

#     # 🟡 MEDIUM THREATS (40-69)
#     "OBFUSCATION": 60,
#     "PACKED BINARY": 60,
#     "UPX": 60,
#     "HIGH ENTROPY": 55,
#     "PORT SCAN": 50,
#     "NETWORK SCAN": 50,
#     "REFLECTION": 50,
#     "DYNAMIC LOADING": 50,
#     "DLL INJECTION": 65,
#     "HOOKING": 60,
#     "ANTI-DEBUG": 60,
#     "VM EVASION": 60,
#     "SANDBOX EVASION": 60,
#     "CRYPTO MINING": 55,
#     "MINER": 55,
#     "HARDCODED PASSWORD": 65,
#     "HARDCODED KEY": 65,
#     "AWS KEY": 65,

#     # 🔵 LOW / INFO (10-39)
#     "INFO": 10,
#     "RECONNAISSANCE": 30,
#     "WHOAMI": 20,
#     "IPCONFIG": 20,
#     "SYSTEMINFO": 20,
#     "PING": 10,
#     "NETSTAT": 15,
#     "TASKLIST": 15
# }

# import re

# # --- KEYWORDS FOR 8-AXIS RADAR CHART ---
# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Analyzes behavior tags and calculates scores for 8 specific axes.
#     """
#     # 🔥 CRITICAL: This Dictionary determines what shows on the graph.
#     # If this has 5 keys, the graph will have 5 points.
#     # We are setting it to 8 keys here.
#     matrix = {
#         "Exfiltration": 0,    
#         "Command & Control": 0, 
#         "Obfuscation": 0,     
#         "Spyware": 0,         
#         "Crypto/Ransom": 0,   
#         "Persistence": 0,     # <--- NEW AXIS
#         "Privilege Esc": 0,   # <--- NEW AXIS
#         "Reconnaissance": 0   # <--- NEW AXIS
#     }

#     keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "email", "post", "exfil", "upload_file", "stealing"],
#         "Command & Control": ["c2", "socket", "connect", "http", "reverse_shell", "bind_shell", "remote"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "clipboard", "monitor", "screenshot"],
#         "Crypto/Ransom": ["encrypt", "aes", "wallet", "bitcoin", "monero", "miner", "ransom"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "cron"],
#         "Privilege Esc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system"],
#         "Reconnaissance": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery"]
#     }

#     for tag in behaviors:
#         tag_lower = tag.lower()
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word in tag_lower:
#                     if any(x in tag_lower for x in ["critical", "high", "alert"]):
#                         matrix[category] += 50
#                     else:
#                         matrix[category] += 25
#                     break 

#     # Cap scores at 100
#     for key in matrix:
#         if matrix[key] > 100: matrix[key] = 100
            
#     return matrix

# # ... (Keep your existing calculate_risk function below this)

# def calculate_risk(behaviors):
#     """
#     Professional Risk Scoring Algorithm (FAANG Standard).
    
#     Logic:
#     1. Base Score: Driven by the highest severity MITRE Tactic found (Primary Source).
#     2. Fallback Score: Driven by keyword matching if MITRE tag is absent.
#     3. Density Score: Adds weight for the *number* of distinct threats.
#     4. Kill Chain Multiplier: Boosts score if threats span multiple tactics 
#        (e.g. Execution + Persistence + Exfiltration).
#     """
#     if not behaviors:
#         return 0

#     scores = []
#     tactic_types = set()

#     for behavior in behaviors:
#         score = 0
#         found_mitre = False
        
#         # --- 1. MITRE ATT&CK LOOKUP (Primary Source) ---
#         # Look for [Txxxx] tags in the behavior string
#         if "[" in behavior and "]" in behavior:
#             try:
#                 # Extract ID, e.g., "[T1059]"
#                 tag_parts = behavior.split("[")[1].split("]")
#                 if tag_parts:
#                     tag_id = tag_parts[0]
                    
#                     # Reverse lookup the ID in our Master DB to get severity
#                     for sig, info in MITRE_SIGNATURES.items():
#                         if info.get('id') == tag_id:
#                             severity = info.get('severity', 'Low')
#                             if severity == "Critical": score = 95
#                             elif severity == "High": score = 75
#                             elif severity == "Medium": score = 45
#                             elif severity == "Low": score = 15
                            
#                             # Add to kill chain tracking (Heuristic based on T-Code structure)
#                             # T10xx: Execution, T11xx: Persistence/PrivEsc, T15xx: Defense Evasion
#                             if tag_id.startswith("T10"): tactic_types.add("Execution")
#                             elif tag_id.startswith("T11"): tactic_types.add("Persistence")
#                             elif tag_id.startswith("T15"): tactic_types.add("Evasion")
#                             elif tag_id.startswith("T14"): tactic_types.add("Impact")
#                             elif tag_id.startswith("T12"): tactic_types.add("Discovery")
                            
#                             found_mitre = True
#                             break
#             except Exception:
#                 pass # Malformed tag, fall through to keyword check

#         # --- 2. KEYWORD HEURISTICS (Fallback Safety Net) ---
#         # If no MITRE tag, check specific keywords from the massive dictionary above
#         if not found_mitre:
#             behavior_upper = behavior.upper()
#             best_match = 0
#             for key, weight in FALLBACK_WEIGHTS.items():
#                 if key in behavior_upper:
#                     if weight > best_match:
#                         best_match = weight
            
#             score = best_match
            
#             # Default for unknown behaviors that aren't in fallback list
#             if score == 0: score = 10

#         scores.append(score)

#     if not scores:
#         return 0

#     # --- 3. ADVANCED SCORING ALGORITHM ---
    
#     # A. The anchor is the highest single threat found
#     max_risk = max(scores)
    
#     # B. Calculate "Threat Density" (Sum of remaining threats scaled down)
#     # This ensures 10 medium threats > 1 medium threat, but 1 Critical always wins.
#     # We sort to remove the max score used in A.
#     remaining_scores = sorted(scores, reverse=True)[1:] 
    
#     # Add 10% of every other threat found
#     density_adder = sum(s * 0.10 for s in remaining_scores) 
    
#     # C. Kill Chain Multiplier (Diversity Boost)
#     # If we see 3+ distinct tactic types (e.g. Exec + Persist + Impact), it's an advanced attack.
#     chain_multiplier = 1.0
#     if len(tactic_types) >= 3:
#         chain_multiplier = 1.25 # +25% Risk for complex attack chain
#     elif len(tactic_types) == 2:
#         chain_multiplier = 1.10 # +10% Risk for multi-stage attack
        
#     final_score = (max_risk + density_adder) * chain_multiplier

#     # D. Hard Cap at 100 (Cannot exceed 100%)
#     return int(min(final_score, 100))
# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     # Fallback to prevent crash if file is missing during setup
#     MITRE_SIGNATURES = {}

# # --- COMPREHENSIVE FALLBACK WEIGHTS ---
# # Covers generic keywords for 50+ attacks across 20+ languages.
# FALLBACK_WEIGHTS = {
#     # 🔴 CRITICAL THREATS (90-100)
#     "RANSOMWARE": 100,
#     "WANNACRY": 100,
#     "ROOTKIT": 100,
#     "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95,
#     "REMOTE CODE EXECUTION": 95,
#     "RCE": 95,
#     "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95,
#     "PRIVILEGE ESCALATION": 95,
#     "SHADOW COPY": 95,
#     "MEMORY INJECTION": 95,
#     "PROCESS INJECTION": 95,
#     "CREATEREMOTETHREAD": 95,
#     "VIRTUALALLOC": 90,
#     "METERPRETER": 95,
#     "MIMIKATZ": 95,
#     "LSASS": 95,
#     "ETERNALBLUE": 95,
    
#     # 🟠 HIGH THREATS (70-89)
#     "BUFFER OVERFLOW": 85,
#     "HEAP OVERFLOW": 85,
#     "XXE": 85,
#     "SSRF": 85,
#     "CROSS-SITE SCRIPTING": 80,
#     "XSS": 80,
#     "PATH TRAVERSAL": 80,
#     "LOCAL FILE INCLUSION": 80,
#     "LFI": 80,
#     "KEYLOGGER": 85,
#     "SPYWARE": 80,
#     "C2": 80,
#     "COMMAND AND CONTROL": 80,
#     "BEACON": 80,
#     "BOTNET": 80,
#     "EXFILTRATION": 80,
#     "POWERSHELL -ENC": 80,
#     "BASE64 PAYLOAD": 75,
#     "BIND SHELL": 75,
#     "WIFI DUMP": 75,
#     "HASH DUMP": 75,

#     # 🟡 MEDIUM THREATS (40-69)
#     "OBFUSCATION": 60,
#     "PACKED BINARY": 60,
#     "UPX": 60,
#     "HIGH ENTROPY": 55,
#     "PORT SCAN": 50,
#     "NETWORK SCAN": 50,
#     "REFLECTION": 50,
#     "DYNAMIC LOADING": 50,
#     "DLL INJECTION": 65,
#     "HOOKING": 60,
#     "ANTI-DEBUG": 60,
#     "VM EVASION": 60,
#     "SANDBOX EVASION": 60,
#     "CRYPTO MINING": 55,
#     "MINER": 55,
#     "HARDCODED PASSWORD": 65,
#     "HARDCODED KEY": 65,
#     "AWS KEY": 65,

#     # 🔵 LOW / INFO (10-39)
#     "INFO": 10,
#     "RECONNAISSANCE": 30,
#     "WHOAMI": 20,
#     "IPCONFIG": 20,
#     "SYSTEMINFO": 20,
#     "PING": 10,
#     "NETSTAT": 15,
#     "TASKLIST": 15
# }

# # --- KEYWORDS FOR 8-AXIS RADAR CHART ---
# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Analyzes behavior tags and calculates scores for 8 specific axes.
#     """
#     # 🔥 CRITICAL: This Dictionary determines what shows on the graph.
#     # If this has 5 keys, the graph will have 5 points.
#     # We are setting it to 8 keys here.
#     matrix = {
#         "Exfiltration": 0,    
#         "Command & Control": 0, 
#         "Obfuscation": 0,     
#         "Spyware": 0,         
#         "Crypto/Ransom": 0,   
#         "Persistence": 0,     # <--- NEW AXIS
#         "Privilege Esc": 0,   # <--- NEW AXIS
#         "Reconnaissance": 0   # <--- NEW AXIS
#     }

#     keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "email", "post", "exfil", "upload_file", "stealing", "data loss", "transfer"],
#         "Command & Control": ["c2", "socket", "connect", "http", "reverse_shell", "bind_shell", "remote", "shell", "beacon", "botnet"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval", "enc", "powershell -enc"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "clipboard", "monitor", "screenshot", "surveillance", "audio", "video"],
#         "Crypto/Ransom": ["encrypt", "aes", "wallet", "bitcoin", "monero", "miner", "ransom", "wannacry", "lockbit", "shadow copy"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "cron", "daemon", "rootkit", "scheduled task"],
#         "Privilege Esc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "token", "creds", "lsass"],
#         "Reconnaissance": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery", "systeminfo", "tasklist", "ping"]
#     }

#     for tag in behaviors:
#         tag_lower = tag.lower()
        
#         # Check against mapped keywords
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word in tag_lower:
#                     if any(x in tag_lower for x in ["critical", "high", "alert"]):
#                         matrix[category] += 50
#                     elif "medium" in tag_lower:
#                         matrix[category] += 30
#                     else:
#                         matrix[category] += 15
#                     break 
        
#         # Check against MITRE ID mappings if present in tag
#         # Example tag: [T1059] Command and Scripting Interpreter
#         mitre_match = re.search(r"\[(T\d+(\.\d+)?)\]", tag)
#         if mitre_match:
#             t_id = mitre_match.group(1)
#             # Map T-codes to categories (Broad strokes)
#             if t_id.startswith("T1041") or t_id.startswith("T1048"): # Exfiltration
#                 matrix["Exfiltration"] += 40
#             elif t_id.startswith("T1071") or t_id.startswith("T1090") or t_id.startswith("T1095"): # C2
#                 matrix["Command & Control"] += 40
#             elif t_id.startswith("T1027") or t_id.startswith("T1140"): # Obfuscation
#                 matrix["Obfuscation"] += 40
#             elif t_id.startswith("T1056") or t_id.startswith("T1113"): # Spyware
#                 matrix["Spyware"] += 40
#             elif t_id.startswith("T1486") or t_id.startswith("T1496"): # Ransom/Crypto
#                 matrix["Crypto/Ransom"] += 50
#             elif t_id.startswith("T1547") or t_id.startswith("T1543") or t_id.startswith("T1053"): # Persistence
#                 matrix["Persistence"] += 40
#             elif t_id.startswith("T1068") or t_id.startswith("T1548"): # PrivEsc
#                 matrix["Privilege Esc"] += 40
#             elif t_id.startswith("T1082") or t_id.startswith("T1083") or t_id.startswith("T1033"): # Recon
#                 matrix["Reconnaissance"] += 20

#     # Cap scores at 100
#     for key in matrix:
#         if matrix[key] > 100: matrix[key] = 100
            
#     return matrix

# def calculate_risk(behaviors):
#     """
#     Professional Risk Scoring Algorithm (FAANG Standard).
    
#     Logic:
#     1. Base Score: Driven by the highest severity MITRE Tactic found (Primary Source).
#     2. Fallback Score: Driven by keyword matching if MITRE tag is absent.
#     3. Density Score: Adds weight for the *number* of distinct threats.
#     4. Kill Chain Multiplier: Boosts score if threats span multiple tactics 
#        (e.g. Execution + Persistence + Exfiltration).
#     """
#     if not behaviors:
#         return 0

#     scores = []
#     tactic_types = set()

#     for behavior in behaviors:
#         score = 0
#         found_mitre = False
        
#         # --- 1. MITRE ATT&CK LOOKUP (Primary Source) ---
#         # Look for [Txxxx] tags in the behavior string
#         if "[" in behavior and "]" in behavior:
#             try:
#                 # Extract ID, e.g., "[T1059]"
#                 tag_parts = behavior.split("[")[1].split("]")
#                 if tag_parts:
#                     tag_id = tag_parts[0]
                    
#                     # Reverse lookup the ID in our Master DB to get severity
#                     # We iterate to find matching ID in the dictionary values
#                     for rule in MITRE_SIGNATURES:
#                          # Depending on structure, MITRE_SIGNATURES might be a list of dicts or dict of dicts
#                          # Assuming list of dicts based on previous context, or dict key access
#                          # Adapting to generic lookup:
#                          rule_data = rule if isinstance(rule, dict) else MITRE_SIGNATURES.get(rule)
                         
#                          if rule_data and rule_data.get('id') == tag_id:
#                             severity = rule_data.get('severity', 'Low')
#                             if severity == "Critical": score = 95
#                             elif severity == "High": score = 75
#                             elif severity == "Medium": score = 45
#                             elif severity == "Low": score = 15
                            
#                             # Add to kill chain tracking (Heuristic based on T-Code structure)
#                             # T10xx: Execution, T11xx: Persistence/PrivEsc, T15xx: Defense Evasion
#                             if tag_id.startswith("T10"): tactic_types.add("Execution")
#                             elif tag_id.startswith("T11"): tactic_types.add("Persistence")
#                             elif tag_id.startswith("T15"): tactic_types.add("Evasion")
#                             elif tag_id.startswith("T14"): tactic_types.add("Impact")
#                             elif tag_id.startswith("T12"): tactic_types.add("Discovery")
                            
#                             found_mitre = True
#                             break
#             except Exception:
#                 pass # Malformed tag, fall through to keyword check

#         # --- 2. KEYWORD HEURISTICS (Fallback Safety Net) ---
#         # If no MITRE tag, check specific keywords from the massive dictionary above
#         if not found_mitre:
#             behavior_upper = behavior.upper()
#             best_match = 0
#             for key, weight in FALLBACK_WEIGHTS.items():
#                 if key in behavior_upper:
#                     if weight > best_match:
#                         best_match = weight
            
#             score = best_match
            
#             # Default for unknown behaviors that aren't in fallback list
#             if score == 0: score = 10

#         scores.append(score)

#     if not scores:
#         return 0

#     # --- 3. ADVANCED SCORING ALGORITHM ---
    
#     # A. The anchor is the highest single threat found
#     max_risk = max(scores)
    
#     # B. Calculate "Threat Density" (Sum of remaining threats scaled down)
#     # This ensures 10 medium threats > 1 medium threat, but 1 Critical always wins.
#     # We sort to remove the max score used in A.
#     remaining_scores = sorted(scores, reverse=True)[1:] 
    
#     # Add 10% of every other threat found
#     density_adder = sum(s * 0.10 for s in remaining_scores) 
    
#     # C. Kill Chain Multiplier (Diversity Boost)
#     # If we see 3+ distinct tactic types (e.g. Exec + Persist + Impact), it's an advanced attack.
#     chain_multiplier = 1.0
#     if len(tactic_types) >= 3:
#         chain_multiplier = 1.25 # +25% Risk for complex attack chain
#     elif len(tactic_types) == 2:
#         chain_multiplier = 1.10 # +10% Risk for multi-stage attack
        
#     final_score = (max_risk + density_adder) * chain_multiplier

#     # D. Hard Cap at 100 (Cannot exceed 100%)
#     return int(min(final_score, 100))


# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     # Fallback to prevent crash if file is missing during setup
#     MITRE_SIGNATURES = {}

# # --- COMPREHENSIVE FALLBACK WEIGHTS ---
# # Covers generic keywords for 50+ attacks across 20+ languages.
# FALLBACK_WEIGHTS = {
#     # 🔴 CRITICAL THREATS (90-100)
#     "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
#     "METERPRETER": 95, "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,
    
#     # 🟠 HIGH THREATS (70-89)
#     "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
#     "KEYLOGGER": 85, "SPYWARE": 80, "C2": 80, "BOTNET": 80, "EXFILTRATION": 80,
#     "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75,

#     # 🟡 MEDIUM THREATS (40-69)
#     "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
#     "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
#     "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,

#     # 🔵 LOW / INFO (10-39)
#     "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10
# }

# # --- KEYWORDS FOR 8-AXIS RADAR CHART ---
# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Analyzes behavior tags and calculates scores for 8 specific axes.
#     Uses BOTH keywords and MITRE T-Codes for maximum precision.
#     """
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

#     keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "email", "post", "exfil", "stealing", "transfer", "t1041", "t1048"],
#         "Command & Control": ["c2", "socket", "connect", "http", "reverse", "bind", "remote", "shell", "beacon", "botnet", "t1071", "t1090", "t1095", "t1105"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval", "enc", "t1027", "t1140"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "clipboard", "monitor", "screen", "audio", "video", "t1056", "t1113"],
#         "Crypto/Ransom": ["encrypt", "aes", "wallet", "bitcoin", "monero", "miner", "ransom", "wannacry", "lockbit", "shadow", "t1486", "t1496"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "cron", "daemon", "rootkit", "t1547", "t1543", "t1053"],
#         "Privilege Esc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "token", "creds", "lsass", "t1068", "t1548"],
#         "Reconnaissance": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery", "systeminfo", "tasklist", "ping", "t1082", "t1083", "t1033"]
#     }

#     for tag in behaviors:
#         tag_lower = tag.lower()
        
#         # 1. T-CODE MAPPING (High Precision)
#         # Extracts [T1059] and maps it immediately
#         mitre_match = re.search(r"\[(t\d+(\.\d+)?)\]", tag_lower)
#         if mitre_match:
#             t_id = mitre_match.group(1)
#             # Map known T-Codes to Categories
#             if t_id.startswith("t1041") or t_id.startswith("t1048"): matrix["Exfiltration"] += 40
#             if t_id.startswith("t1071") or t_id.startswith("t1090") or t_id.startswith("t1095"): matrix["Command & Control"] += 40
#             if t_id.startswith("t1027") or t_id.startswith("t1140"): matrix["Obfuscation"] += 40
#             if t_id.startswith("t1056") or t_id.startswith("t1113"): matrix["Spyware"] += 40
#             if t_id.startswith("t1486") or t_id.startswith("t1496"): matrix["Crypto/Ransom"] += 50
#             if t_id.startswith("t1547") or t_id.startswith("t1543") or t_id.startswith("t1053"): matrix["Persistence"] += 40
#             if t_id.startswith("t1068") or t_id.startswith("t1548"): matrix["Privilege Esc"] += 40
#             if t_id.startswith("t1082") or t_id.startswith("t1083") or t_id.startswith("t1033"): matrix["Reconnaissance"] += 20

#         # 2. KEYWORD MAPPING (Fallback)
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word in tag_lower:
#                     if any(x in tag_lower for x in ["critical", "high", "alert"]):
#                         matrix[category] += 30
#                     elif "medium" in tag_lower:
#                         matrix[category] += 20
#                     else:
#                         matrix[category] += 10
#                     break 

#     # Cap scores at 100 for the UI
#     for key in matrix:
#         matrix[key] = min(matrix[key], 100)
            
#     return matrix

# def calculate_risk(behaviors):
#     """
#     Professional Risk Scoring Algorithm.
#     """
#     if not behaviors: return 0

#     scores = []
#     tactic_types = set()

#     for behavior in behaviors:
#         score = 0
#         found_mitre = False
        
#         # 1. MITRE ATT&CK LOOKUP
#         if "[" in behavior and "]" in behavior:
#             try:
#                 tag_parts = behavior.split("[")[1].split("]")
#                 if tag_parts:
#                     tag_id = tag_parts[0]
#                     # Direct Dictionary Lookup (Optimized)
#                     for sig, info in MITRE_SIGNATURES.items():
#                         if info.get('id') == tag_id:
#                             severity = info.get('severity', 'Low')
#                             if severity == "Critical": score = 95
#                             elif severity == "High": score = 75
#                             elif severity == "Medium": score = 45
#                             else: score = 15
                            
#                             if tag_id.startswith("T10"): tactic_types.add("Execution")
#                             elif tag_id.startswith("T11"): tactic_types.add("Persistence")
#                             elif tag_id.startswith("T15"): tactic_types.add("Evasion")
                            
#                             found_mitre = True
#                             break
#             except Exception: pass

#         # 2. KEYWORD HEURISTICS
#         if not found_mitre:
#             behavior_upper = behavior.upper()
#             best_match = 0
#             for key, weight in FALLBACK_WEIGHTS.items():
#                 if key in behavior_upper:
#                     if weight > best_match: best_match = weight
#             score = best_match if best_match > 0 else 10

#         scores.append(score)

#     if not scores: return 0

#     # 3. ADVANCED SCORING
#     max_risk = max(scores)
#     remaining_scores = sorted(scores, reverse=True)[1:] 
#     density_adder = sum(s * 0.10 for s in remaining_scores) 
    
#     chain_multiplier = 1.0
#     if len(tactic_types) >= 3: chain_multiplier = 1.25
#     elif len(tactic_types) == 2: chain_multiplier = 1.10
        
#     final_score = (max_risk + density_adder) * chain_multiplier
#     return int(min(final_score, 100))

# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     MITRE_SIGNATURES = {}

# # --- COMPREHENSIVE FALLBACK WEIGHTS ---
# FALLBACK_WEIGHTS = {
#      #🔴 CRITICAL THREATS (90-100)
#     "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
#     "METERPRETER": 95, "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,
    
#     # 🟠 HIGH THREATS (70-89)
#     "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
#     "KEYLOGGER": 85, "SPYWARE": 80, "C2": 80, "BOTNET": 80, "EXFILTRATION": 80,
#     "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75,

#     # 🟡 MEDIUM THREATS (40-69)
#     "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
#     "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
#     "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,

#     # 🔵 LOW / INFO (10-39)
#     "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10
# }

# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Generates the 8-Axis Radar Chart Data.
#     Standardized Keys: Exfil, C2, Obfuscation, Spyware, Crypto, Persistence, PrivEsc, Recon
#     """
#     # 1. Initialize 8 Distinct Axes
#     matrix = {
#         "Exfil": 0,       # Data Theft
#         "C2": 0,          # Command & Control
#         "Obfuscation": 0, # Hiding Tracks
#         "Spyware": 0,     # Monitoring/Keylogging
#         "Crypto": 0,      # Ransomware/Miners
#         "Persistence": 0, # Auto-Start/Registry
#         "PrivEsc": 0,     # Admin Rights
#         "Recon": 0        # Scanning/Enumeration
#     }

#     # 2. Define Precise Keywords
#     keywords = {
#         "Exfil": ["upload", "ftp", "smtp", "email", "post", "exfil", "steal", "transfer", "t1041", "t1048"],
#         "C2": ["c2", "socket", "connect", "reverse", "bind", "remote", "shell", "beacon", "botnet", "t1071", "t1090", "t1095"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval", "t1027", "t1140"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "clipboard", "monitor", "screen", "audio", "t1056", "t1113"],
#         "Crypto": ["encrypt", "aes", "wallet", "bitcoin", "monero", "miner", "ransom", "wannacry", "lockbit", "t1486"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "cron", "rootkit", "t1547", "t1543"],
#         "PrivEsc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "token", "lsass", "t1068", "t1548"],
#         "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery", "systeminfo", "t1082", "t1083"]
#     }

#     for tag in behaviors:
#         tag_lower = tag.lower()
        
#         # A. MITRE T-CODE PRECISION LOOKUP
#         # Matches [T1059] or similar patterns
#         mitre_match = re.search(r"\[(t\d+(\.\d+)?)\]", tag_lower)
#         if mitre_match:
#             t_id = mitre_match.group(1)
#             # Forced categorization based on ID prefix
#             if t_id.startswith("t1041") or t_id.startswith("t1048"): matrix["Exfil"] = max(matrix["Exfil"], 75)
#             if t_id.startswith("t1071") or t_id.startswith("t1090") or t_id.startswith("t1095"): matrix["C2"] = max(matrix["C2"], 75)
#             if t_id.startswith("t1027"): matrix["Obfuscation"] = max(matrix["Obfuscation"], 60)
#             if t_id.startswith("t1056"): matrix["Spyware"] = max(matrix["Spyware"], 80)
#             if t_id.startswith("t1486"): matrix["Crypto"] = 100 # Ransomware is Critical
#             if t_id.startswith("t1547") or t_id.startswith("t1543"): matrix["Persistence"] = max(matrix["Persistence"], 80)
#             if t_id.startswith("t1548"): matrix["PrivEsc"] = max(matrix["PrivEsc"], 90)
#             if t_id.startswith("t1082") or t_id.startswith("t1083"): matrix["Recon"] = max(matrix["Recon"], 50)

#         # B. KEYWORD FALLBACK
#         for category, distinct_words in keywords.items():
#             for word in distinct_words:
#                 if word in tag_lower:
#                     boost = 50 if any(x in tag_lower for x in ["critical", "high", "alert"]) else 25
#                     matrix[category] += boost
#                     break 

#     # Cap scores at 100 for visual clarity
#     for k in matrix:
#         matrix[k] = min(matrix[k], 100)
            
#     return matrix

# def calculate_risk(behaviors):
#     """Calculates overall Threat Score (0-100)."""
#     if not behaviors: return 0
#     scores = []
    
#     for behavior in behaviors:
#         score = 10 # Baseline
        
#         # Check MITRE Dictionary (If available)
#         if "[" in behavior:
#             for sig, info in MITRE_SIGNATURES.items():
#                 if info.get('id') in behavior:
#                     s = info.get('severity', 'Low')
#                     score = 95 if s == "Critical" else 75 if s == "High" else 45
#                     break
        
#         # Check Keyword Weights
#         behavior_upper = behavior.upper()
#         for key, weight in FALLBACK_WEIGHTS.items():
#             if key in behavior_upper:
#                 score = max(score, weight)
        
#         scores.append(score)

#     if not scores: return 0
    
#     # Weighted Average favoring High Risks
#     max_risk = max(scores)
#     density_bonus = min(len(scores) * 2, 20) # +2 points per finding, max 20
    
#     return int(min(max_risk + density_bonus, 100))

# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     MITRE_SIGNATURES = {}
# # =========================================================================
# # 1. CONFIGURATION & WEIGHTS
# # =========================================================================

# # 🔥 MITRE ID -> RADAR AXIS MAPPING (The "Brain" for the Chart)
# # This ensures specific IDs map to the correct axis even without keywords.
# MITRE_TO_AXIS = {
#     # Exfiltration
#     "T1041": "Exfil", "T1048": "Exfil", "T1020": "Exfil", "T1052": "Exfil",
#     # C2
#     "T1071": "C2", "T1090": "C2", "T1095": "C2", "T1572": "C2", "T1105": "C2",
#     # Obfuscation
#     "T1027": "Obfuscation", "T1140": "Obfuscation", "T1006": "Obfuscation",
#     # Spyware
#     "T1056": "Spyware", "T1113": "Spyware", "T1123": "Spyware",
#     # Crypto/Ransom
#     "T1486": "Crypto", "T1485": "Crypto", "T1490": "Crypto",
#     # Persistence
#     "T1547": "Persistence", "T1543": "Persistence", "T1053": "Persistence", "T1134": "Persistence",
#     # PrivEsc
#     "T1548": "PrivEsc", "T1068": "PrivEsc", "T1003": "PrivEsc", "T1134": "PrivEsc",
#     # Recon
#     "T1082": "Recon", "T1083": "Recon", "T1046": "Recon", "T1033": "Recon", "T1012": "Recon"
# }

# # 🔥 BASELINE SEVERITY SCORES (MITRE T-Codes)
# MITRE_SEVERITY_MAP = {
#     # CRITICAL
#     "T1486": 100, "T1485": 100, "T1059": 95, "T1003": 95, "T1505": 90,
#     # HIGH
#     "T1547": 85, "T1055": 85, "T1041": 80, "T1572": 80, "T1071": 75,
#     # MEDIUM
#     "T1027": 60, "T1056": 65, "T1113": 60,
#     # LOW
#     "T1082": 30, "T1033": 25, "T1046": 30
# }

# # 🔥 COMPREHENSIVE KEYWORD FALLBACKS
# FALLBACK_WEIGHTS = {
#     # 🔴 CRITICAL THREATS (90-100)
#     "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
#     "METERPRETER": 95, "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,
    
#     # 🟠 HIGH THREATS (70-89)
#     "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
#     "KEYLOGGER": 85, "SPYWARE": 80, "C2": 80, "BOTNET": 80, "EXFILTRATION": 80,
#     "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75, "TUNNEL": 75,

#     # 🟡 MEDIUM THREATS (40-69)
#     "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
#     "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
#     "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,

#     # 🔵 LOW / INFO (10-39)
#     "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10, "ENUM": 25
# }

# # =========================================================================
# # 2. RADAR CHART LOGIC
# # =========================================================================
# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Generates the 8-Axis Radar Chart Data.
#     Keys: Exfiltration, C2, Obfuscation, Spyware, Crypto, Persistence, PrivEsc, Recon
#     """
#     # 1. Initialize Matrix
#     matrix = {
#         "Exfiltration": 0, "C2": 0, "Obfuscation": 0, "Spyware": 0,
#         "Crypto": 0, "Persistence": 0, "PrivEsc": 0, "Recon": 0
#     }

#     # 2. Axis Keywords (Fallback)
#     axis_keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "exfil", "steal", "transfer"],
#         "C2": ["c2", "socket", "connect", "reverse", "bind", "botnet", "listener"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "monitor", "screen"],
#         "Crypto": ["encrypt", "wallet", "bitcoin", "miner", "ransom", "wannacry"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "rootkit"],
#         "PrivEsc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "lsass", "mimikatz"],
#         "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery"]
#     }

#     for tag in behaviors:
#         tag_upper = str(tag).upper()
        
#         # A. MITRE ID LOOKUP (Primary & Precise)
#         mitre_match = re.search(r"\[(T\d+)\]", tag_upper)
#         if mitre_match:
#             t_id = mitre_match.group(1)
            
#             # Map to Axis
#             if t_id in MITRE_TO_AXIS:
#                 axis = MITRE_TO_AXIS[t_id]
#                 score = MITRE_SEVERITY_MAP.get(t_id, 50) # Default to 50
#                 matrix[axis] = max(matrix[axis], score)
            
#             # Heuristic Backup
#             elif t_id.startswith("T14"): matrix["Crypto"] = max(matrix["Crypto"], 90)
#             elif t_id.startswith("T10"): matrix["C2"] = max(matrix["C2"], 50)

#         # B. KEYWORD FALLBACK
#         for category, distinct_words in axis_keywords.items():
#             for word in distinct_words:
#                 if word.upper() in tag_upper:
#                     boost = 40
#                     if "CRITICAL" in tag_upper: boost = 90
#                     elif "HIGH" in tag_upper: boost = 75
#                     elif "MEDIUM" in tag_upper: boost = 50
#                     matrix[category] = max(matrix[category], boost)
#                     break 

#     # Cap at 100
#     for k in matrix:
#         if matrix[k] > 100: matrix[k] = 100
        
#     return matrix

# # =========================================================================
# # 3. THREAT SCORING LOGIC
# # =========================================================================
# def calculate_risk(behaviors: list) -> int:
#     """Calculates overall Threat Score (0-100)."""
#     if not behaviors: return 0
#     scores = []
    
#     for behavior in behaviors:
#         score = 10 # Baseline
#         b_upper = str(behavior).upper()
        
#         # 1. Check MITRE Map (O(1) Lookup)
#         mitre_match = re.search(r"\[(T\d+)\]", b_upper)
#         if mitre_match:
#             t_id = mitre_match.group(1)
#             if t_id in MITRE_SEVERITY_MAP:
#                 score = max(score, MITRE_SEVERITY_MAP[t_id])
        
#         # 2. Check Keyword Fallbacks
#         for key, weight in FALLBACK_WEIGHTS.items():
#             if key in b_upper:
#                 score = max(score, weight)
        
#         scores.append(score)

#     if not scores: return 0
    
#     # 3. Final Score: Max Risk + Density Bonus
#     max_risk = max(scores)
    
#     # Density Bonus: +2 per finding, capped at +15
#     # Only applies if we found actual threats (>30 score)
#     density_bonus = 0
#     if max_risk > 30:
#         density_bonus = min(len(scores) * 2, 15)
    
#     return int(min(max_risk + density_bonus, 100))

# import re

# # --- Dependency Check ---
# try:
#     from .mitre_mapping import MITRE_SIGNATURES
# except ImportError:
#     MITRE_SIGNATURES = {}

# # =========================================================================
# # 1. THREAT INTELLIGENCE CONFIGURATION
# # =========================================================================

# # 🔥 MITRE ID -> RADAR AXIS MAPPING
# # Ensures specific IDs affect the correct Radar Chart axis.
# MITRE_TO_AXIS = {
#     # Exfiltration
#     "T1041": "Exfil", "T1048": "Exfil", "T1020": "Exfil", "T1052": "Exfil",
#     # C2 (Command & Control)
#     "T1071": "C2", "T1090": "C2", "T1095": "C2", "T1572": "C2", "T1105": "C2",
#     # Obfuscation
#     "T1027": "Obfuscation", "T1140": "Obfuscation", "T1006": "Obfuscation", "T1027.002": "Obfuscation",
#     # Spyware
#     "T1056": "Spyware", "T1113": "Spyware", "T1123": "Spyware",
#     # Crypto/Ransom
#     "T1486": "Crypto", "T1485": "Crypto", "T1490": "Crypto",
#     # Persistence
#     "T1547": "Persistence", "T1543": "Persistence", "T1053": "Persistence", "T1134": "Persistence",
#     # PrivEsc (Privilege Escalation)
#     "T1548": "PrivEsc", "T1068": "PrivEsc", "T1003": "PrivEsc", "T1134": "PrivEsc",
#     # Recon (Reconnaissance)
#     "T1082": "Recon", "T1083": "Recon", "T1046": "Recon", "T1033": "Recon", "T1012": "Recon"
# }

# # 🔥 BASELINE SEVERITY SCORES (MITRE T-Codes)
# # These act as the "Source of Truth" for scoring.
# MITRE_SEVERITY_MAP = {
#     # CRITICAL (90-100)
#     "T1486": 100, # Ransomware Encryption
#     "T1485": 100, # Disk Wiper
#     "T1059": 95,  # Command Shell (PowerShell/CMD) - Context dependent, usually high
#     "T1003": 95,  # Credential Dumping (Mimikatz)
#     "T1505": 90,  # Web Shell
    
#     # HIGH (70-89)
#     "T1547": 85,  # Registry/Startup Persistence
#     "T1055": 85,  # Process Injection
#     "T1041": 80,  # Exfiltration
#     "T1572": 80,  # Protocol Tunneling
#     "T1071": 75,  # C2 Traffic
    
#     # MEDIUM (40-69)
#     "T1027": 70,  # Obfuscation (Packed/Encrypted)
#     "T1056": 65,  # Keylogging
#     "T1113": 60,  # Screen Capture
    
#     # LOW (10-39)
#     "T1082": 35,  # System Info Discovery
#     "T1046": 30,  # Network Scanning
#     "T1033": 25   # User Discovery
# }

# # 🔥 COMPREHENSIVE KEYWORD FALLBACKS
# # Used if no MITRE ID is found in the behavior string.
# FALLBACK_WEIGHTS = {
#     # 🔴 CRITICAL
#     "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
#     "REVERSE SHELL": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
#     "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
#     "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,
    
#     # 🟠 HIGH
#     "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
#     "KEYLOGGER": 80, "SPYWARE": 80, "C2 SERVER": 80, "BOTNET": 80, "EXFILTRATION": 80,
# "SYSTEM COMMAND": 85, # Boosts generic T1059 if context is dangerous
#     "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75, "TUNNEL": 75,
    
#     # 🟡 MEDIUM
#     "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
#     "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
#     "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,
    
#     # 🔵 LOW
#     "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10, "ENUM": 25
# }

# # =========================================================================
# # 2. RADAR CHART CALCULATOR (8-AXIS)
# # =========================================================================
# def calculate_risk_matrix(behaviors: list) -> dict:
#     """
#     Generates the 8-Axis Radar Chart Data.
#     Standardized Keys: Exfil, C2, Obfuscation, Spyware, Crypto, Persistence, PrivEsc, Recon
#     """
#     matrix = {
#         "Exfiltration": 0, "C2": 0, "Obfuscation": 0, "Spyware": 0,
#         "Crypto": 0, "Persistence": 0, "PrivEsc": 0, "Recon": 0
#     }

#     # Keyword Mapping for Radar Axes (Fallback Logic)
#     axis_keywords = {
#         "Exfiltration": ["upload", "ftp", "smtp", "exfil", "steal", "transfer"],
#         "C2": ["c2", "socket", "connect", "reverse", "bind", "botnet", "listener"],
#         "Obfuscation": ["base64", "xor", "packed", "entropy", "rot13", "hidden", "stego", "eval"],
#         "Spyware": ["keylog", "hook", "camera", "mic", "monitor", "screen"],
#         "Crypto": ["encrypt", "wallet", "bitcoin", "miner", "ransom", "wannacry"],
#         "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "boot", "rootkit"],
#         "PrivEsc": ["admin", "root", "uac", "bypass", "sudo", "privilege", "system", "lsass", "mimikatz"],
#         "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum", "discovery"]
#     }

#     print("\n🔍 [RADAR MATRIX] Generating Axis Data...")

#     for tag in behaviors:
#         tag_upper = str(tag).upper()
        
#         # A. MITRE ID LOOKUP (Precise)
#         mitre_match = re.search(r"\[(T\d+(\.\d+)?)\]", tag_upper)
#         if mitre_match:
#             # Normalize ID (e.g., T1027.001 -> T1027 to find parent category)
#             full_id = mitre_match.group(1)
#             parent_id = full_id.split('.')[0] 
            
#             # Use Parent ID to map to Axis
#             if parent_id in MITRE_TO_AXIS:
#                 axis = MITRE_TO_AXIS[parent_id]
#                 # Default score 50 if severity not defined, allows chart to move
#                 score = MITRE_SEVERITY_MAP.get(parent_id, 50) 
#                 if score > matrix[axis]:
#                     matrix[axis] = score
#                     # print(f"   ➤ Axis Hit (MITRE): {full_id} -> {axis} ({score})")
            
#             # Heuristic Backups based on T-Code structure
#             elif full_id.startswith("T14"): matrix["Crypto"] = max(matrix["Crypto"], 90)
#             elif full_id.startswith("T10"): matrix["C2"] = max(matrix["C2"], 50)

#         # B. KEYWORD FALLBACK
#         for category, distinct_words in axis_keywords.items():
#             for word in distinct_words:
#                 if word.upper() in tag_upper:
#                     boost = 40
#                     if "CRITICAL" in tag_upper: boost = 90
#                     elif "HIGH" in tag_upper: boost = 75
#                     elif "MEDIUM" in tag_upper: boost = 50
                    
#                     if boost > matrix[category]:
#                         matrix[category] = boost
#                         # print(f"   ➤ Axis Hit (Keyword): {word} -> {category} ({boost})")
#                     break 

#     # Cap values at 100 for Chart Display
#     for k in matrix:
#         if matrix[k] > 100: matrix[k] = 100
        
#     return matrix

# # =========================================================================
# # 3. THREAT SCORING LOGIC (PRECISION ALGORITHM)
# # =========================================================================
# def calculate_risk(behaviors: list) -> int:
#     """
#     Calculates risk by taking the MAX threat score and adding 
#     weighted penalties for additional behaviors.
#     Includes SILENT KILLER TRACEBACK logging.
#     """
#     if not behaviors: return 0
#     scores = []
    
#     print("\n🕵️ [SILENT KILLER DETECTION] Calculating Threat Score...")
#     print(f"   Input Behaviors Count: {len(behaviors)}")
    
#     for behavior in behaviors:
#         score = 10 # Default Low Baseline
#         b_upper = str(behavior).upper()
#         trigger_source = "Baseline"
        
#         # 1. MITRE ID Lookup (High Precision)
#         # Matches [T1059] or [T1059.001]
#         mitre_match = re.search(r"\[(T\d+(\.\d+)?)\]", b_upper)
#         if mitre_match:
#             full_id = mitre_match.group(1)
#             parent_id = full_id.split('.')[0]
            
#             # Priority: Check Parent ID in Map
#             if parent_id in MITRE_SEVERITY_MAP:
#                 map_score = MITRE_SEVERITY_MAP[parent_id]
#                 if map_score > score:
#                     score = map_score
#                     trigger_source = f"MITRE {parent_id}"
        
#         # 2. Keyword Fallback (Broad Coverage)
#         # We check this even if MITRE matched, in case a keyword implies higher severity
#         for key, weight in FALLBACK_WEIGHTS.items():
#             if key in b_upper:
#                 if weight > score:
#                     score = weight
#                     trigger_source = f"Keyword '{key}'"
        
#         scores.append(score)
        
#         # 🔥 DEBUG LOG: Prints exact reason for the score
#         # Use this to find why "ping" might accidentally trigger "95"
#         print(f"   👉 Tag: '{behavior[:40]}...' | Score: {score} | Trigger: {trigger_source}")

#     if not scores: return 0
    
#     # --- SCORING ALGORITHM ---
    
#     # 1. Establish the "Anchor" Score (The single most dangerous finding)
#     # Example: If we found Ransomware (100) and Ping (10), Anchor is 100.
#     max_risk = max(scores)
    
#     # 2. Calculate "Noise" Score
#     # Sum of all other scores excluding the max
#     remaining_sum = sum(scores) - max_risk
    
#     # 3. Apply Density Penalty (10% of remaining threats)
#     # This ensures multiple "High" threats push the score higher than a single "High",
#     # but 10 "Low" threats don't artificially create a "Critical" alert.
#     final_score = max_risk + (remaining_sum * 0.10)
    
#     # 4. Cap at 100
#     final_score = int(min(final_score, 100))
    
#     print(f"   📊 CALCULATION: Max Risk ({max_risk}) + Density Boost ({int(remaining_sum * 0.10)}) = {final_score}")
#     print("---------------------------------------------------------------")
    
#     return final_score

import re

# --- Dependency Check (Safe Import) ---
try:
    from .mitre_mapping import MITRE_SIGNATURES
except ImportError:
    MITRE_SIGNATURES = {}

# =========================================================================
# 1. PRECISE THREAT SCORING CONFIGURATION
# =========================================================================

# 🔥 MITRE T-CODE WEIGHTS (The Anchor)
MITRE_SEVERITY_MAP = {
    # CRITICAL (90-100) - Pure Malice
    "T1486": 100, # Ransomware
    "T1485": 100, # Disk Wiper
    "T1490": 100, # Shadow Copy Delete
    "T1003": 95,  # Credential Dumping (Mimikatz)
    "T1505": 95,  # Web Shells
    "T1574": 90,  # Hijacking (DLL/Lib)
    # HIGH (70-89) - Dangerous but situational
    "T1547": 85,  # Persistence (Registry)
    "T1055": 85,  # Process Injection
    "T1572": 80,  # Tunneling
    "T1041": 80,  # Exfiltration
    "T1071": 75,  # C2 Traffic
    "T1548": 80,  # UAC Bypass
    "T1059": 80,  # Command Execution (PowerShell/CMD) - Bumped up slightly

    # MEDIUM (40-69) - Suspicious / Admin Tools
    "T1059": 65,  # Command Execution (cmd, powershell, os.system)
    "T1027": 60,  # Obfuscation (Base64)
    "T1056": 65,  # Input Capture
    "T1140": 55,  # Deobfuscation
    "T1113": 55,  # Screen Capture
    "T1095": 60,  # Raw Sockets (Lowered from 95 to fix False Positives)
    # LOW (10-39) - Reconnaissance / Info
    "T1082": 30,  # System Info
    "T1083": 30,  # File Discovery
    "T1033": 20,  # Whoami
    "T1046": 30,  # Network Scan
    "T1012": 20,  # Registry Query
}

# 🔥 KEYWORD FALLBACKS (Safety Net)
FALLBACK_WEIGHTS = {
    "RANSOMWARE": 100, "WANNACRY": 100, "ROOTKIT": 100, "CONTAINER ESCAPE": 100,
    "LSASS": 95, "REMOTE CODE EXECUTION": 95, "RCE": 95, "SQL INJECTION": 95,
    "COMMAND INJECTION": 95, "PRIVILEGE ESCALATION": 95, "SHADOW COPY": 95,
    "MIMIKATZ": 95, "LSASS": 95, "ETERNALBLUE": 95,"WEB SHELL": 95,
    
    # 🟠 HIGH
    "BUFFER OVERFLOW": 85, "XXE": 85, "SSRF": 85, "XSS": 80,
    "KEYLOGGER": 80, "SPYWARE": 80, "C2 SERVER": 80, "BOTNET": 80, "EXFILTRATION": 80,
    "SYSTEM COMMAND": 85, # Boosts generic T1059 if context is dangerous
    "POWERSHELL -ENC": 80, "BASE64 PAYLOAD": 75, "BIND SHELL": 75, "TUNNEL": 75,
    
    # 🟡 MEDIUM
    "OBFUSCATION": 60, "PACKED BINARY": 60, "UPX": 60, "HIGH ENTROPY": 55,
    "PORT SCAN": 50, "REFLECTION": 50, "DLL INJECTION": 65, "HOOKING": 60,
    "ANTI-DEBUG": 60, "VM EVASION": 60, "CRYPTO MINING": 55, "AWS KEY": 65,
    
    # 🔵 LOW
    "INFO": 10, "RECONNAISSANCE": 30, "WHOAMI": 20, "IPCONFIG": 20, "PING": 10, "ENUM": 25, "SCAN": 25
    }

# =========================================================================
# 2. RADAR CHART LOGIC
# =========================================================================
def calculate_risk_matrix(behaviors: list) -> dict:
    matrix = {
        "Exfiltration": 0, "C2": 0, "Obfuscation": 0, "Spyware": 0,
        "Crypto": 0, "Persistence": 0, "PrivEsc": 0, "Recon": 0
    }

    mitre_to_axis = {
        "T1041": "Exfiltration", "T1048": "Exfiltration", "T1020": "Exfiltration",
        "T1071": "C2", "T1090": "C2", "T1095": "C2", "T1572": "C2", "T1105": "C2",
        "T1027": "Obfuscation", "T1140": "Obfuscation", "T1006": "Obfuscation",
        "T1056": "Spyware", "T1113": "Spyware", "T1123": "Spyware",
        "T1486": "Crypto", "T1485": "Crypto", "T1490": "Crypto",
        "T1547": "Persistence", "T1543": "Persistence", "T1053": "Persistence",
        "T1548": "PrivEsc", "T1068": "PrivEsc", "T1003": "PrivEsc",
        "T1082": "Recon", "T1083": "Recon", "T1046": "Recon", "T1033": "Recon", "T1059": "C2"
    }

    axis_keywords = {
        "Exfiltration": ["upload", "ftp", "smtp", "exfil", "steal"],
        "C2": ["c2", "socket", "reverse", "botnet", "listener", "bind"],
        "Obfuscation": ["base64", "xor", "packed", "rot13", "hidden", "eval"],
        "Spyware": ["keylog", "hook", "camera", "mic", "monitor", "screen"],
        "Crypto": ["encrypt", "bitcoin", "miner", "ransom", "wannacry", "wipe"],
        "Persistence": ["startup", "registry", "service", "schtasks", "autorun", "rootkit"],
        "PrivEsc": ["admin", "root", "uac", "bypass", "privilege", "lsass", "mimikatz"],
        "Recon": ["scan", "nmap", "whoami", "ipconfig", "netstat", "enum"]
    }

    for tag in behaviors:
        tag_upper = str(tag).upper()
        
        mitre_match = re.search(r"\[(T\d+(\.\d+)?)\]", tag_upper)
        if mitre_match:
            t_id = mitre_match.group(1).split('.')[0]
            if t_id in mitre_to_axis:
                axis = mitre_to_axis[t_id]
                score = MITRE_SEVERITY_MAP.get(t_id, 50) 
                matrix[axis] = max(matrix[axis], score)
            elif t_id.startswith("T14"): matrix["Crypto"] = max(matrix["Crypto"], 90)
            elif t_id.startswith("T10"): matrix["C2"] = max(matrix["C2"], 50)

        for category, distinct_words in axis_keywords.items():
            for word in distinct_words:
                if word.upper() in tag_upper:
                    boost = 40
                    if "CRITICAL" in tag_upper: boost = 90
                    elif "HIGH" in tag_upper: boost = 75
                    elif "MEDIUM" in tag_upper: boost = 50
                    matrix[category] = max(matrix[category], boost)
                    break 

    for k in matrix:
        if matrix[k] > 100: matrix[k] = 100
        
    return matrix

# =========================================================================
# 3. THREAT SCORING LOGIC (With Traceback)
# =========================================================================
def calculate_risk(behaviors: list) -> int:
    if not behaviors: return 0
    scores = []
    
    print("\n🕵️ [SILENT KILLER DETECTION] Calculating Threat Score...")
    print(f"   Input Behaviors Count: {len(behaviors)}")
    
    for behavior in behaviors:
        score = 10 
        b_upper = str(behavior).upper()
        trigger_source = "Baseline"
        
        # 1. Check MITRE Map (Preferred)
        mitre_match = re.search(r"\[(T\d+(\.\d+)?)\]", b_upper)
        if mitre_match:
            # Clean ID (e.g. T1059.004 -> T1059)
            t_id = mitre_match.group(1).split('.')[0]
            
            if t_id in MITRE_SEVERITY_MAP:
                mitre_score = MITRE_SEVERITY_MAP[t_id]
                if mitre_score > score:
                    score = mitre_score
                    trigger_source = f"MITRE {t_id}"
        
        # 2. Check Keyword Fallbacks
        for key, weight in FALLBACK_WEIGHTS.items():
            if key in b_upper:
                if weight > score:
                    score = weight
                    trigger_source = f"Keyword '{key}'"
        
        scores.append(score)
        print(f"   👉 Tag: '{behavior[:40]}...' | Score: {score} | Trigger: {trigger_source}")

    if not scores: return 0
    
    max_risk = max(scores)
    
    # 3. Precise Density Penalty
    # We calculate the sum of the *other* threats
    remaining_sum = sum(scores) - max_risk
    
    density_bonus = 0
    if max_risk >= 75: 
        density_bonus = min(len(scores) * 3, 15) 
    elif max_risk >= 50:
        density_bonus = min(len(scores) * 2, 20)
    else:
        # Low risk items stack very slowly
        density_bonus = min(len(scores) * 1, 10)

    final_score = int(min(max_risk + density_bonus, 100))
    
    print(f"   📊 CALCULATION: Max Risk ({max_risk}) + Density ({int(density_bonus)}) = {final_score}")
    print("---------------------------------------------------------------")
    
    return final_score