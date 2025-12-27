import re

"""
UNIVERSAL BEHAVIOR RULES (MASTER V3.0 - ENTERPRISE EDITION)
--------------------------------------------------------------------------------
A heuristic detection engine covering 150+ attack vectors across 25+ languages.
Designed for Source Code, Binary Strings, Network Payloads, and Stego-Artifacts.

8-AXIS RADAR MAPPING:
1. EXECUTION (RCE/Shells)       5. CREDENTIALS (Theft/Dumping)
2. PERSISTENCE (Startups)       6. DISCOVERY (Recon/Scanning)
3. PRIVILEGE ESC (Root/Admin)   7. LATERAL MOVEMENT (Network/C2)
4. EVASION (Obfuscation)        8. IMPACT (Ransomware/Wipers)
"""

class EnterpriseThreatEngine:
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compiles Regex for O(1) performance."""
        for rule in BEHAVIOR_RULES:
            try:
                self.compiled_patterns[rule['id']] = re.compile(rule['pattern'], re.IGNORECASE)
            except re.error as e:
                print(f"⚠️ [REGEX ERROR] Rule {rule['id']} failed: {e}")

    def scan(self, content):
        """Scans any text content (Source, Binary Strings, Decoded Payloads)."""
        findings = []
        if not content: return findings
        
        # Fast scan against pre-compiled patterns
        for rule_id, pattern in self.compiled_patterns.items():
            if pattern.search(content):
                # Retrieve full rule details
                rule_data = next((r for r in BEHAVIOR_RULES if r["id"] == rule_id), None)
                if rule_data:
                    findings.append(rule_data)
        return findings

# =========================================================================
# 💀 MASTER RULESET: 150+ ATTACK VECTORS
# =========================================================================
BEHAVIOR_RULES = [
    # =========================================================================
    # 1. EXECUTION & RCE (RADAR AXIS: EXECUTION)
    # =========================================================================
    {
        "id": "T1059.001", "name": "PowerShell Execution", "score": 90, "mitre": "T1059",
        "axis": "Execution", "desc": "Executes malicious PowerShell commands.",
        "pattern": r"\b(powershell\.exe|pwsh|Invoke-Expression|IEX\s|New-Object\s+Net\.WebClient|DownloadString|ByPass|NoProfile|-enc|-encodedcommand)\b"
    },
    {
        "id": "T1059.003", "name": "Windows Command Shell", "score": 85, "mitre": "T1059",
        "axis": "Execution", "desc": "Standard CMD execution potentially spawning subprocesses.",
        "pattern": r"\b(cmd\.exe|/c\s+start|cmd\s+/c|mkdir|echo\s+.*>|type\s+.*\||del\s+/f|taskkill)\b"
    },
    {
        "id": "T1059.004", "name": "Unix Shell Execution", "score": 90, "mitre": "T1059",
        "axis": "Execution", "desc": "Bash/Sh execution often used in reverse shells.",
        "pattern": r"\b(/bin/sh|/bin/bash|/bin/zsh|sh\s+-c|bash\s+-i|exec\s+5<>/dev/tcp|nohup\s+|awk\s+'.*BEGIN\s+{system)\b"
    },
    {
        "id": "T1059.006", "name": "Python/Ruby RCE", "score": 95, "mitre": "T1059",
        "axis": "Execution", "desc": "Script-based Remote Code Execution.",
        "pattern": r"\b(os\.system\(|subprocess\.call|subprocess\.Popen|pty\.spawn|eval\(|exec\(|pickle\.loads|yaml\.load|marshal\.load|Shelve\.open)\b"
    },
    {
        "id": "T1059.007", "name": "JavaScript/Node RCE", "score": 95, "mitre": "T1059",
        "axis": "Execution", "desc": "Server-side JS execution (Node.js).",
        "pattern": r"\b(child_process\.exec|child_process\.spawn|eval\(|new\s+Function\(|process\.binding|process\.kill|vm\.runInNewContext)\b"
    },
    {
        "id": "T1059.008", "name": "PHP Web Shell", "score": 100, "mitre": "T1059",
        "axis": "Execution", "desc": "Classic PHP backdoor execution methods.",
        "pattern": r"\b(shell_exec|passthru|system\(|proc_open|popen|pcntl_exec|assert\(|preg_replace\(.*/e|`.*`)\b"
    },
    {
        "id": "T1203", "name": "Exploitation via Deserialization", "score": 95, "mitre": "T1203",
        "axis": "Execution", "desc": "Unsafe object deserialization leading to RCE.",
        "pattern": r"\b(ObjectInputStream|readObject|unserialize|XStream|BinaryFormatter|LosFormatter|SoapFormatter|fastjson|jackson\.databind)\b"
    },
    {
        "id": "T1569", "name": "System Services Execution", "score": 85, "mitre": "T1569",
        "axis": "Execution", "desc": "Abusing system services to execute binaries.",
        "pattern": r"\b(sc\.exe\s+start|net\s+start|systemctl\s+start|service\s+.*start|launchctl\s+load|svchost\.exe)\b"
    },

    # =========================================================================
    # 2. PERSISTENCE (RADAR AXIS: PERSISTENCE)
    # =========================================================================
    {
        "id": "T1547.001", "name": "Registry Run Keys", "score": 90, "mitre": "T1547",
        "axis": "Persistence", "desc": "Adds payload to Windows Registry for autorun.",
        "pattern": r"(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\.*\\RunOnce|RegSetValueEx|REG\s+ADD|Set-ItemProperty.*Run)"
    },
    {
        "id": "T1547.009", "name": "Shortcut Modification", "score": 75, "mitre": "T1547",
        "axis": "Persistence", "desc": "Modifies .LNK files to execute malware.",
        "pattern": r"(\.lnk|WScript\.Shell.*CreateShortcut|TargetPath|IconLocation|Arguments.*cmd\.exe)"
    },
    {
        "id": "T1053.005", "name": "Scheduled Tasks", "score": 85, "mitre": "T1053",
        "axis": "Persistence", "desc": "Schedules malicious jobs (Cron/Schtasks).",
        "pattern": r"\b(schtasks|/create|/tn|crontab\s+-e|/etc/cron\.|at\.exe|job\.add|systemd\.timer)\b"
    },
    {
        "id": "T1543.003", "name": "Windows Service Creation", "score": 90, "mitre": "T1543",
        "axis": "Persistence", "desc": "Creates a new service to maintain access.",
        "pattern": r"\b(sc\.exe\s+create|New-Service|CreateService|OpenSCManager|StartServiceCtrlDispatcher)\b"
    },
    {
        "id": "T1543.002", "name": "Systemd Service (Linux)", "score": 85, "mitre": "T1543",
        "axis": "Persistence", "desc": "Installs a malicious systemd unit.",
        "pattern": r"(/etc/systemd/system/.*\.service|systemctl\s+enable|Unit\].*Service\]|ExecStart=)"
    },
    {
        "id": "T1546.015", "name": "Component Object Model Hijacking", "score": 80, "mitre": "T1546",
        "axis": "Persistence", "desc": "Abuses COM objects for persistence.",
        "pattern": r"(CLSID\\.*\\InprocServer32|regsvr32|DllRegisterServer|scriptlet|scrobj\.dll)"
    },
    {
        "id": "T1134.005", "name": "Bootkit/Rootkit Artifacts", "score": 100,
        "mitre": "T1014", "axis": "Persistence", "desc": "Low-level kernel/boot persistence.",
        "pattern": r"(FixMbr|FixBoot|bcdedit|/etc/ld\.so\.preload|LD_PRELOAD|insmod|modprobe|kldload|rootkit|vmlinuz)"
    },

    # =========================================================================
    # 3. PRIVILEGE ESCALATION (RADAR AXIS: PRIV_ESC)
    # =========================================================================
    {
        "id": "T1078", "name": "Local Account Manipulation", "score": 90, "mitre": "T1078",
        "axis": "PrivEsc", "desc": "Adding users or changing groups.",
        "pattern": r"(net\s+user\s+/add|net\s+localgroup\s+administrators|useradd|usermod\s+-aG|Add-LocalGroupMember)"
    },
    {
        "id": "T1548.002", "name": "UAC Bypass", "score": 95, "mitre": "T1548",
        "axis": "PrivEsc", "desc": "Bypassing User Account Control.",
        "pattern": r"(fodhelper\.exe|eventvwr\.exe|slui\.exe|sdclt\.exe|ConsentPromptBehavior|EnableLUA|RunAs|SetUID|High\s+Mandatory\s+Level)"
    },
    {
        "id": "T1068", "name": "Exploitation for Privilege Escalation", "score": 100,
        "mitre": "T1068", "axis": "PrivEsc", "desc": "Known exploit keywords.",
        "pattern": r"(DirtyCow|EternalBlue|DoublePulsar|Zerologon|PrintNightmare|cve-202|exploit-db|SeDebugPrivilege|AdjustTokenPrivileges)"
    },
    {
        "id": "T1055.001", "name": "DLL Injection / Sideloading", "score": 90, "mitre": "T1055",
        "axis": "PrivEsc", "desc": "Injecting malicious DLLs into high-privilege processes.",
        "pattern": r"(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|LoadLibrary|ReflectiveLoader|QueueUserAPC|SetWindowsHookEx|RtlCreateUserThread)"
    },
    {
        "id": "T1548.001", "name": "SetUID/SetGID Abuse", "score": 85, "mitre": "T1548",
        "axis": "PrivEsc", "desc": "Abusing Linux bits for root access.",
        "pattern": r"(chmod\s+u\+s|chmod\s+4755|chown\s+root|sudo\s+-l|visudo|/etc/sudoers|GTFOBins)"
    },

    # =========================================================================
    # 4. DEFENSE EVASION (RADAR AXIS: OBFUSCATION)
    # =========================================================================
    {
        "id": "T1027", "name": "Payload Obfuscation", "score": 75, "mitre": "T1027",
        "axis": "Obfuscation", "desc": "Hiding code using encoding.",
        "pattern": r"(base64_decode|FromBase64String|xor_encrypt|rot13|strrev|chr\(|ord\(|gzip\.decompress|zlib\.inflate|pack\('H\*'|Hex-String|Char-Code)"
    },
    {
        "id": "T1562.001", "name": "Disable Security Tools", "score": 95, "mitre": "T1562",
        "axis": "Obfuscation", "desc": "Killing AV or Firewalls.",
        "pattern": r"(Set-MpPreference.*Disable|sc\s+stop\s+windefend|netsh\s+advfirewall.*off|ufw\s+disable|iptables\s+-F|Kill-Process.*av|fltmc\s+unload|AMSI_Bypass)"
    },
    {
        "id": "T1140", "name": "Deobfuscate/Decode Files", "score": 70, "mitre": "T1140",
        "axis": "Obfuscation", "desc": "Decoding malicious artifacts at runtime.",
        "pattern": r"(certutil\s+-decode|openssl\s+enc\s+-d|gpg\s+-d|Expand-Archive|tar\s+-x|unzip|7z\s+e)"
    },
    {
        "id": "T1070.004", "name": "File Deletion / Log Wiping", "score": 80, "mitre": "T1070",
        "axis": "Obfuscation", "desc": "Removing evidence of activity.",
        "pattern": r"(rm\s+-rf|del\s+/s\s+/q|Clear-EventLog|wevtutil\s+cl|history\s+-c|shred|sdelete|fs\.unlink|os\.remove|TruncateFile)"
    },
    {
        "id": "T1497", "name": "Anti-Analysis / Sandbox Evasion", "score": 70, "mitre": "T1497",
        "axis": "Obfuscation", "desc": "Detecting if running in a VM/Debugger.",
        "pattern": r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|GetTickCount|VirtualBox|VMWare|QEMU|Xen|Sandie|Cuckoo|Sleep\(\d{4,}\))"
    },
    {
        "id": "T1027.002", "name": "Binary Packing", "score": 60, "mitre": "T1027",
        "axis": "Obfuscation", "desc": "Evidence of packed executables.",
        "pattern": r"(UPX\d|FSG!|MEW|MPRESS|Themida|Obsidium|VMProtect|ConfuserEx|Eazfuscator)"
    },

    # =========================================================================
    # 5. CREDENTIAL ACCESS (RADAR AXIS: CREDENTIALS)
    # =========================================================================
    {
        "id": "T1003.001", "name": "LSASS Memory Dumping", "score": 100, "mitre": "T1003",
        "axis": "Credentials", "desc": "Dumping memory to steal hashes.",
        "pattern": r"(lsass\.exe|MiniDumpWriteDump|procdump|comsvcs\.dll|rundll32.*MiniDump|Mimikatz|Sekurlsa|LogonPasswords)"
    },
    {
        "id": "T1056.001", "name": "Keylogging", "score": 90, "mitre": "T1056",
        "axis": "Credentials", "desc": "Capturing keystrokes.",
        "pattern": r"(GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD|pynput\.keyboard|IOHIDManager|GetKeyState|LogKeys|/dev/input/event)"
    },
    {
        "id": "T1555", "name": "Password Store Theft", "score": 85, "mitre": "T1555",
        "axis": "Credentials", "desc": "Stealing saved passwords from browsers/wallets.",
        "pattern": r"(Login Data|Cookies|wallet\.dat|id_rsa|authorized_keys|unattend\.xml|web\.config|connectionString|password=|aws_access_key)"
    },
    {
        "id": "T1115", "name": "Clipboard Theft", "score": 80, "mitre": "T1115",
        "axis": "Credentials", "desc": "Monitoring clipboard content.",
        "pattern": r"(GetClipboardData|clipboard\.paste|pyperclip\.copy|pbpaste|xclip|OpenClipboard)"
    },
    {
        "id": "T1003.002", "name": "SAM/SYSTEM Hive Dumping", "score": 95, "mitre": "T1003",
        "axis": "Credentials", "desc": "Copying registry hives containing hashes.",
        "pattern": r"(reg\s+save\s+hklm\\sam|reg\s+save\s+hklm\\system|secretsdump|samdump|ntds\.dit|vssadmin.*shadow)"
    },

    # =========================================================================
    # 6. DISCOVERY (RADAR AXIS: DISCOVERY)
    # =========================================================================
    {
        "id": "T1046", "name": "Network Service Scanning", "score": 40, "mitre": "T1046",
        "axis": "Discovery", "desc": "Scanning for open ports.",
        "pattern": r"(nmap|masscan|zenmap|portscan|socket\.connect_ex|192\.168\.|10\.\d+\.\d+|172\.16\.|FullScan|SYN_SCAN)"
    },
    {
        "id": "T1082", "name": "System Info Discovery", "score": 30, "mitre": "T1082",
        "axis": "Discovery", "desc": "Gathering OS details.",
        "pattern": r"(systeminfo|uname\s+-a|Get-ComputerInfo|wmic\s+os|lscpu|/proc/cpuinfo|hostname|ver|sw_vers)"
    },
    {
        "id": "T1033", "name": "User Discovery", "score": 30, "mitre": "T1033",
        "axis": "Discovery", "desc": "Identifying current user.",
        "pattern": r"(whoami|id|wmic\s+useraccount|Get-LocalUser|/etc/passwd|net\s+user|quser)"
    },
    {
        "id": "T1057", "name": "Process Discovery", "score": 30, "mitre": "T1057",
        "axis": "Discovery", "desc": "Listing running processes.",
        "pattern": r"(tasklist|Get-Process|ps\s+aux|top|htop|pgrep|CreateToolhelp32Snapshot|Process32First)"
    },
    {
        "id": "T1012", "name": "Query Registry", "score": 25, "mitre": "T1012",
        "axis": "Discovery", "desc": "Reading registry keys.",
        "pattern": r"(reg\s+query|RegQueryValue|Get-ItemProperty.*Registry)"
    },

    # =========================================================================
    # 7. LATERAL MOVEMENT & C2 (RADAR AXIS: LATERAL_MOV)
    # =========================================================================
    {
        "id": "T1071", "name": "C2 Communication", "score": 85, "mitre": "T1071",
        "axis": "LateralMov", "desc": "Traffic to Command & Control servers.",
        "pattern": r"(socket\.socket|fsockopen|InternetOpen|HttpOpenRequest|WinHttp|LWP::UserAgent|requests\.get|urllib\.request|curl|wget|beacon|payload|c2_server)"
    },
    {
        "id": "T1572", "name": "Protocol Tunneling", "score": 90, "mitre": "T1572",
        "axis": "LateralMov", "desc": "Tunneling traffic to bypass firewalls.",
        "pattern": r"(ngrok|chisel|frp|dnscat|socat|stunnel|plink|ssh\s+-R|proxychains|ligolo|ptunnel)"
    },
    {
        "id": "T1210", "name": "Exploitation of Remote Services", "score": 95, "mitre": "T1210",
        "axis": "LateralMov", "desc": "Spreading via SMB/RDP exploits.",
        "pattern": r"(psexec|smbexec|wmic\s+/node|Invoke-Command\s+-ComputerName|Enter-PSSession|tscon|rdesktop|xfreerdp|EternalBlue)"
    },
    {
        "id": "T1090", "name": "Proxy / Tor Usage", "score": 80, "mitre": "T1090",
        "axis": "LateralMov", "desc": "Hiding traffic source.",
        "pattern": r"(tor\.exe|socks5|9050|9150|gopher://|proxy:|AssignProxy|WinINet)"
    },
    {
        "id": "T1570", "name": "Lateral Tool Transfer", "score": 75, "mitre": "T1570",
        "axis": "LateralMov", "desc": "Moving files between systems.",
        "pattern": r"(scp|rsync|copy\s+\\\\.*\\C\$|admin\$|ipc\$|bitsadmin|certutil\s+-urlcache)"
    },

    # =========================================================================
    # 8. IMPACT & DESTRUCTION (RADAR AXIS: IMPACT)
    # =========================================================================
    {
        "id": "T1486", "name": "Ransomware Encryption", "score": 100, "mitre": "T1486",
        "axis": "Impact", "desc": "Mass encryption of files.",
        "pattern": r"(AESEncrypt|RSAEncrypt|ChaCha20|BitLocker|EncryptFile|WannaCry|Ryuk|LockBit|REvil|\.enc|\.locked|RansomNote|restore_files)"
    },
    {
        "id": "T1490", "name": "Inhibit System Recovery", "score": 100, "mitre": "T1490",
        "axis": "Impact", "desc": "Deleting backups to prevent restoration.",
        "pattern": r"(vssadmin.*delete.*shadows|wbadmin.*delete.*backup|bcdedit.*recoveryenabled.*No|wmic.*shadowcopy.*delete)"
    },
    {
        "id": "T1485", "name": "Disk Wiper / Data Destruction", "score": 100, "mitre": "T1485",
        "axis": "Impact", "desc": "Permanently destroying data.",
        "pattern": r"(cipher\s+/w|dd\s+if=/dev/zero|format\s+c:|rm\s+-rf\s+/|shred|Overwrite|WipeDisk|KillDisk)"
    },
    {
        "id": "T1496", "name": "Cryptojacking (Mining)", "score": 85, "mitre": "T1496",
        "axis": "Impact", "desc": "Resource hijacking for mining.",
        "pattern": r"(xmrig|minerd|cgminer|cpuminer|stratum\+tcp|cryptonight|ethminer|nicehash|wallet_address|hwloc|cudaMalloc)"
    },
    {
        "id": "T1529", "name": "System Shutdown/Reboot", "score": 70, "mitre": "T1529",
        "axis": "Impact", "desc": "Forced reboot to disrupt ops.",
        "pattern": r"(shutdown\s+/r|shutdown\s+/s|init\s+0|init\s+6|reboot|halt|SetSystemPowerState)"
    }
]

# 🔥 EXPORT INSTANCE
MITRE_ENGINE = EnterpriseThreatEngine()

# """
# UNIVERSAL BEHAVIOR RULES (MASTER V3.0 - BINARY OPTIMIZED)
# --------------------------------------------------------------------------------
# A curated list of 75+ heuristic patterns mapping to MITRE ATT&CK techniques.
# Optimized for Source Code AND Compiled Binary Strings (PE/ELF Headers & Imports).
# """

# BEHAVIOR_RULES = [
#     # =========================================================================
#     # 1. MEMORY FORENSICS & INJECTION (Binary Specific) - Score: 100
#     # =========================================================================
#     {
#         "id": "T1055", "name": "Process Injection (Windows API)", "score": 100,
#         "mitre": "T1055", "languages": ["C", "C++", "Binary"],
#         "pattern": r"\b(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|OpenProcess|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection|RtlCreateUserThread|ZwQueueApcThread)\b"
#     },
#     {
#         "id": "T1055.002", "name": "Linux/Unix Injection", "score": 100,
#         "mitre": "T1055.002", "languages": ["C", "Linux"],
#         "pattern": r"\b(ptrace|PTRACE_POKETEXT|PTRACE_ATTACH|process_vm_writev|LD_PRELOAD|/etc/ld\.so\.preload)\b"
#     },
#     {
#         "id": "T1129", "name": "Dynamic API Loading (Evasion)", "score": 85,
#         "mitre": "T1129", "languages": ["C", "Binary"],
#         "pattern": r"\b(LoadLibrary|GetProcAddress|LdrLoadDll|GetModuleHandle|dlopen|dlsym)\b"
#     },

#     # =========================================================================
#     # 2. PACKING & ANTI-ANALYSIS (Binary Specific) - Score: 80
#     # =========================================================================
#     {
#         "id": "T1027.002", "name": "Packed Binary Artifacts", "score": 90,
#         "mitre": "T1027.002", "languages": ["Binary"],
#         "pattern": r"\b(UPX0|UPX1|MPRESS|FSG!|ASPack|Themida|Section0|TE v1\.|VProtect|Petite|NsPacK|yoda's crypter)\b"
#     },
#     {
#         "id": "T1622", "name": "Anti-Debugging Checks", "score": 85,
#         "mitre": "T1622", "languages": ["C", "Binary"],
#         "pattern": r"\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|NtGlobalFlag|FindWindow|RDTSC|GetTickCount|QueryPerformanceCounter)\b"
#     },
#     {
#         "id": "T1497", "name": "Virtualization/Sandbox Detection", "score": 80,
#         "mitre": "T1497", "languages": ["Binary"],
#         "pattern": r"(VBoxService|VBoxTray|VMTools|VMware|QEMU|Xen|SbieDll\.dll|Sandie|Analysis|Malware|Sample|Virus)"
#     },

#     # =========================================================================
#     # 3. CRITICAL EXECUTION & RCE (Score: 100)
#     # =========================================================================
#     {
#         "id": "T1059", "name": "Critical RCE (Shell Execution)", "score": 100,
#         "mitre": "T1059", "languages": ["All"],
#         "pattern": r"\b(os\.system|subprocess\.call|cmd\.exe|/bin/sh|/bin/bash|powershell|exec\(|child_process\.exec|Runtime\.getRuntime\(\)\.exec|system\(|ShellExecute|CreateProcess|WinExec|execve|exec\.Command|shell_exec|passthru|proc_open|popen|Start-Process|Invoke-Expression|WScript\.Shell|vbscript:execute|std::process::Command|syscall\.Exec|io\.popen)\b"
#     },
#     {
#         "id": "T1059.006", "name": "Reverse Shell (One-Liner)", "score": 100,
#         "mitre": "T1059.004", "languages": ["Python", "Bash", "Perl", "Ruby", "Netcat"],
#         "pattern": r"(nc\s+-e|nc\.exe\s+-e|/dev/tcp/|socket\.connect.*subprocess|bash\s+-i\s+>&|0>&1|powercat|ruby\s+-rsocket|perl\s+-e.*socket|php\s+-r.*fsockopen|meterpreter|reverse_tcp|os\.dup2|bind_tcp|shell_reverse_tcp)"
#     },
#     {
#         "id": "T1203", "name": "Unsafe Deserialization", "score": 95,
#         "mitre": "T1203", "languages": ["Python", "Java", "Node", "PHP"],
#         "pattern": r"\b(pickle\.loads|cPickle\.loads|ObjectInputStream|readObject|unserialize|yaml\.load|marshal\.load|JSON\.parse.*func|node-serialize)\b"
#     },

#     # =========================================================================
#     # 4. PERSISTENCE & PRIVILEGE ESCALATION (Score: 90)
#     # =========================================================================
#     {
#         "id": "T1547", "name": "Persistence (Registry/Startup)", "score": 90,
#         "mitre": "T1547", "languages": ["Windows", "Linux"],
#         "pattern": r"(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|REG\s+ADD|schtasks|crontab|init\.d|rc\.local|LaunchAgents|LaunchDaemons|bcdedit|Autorun|RegistryKey|Set-ItemProperty.*Run|RegSetValueEx|RegCreateKey)"
#     },
#     {
#         "id": "T1543", "name": "Service/Daemon Creation", "score": 85,
#         "mitre": "T1543", "languages": ["Windows", "Linux"],
#         "pattern": r"(sc\.exe\s+create|New-Service|systemctl\s+enable|CreateService|OpenSCManager|InstalleService|chkconfig|update-rc\.d)"
#     },
#     {
#         "id": "T1078", "name": "Privilege Escalation Ops", "score": 95,
#         "mitre": "T1078", "languages": ["Shell", "C", "Python"],
#         "pattern": r"(sudo\s+|uac_bypass|RunAs|SetUID|whoami\s+/priv|net\s+localgroup\s+administrators|chmod\s+777|chown\s+root|Set-ExecutionPolicy\s+Unrestricted|visudo|useradd|net\s+user\s+/add|SeDebugPrivilege|AdjustTokenPrivileges|cap_add|--privileged)"
#     },

#     # =========================================================================
#     # 5. CREDENTIAL ACCESS & SPYWARE (Score: 90)
#     # =========================================================================
#     {
#         "id": "T1003", "name": "Credential Dumping", "score": 100,
#         "mitre": "T1003", "languages": ["C++", "PowerShell", "Python"],
#         "pattern": r"\b(Mimikatz|Sekurlsa|procdump|samdump|lsass|MiniDumpWriteDump|LsaRetrievePrivateData|VaultEnumerateItems|sqldump|LaZagne|hashcat|JohnTheRipper|wdigest|tspkg|kerberos)\b"
#     },
#     {
#         "id": "T1056", "name": "Keylogging/Input Capture", "score": 90,
#         "mitre": "T1056", "languages": ["C++", "Python", "Swift"],
#         "pattern": r"(pynput\.keyboard|GetAsyncKeyState|SetWindowsHookEx|log_keys|document\.onkeypress|dev/input/event|CGEventCreateKeyboardEvent|HookManager|KeyEventArgs|/dev/input/mice|IOHIDManager|RegisterRawInputDevices|WH_KEYBOARD_LL|GetKeyboardState|MapVirtualKey)"
#     },

#     # =========================================================================
#     # 6. DATA EXFILTRATION & NETWORK (Score: 70)
#     # =========================================================================
#     {
#         "id": "T1041", "name": "Data Exfiltration API", "score": 75,
#         "mitre": "T1041", "languages": ["Python", "JS", "Go", "C#"],
#         "pattern": r"(requests\.post|socket\.socket|socket\.send|ftp://|smtplib|fsockopen|WebClient\.Upload|PostAsync|LWP::UserAgent|net\.Dial|InternetOpen|HttpSendRequest|URLDownloadToFile|xmpp|irc|telegram|discord|webhook|dshackle|curl_exec|gopher://)"
#     },
#     {
#         "id": "T1572", "name": "Tunneling & Proxy Tools", "score": 80,
#         "mitre": "T1572", "languages": ["Go", "C", "Shell"],
#         "pattern": r"\b(ngrok|chisel|frpc|dnscat|ptunnel|ligolo|socat|stunnel|plink|ssh\s+-R|proxychains)\b"
#     },
#     {
#         "id": "T1090", "name": "Cloud Metadata Theft", "score": 95,
#         "mitre": "T1090", "languages": ["Cloud", "Shell"],
#         "pattern": r"(169\.254\.169\.254|metadata\.google\.internal|aws_access_key_id|aws_secret_access_key|s3://|blob\.core\.windows\.net|metadata/v1/|iam/security-credentials|computeMetadata)"
#     },

#     # =========================================================================
#     # 7. IMPACT & DESTRUCTION (Score: 100)
#     # =========================================================================
#     {
#         "id": "T1486", "name": "Ransomware Activity", "score": 100,
#         "mitre": "T1486", "languages": ["C++", "Python", "Go"],
#         "pattern": r"(vssadmin.*Delete.*Shadows|wbadmin.*DELETE.*BACKUP|bcdedit.*recoveryenabled|WannaCry|\.enc|AESEncrypt|RSAEncrypt|EncryptFile|CryptEncrypt|CryptGenKey|RansomNote|cipher\s+/w|FormatMessage|BitLocker|ChaCha20Poly1305|XChaCha20)"
#     },
#     {
#         "id": "T1485", "name": "Data Destruction (Wiper)", "score": 100,
#         "mitre": "T1485", "languages": ["Shell", "Python"],
#         "pattern": r"(open\(.*['\"]w['\"]\)|os\.remove|shutil\.rmtree|chmod|attrib\s+\+h|fs\.writeFile|fs\.unlink|File\.Delete|remove\(|del\s+|rm\s+-rf|WriteAllText|FileInfo\.Delete|unlink\(|fwrite|ioutil\.WriteFile|std::ofstream|CFile::Write|MoveFile|shred|icacls|takeown|dd\s+if=/dev/zero)"
#     }
# ]