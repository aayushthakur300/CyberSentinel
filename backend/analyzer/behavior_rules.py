# backend/analyzer/behavior_rules.py

"""
Universal Behavior Rules for AI Malware Analyzer.
These Regex patterns detect suspicious behavior across 20+ languages.
Matched patterns map directly to the keys in 'risk_engine.py'.
"""

BEHAVIOR_RULES = [
    # ---------------------------------------------------------
    # 1. COMMAND EXECUTION (Score: 85)
    # ---------------------------------------------------------
    {
        "name": "Command Execution", 
        "pattern": r"(os\.system|subprocess\.call|cmd\.exe|/bin/sh|/bin/bash|powershell|exec\(|child_process\.exec|Runtime\.getRuntime\(\)\.exec|system\(|ShellExecute|CreateProcess|exec\.Command|shell_exec|passthru|proc_open|popen|`.*`|Start-Process|Invoke-Expression|WScript\.Shell|vbscript:execute|std::process::Command|syscall\.Exec|io\.popen)"
    },

    # ---------------------------------------------------------
    # 2. NETWORK EXFILTRATION (Score: 65) - HIGH RISK
    # (Only matches pushing data OUT or connecting to sockets)
    # ---------------------------------------------------------
    {
        "name": "Network Exfiltration", 
        "pattern": r"(requests\.post|socket\.socket|socket\.send|ftp://|smtplib|fsockopen|WebClient\.Upload|PostAsync|LWP::UserAgent|net\.Dial|InternetOpen|xmpp|irc|telegram|discord|webhook)"
    },

    # ---------------------------------------------------------
    # 3. NETWORK ACTIVITY (Score: 20) - LOW RISK
    # (Matches downloading, browsing, or passive connections)
    # ---------------------------------------------------------
    {
        "name": "Network_Activity", 
        "pattern": r"(requests\.get|urllib\.request|http://|https://|fetch\(|curl |wget |Net\.WebClient|DownloadString|file_get_contents|http\.Get|URLSession|UnityWebRequest|WinHttp\.WinHttpRequest|axios|HttpClient|TcpClient|urlopen)"
    },

    # ---------------------------------------------------------
    # 4. FILE TAMPERING (Score: 30)
    # ---------------------------------------------------------
    {
        "name": "File Tampering", 
        "pattern": r"(open\(.*['\"]w['\"]\)|os\.remove|shutil\.rmtree|chmod|attrib \+h|fs\.writeFile|fs\.unlink|File\.Delete|remove\(|del |rm -rf|WriteAllText|FileInfo\.Delete|unlink\(|fwrite|ioutil\.WriteFile|std::ofstream|CFile::Write|MoveFile|shred|icacls|takeown)"
    },

    # ---------------------------------------------------------
    # 5. KEYLOGGING (Score: 90)
    # ---------------------------------------------------------
    {
        "name": "Keylogging", 
        "pattern": r"(pynput\.keyboard|GetGetAsyncKeyState|SetWindowsHookEx|log_keys|GetAsyncKeyState|document\.onkeypress|dev/input/event|CGEventCreateKeyboardEvent|HookManager|KeyEventArgs|/dev/input/mice|IOHIDManager|RegisterRawInputDevices)"
    },

    # ---------------------------------------------------------
    # 6. REVERSE SHELLS (Score: 100)
    # ---------------------------------------------------------
    {
        "name": "Reverse Shell", 
        "pattern": r"(nc -e|/dev/tcp/|socket\.connect.*subprocess|bash -i >&|0>&1|nc\.exe|socat |powercat|ruby -rsocket|perl -e .*socket|php -r .*fsockopen|meterpreter|reverse_tcp|os\.dup2)"
    },

    # ---------------------------------------------------------
    # 7. PRIVILEGE ESCALATION (Score: 95)
    # ---------------------------------------------------------
    {
        "name": "Privilege Escalation", 
        "pattern": r"(sudo |uac_bypass|RunAs|SetUID|whoami /priv|net localgroup administrators|chmod 777|chown root|Set-ExecutionPolicy Unrestricted|visudo|useradd|net user /add|SeDebugPrivilege|cap_add|--privileged)"
    },

    # ---------------------------------------------------------
    # 8. OBFUSCATION (Score: 60)
    # ---------------------------------------------------------
    {
        "name": "Obfuscation", 
        "pattern": r"(base64\.b64decode|eval\(|str_rot13|codecs\.decode|fromCharCode|unescape|Base64String|Convert\.FromBase64String|gzinflate|pack\(|xor_encrypt|VirtualAlloc|WriteProcessMemory|Reflect\.define|marshal|zlib|hexlify|CryptDecrypt)"
    },

    # ---------------------------------------------------------
    # 9. PERSISTENCE (Score: 75)
    # ---------------------------------------------------------
    {
        "name": "Persistence", 
        "pattern": r"(reg add|schtasks|crontab|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|Startup|Autorun|init\.d|rc\.local|LaunchAgents|LaunchDaemons|bcdedit|at \d+|cron\.hourly|\.bashrc|\.profile|ENTRYPOINT|CMD)"
    },

    # ---------------------------------------------------------
    # 10. CRYPTO MINING (Score: 45)
    # ---------------------------------------------------------
    {
        "name": "Crypto Mining", 
        "pattern": r"(stratum\+tcp|minerd|cgminer|xmrig|cpuminer|cryptonight|nicehash|wallet_address|ethminer|monero)"
    },

    # ---------------------------------------------------------
    # 11. DATABASE INJECTION (Score: 40)
    # ---------------------------------------------------------
    {
        "name": "Database Injection", 
        "pattern": r"(UNION SELECT|DROP TABLE|OR '1'='1'|WAITFOR DELAY|xp_cmdshell|pg_sleep|sleep\(\d+\)|db\.eval\(|mysql_query|sqlite3_exec|--)"
    },

    # ---------------------------------------------------------
    # 12. RANSOMWARE BEHAVIOR (Score: 100)
    # ---------------------------------------------------------
    {
        "name": "Ransomware_Behavior",
        "pattern": r"(vssadmin.*Delete.*Shadows|wbadmin.*DELETE.*BACKUP|bcdedit.*recoveryenabled|WannaCry|\.enc|AESEncrypt|RSAEncrypt|EncryptFile|RansomNote)"
    }
]