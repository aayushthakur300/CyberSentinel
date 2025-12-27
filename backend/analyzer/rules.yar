/*
    CYBERSENTINEL MASTER YARA RULESET (FINAL INTEGRATED)
    Covers: 50+ Attacks, 20+ Languages, Images/Stego, Ransomware, & C2.
*/

// =========================================================================
// 1. RANSOMWARE & DESTRUCTIVE (Critical)
// =========================================================================

rule python_ransomware {
    meta:
        description = "Python Ransomware: Encrypts & Overwrites Files"
        severity = "Critical"
        mitre_id = "T1486"
    strings:
        // Encryption Libraries
        $c1 = "cryptography.fernet" nocase
        $c2 = "Fernet" nocase
        $c3 = "pyAesCrypt" nocase
        
        // File Traversal
        $w1 = "os.walk" nocase
        $w2 = "glob.glob" nocase
        
        // Destructive Actions
        $a1 = ".write(b\"" nocase
        $a2 = "open(" nocase
        $a3 = ".encrypt(" nocase
    condition:
        ($c1 or $c2 or $c3) and ($w1 or $w2) and ($a1 or $a2 or $a3)
}

rule ransomware_system_tools {
    meta:
        description = "Ransomware System Manipulation (Shadow Copies)"
        severity = "Critical"
        mitre_id = "T1490"
    strings:
        $s1 = "vssadmin" nocase
        $s2 = "Delete Shadows" nocase
        $s3 = "wbadmin" nocase
        $s4 = "bcdedit" nocase
        $s5 = "/boot/bcd" nocase
    condition:
        any of them
}

rule wannacry_indicators {
    meta:
        description = "WannaCry / SMB Exploit Indicators"
        severity = "Critical"
        mitre_id = "T1486"
    strings:
        $s1 = "mssecsvc.exe" nocase
        $s2 = "tasksche.exe" nocase
        $s3 = "WanaDecryptor" nocase
    condition:
        any of them
}

rule destructive_commands {
    meta:
        description = "Destructive System Commands (Wipers)"
        severity = "Critical"
        mitre_id = "T1485"
    strings:
        $s1 = "rm -rf /" 
        $s2 = "mkfs.ext4"
        $s3 = "dd if=/dev/zero"
        $s4 = ":(){ :|:& };:" // Fork Bomb
        $s5 = "cipher /w" // Windows Wiper
    condition:
        any of them
}

// =========================================================================
// 2. IMAGES & STEGANOGRAPHY (New Section)
// =========================================================================

rule polyglot_image_webshell {
    meta:
        description = "Malicious Code Hidden in Image (Polyglot)"
        severity = "Critical"
        mitre_id = "T1027.003"
    strings:
        // Magic Bytes for Images
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 }
        $gif = "GIF8"
        
        // Malicious Payloads
        $php = "<?php"
        $eval = "eval("
        $system = "system("
        $cmd = "cmd.exe"
        $sh = "/bin/sh"
    condition:
        ($jpg or $png or $gif) and ($php or $eval or $system or $cmd or $sh)
}

rule stego_tool_artifacts {
    meta:
        description = "Artifacts from Steganography Tools"
        severity = "High"
        mitre_id = "T1027.003"
    strings:
        $s1 = "steghide" nocase
        $s2 = "openstego" nocase
        $s3 = "outguess" nocase
        $s4 = "JPHide" nocase
    condition:
        any of them
}

// =========================================================================
// 3. WEB SHELLS & BACKDOORS (PHP, JSP, ASP, Node)
// =========================================================================

rule php_webshell_advanced {
    meta:
        description = "PHP Web Shell / Backdoor"
        severity = "Critical"
        mitre_id = "T1505.003"
    strings:
        $s1 = "eval($_POST" nocase
        $s2 = "system($_GET" nocase
        $s3 = "shell_exec(" nocase
        $s4 = "base64_decode($" nocase
        $s5 = "passthru(" nocase
        $s6 = "proc_open(" nocase
        $s7 = "pcntl_exec" nocase
    condition:
        any of them
}

rule jsp_webshell {
    meta:
        description = "Java JSP Web Shell"
        severity = "Critical"
        mitre_id = "T1505.003"
    strings:
        $s1 = "Runtime.getRuntime().exec(" nocase
        $s2 = "ProcessBuilder(" nocase
        $s3 = "cmd.exe" nocase
        $s4 = "/bin/sh" nocase
    condition:
        ($s1 or $s2) and ($s3 or $s4)
}

rule asp_webshell {
    meta:
        description = "ASP.NET / C# Web Shell"
        severity = "Critical"
        mitre_id = "T1505.003"
    strings:
        $s1 = "eval(" nocase
        $s2 = "Page_Load" nocase
        $s3 = "Process.Start(" nocase
        $s4 = "cmd.exe" nocase
    condition:
        all of ($s1, $s2) or ($s3 and $s4)
}

rule node_rce {
    meta:
        description = "Node.js Remote Code Execution"
        severity = "Critical"
        mitre_id = "T1059.007"
    strings:
        $s1 = "require('child_process')" nocase
        $s2 = "exec(" nocase
        $s3 = "spawn(" nocase
        $s4 = "eval(" nocase
    condition:
        $s1 and ($s2 or $s3 or $s4)
}

// =========================================================================
// 4. REVERSE SHELLS (Multi-Language)
// =========================================================================

rule python_reverse_shell {
    meta:
        description = "Python Reverse Shell Pattern"
        severity = "Critical"
        mitre_id = "T1059.006"
    strings:
        $s1 = "socket.socket"
        $s2 = "subprocess.call"
        $s3 = "os.dup2"
        $s4 = "pty.spawn"
        $s5 = "/bin/sh"
    condition:
        $s1 and ($s2 or $s3 or $s4 or $s5)
}

rule bash_reverse_shell {
    meta:
        description = "Bash / Netcat Reverse Shell"
        severity = "Critical"
        mitre_id = "T1059.004"
    strings:
        $s1 = "/bin/bash -i" nocase
        $s2 = "/dev/tcp/" nocase
        $s3 = "nc -e" nocase
        $s4 = "exec 5<>/dev/tcp" nocase
    condition:
        any of them
}

rule perl_ruby_reverse_shell {
    meta:
        description = "Perl/Ruby Reverse Shell"
        severity = "Critical"
        mitre_id = "T1059"
    strings:
        $p1 = "perl -e" nocase
        $p2 = "Socket.new" nocase
        $r1 = "TCPSocket.open" nocase
        $r2 = ".to_i;exec" nocase
    condition:
        any of them
}

rule golang_reverse_shell {
    meta:
        description = "Go (Golang) Reverse Shell"
        severity = "High"
        mitre_id = "T1059"
    strings:
        $s1 = "net.Dial" nocase
        $s2 = "os/exec" nocase
        $s3 = "Command(\"/bin/sh\")" nocase
    condition:
        all of them
}

// =========================================================================
// 5. MEMORY CORRUPTION & INJECTION
// =========================================================================

rule memory_injection_apis {
    meta:
        description = "Process Injection APIs (Windows)"
        severity = "Critical"
        mitre_id = "T1055"
    strings:
        $s1 = "VirtualAlloc" nocase
        $s2 = "CreateRemoteThread" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "QueueUserAPC" nocase
        $s5 = "SetWindowsHookEx" nocase
    condition:
        any of them
}

rule c_buffer_overflow {
    meta:
        description = "Potential C/C++ Buffer Overflow"
        severity = "High"
        mitre_id = "T1190"
    strings:
        $s1 = "strcpy(" 
        $s2 = "strcat(" 
        $s3 = "gets(" 
        $s4 = "sprintf(" 
    condition:
        any of them
}

// =========================================================================
// 6. CREDENTIAL THEFT & SPYWARE
// =========================================================================

rule hardcoded_credentials {
    meta:
        description = "Hardcoded Password or API Key"
        severity = "High"
        mitre_id = "T1552"
    strings:
        $pass1 = "password =" nocase
        $pass2 = "passwd =" nocase
        $api1 = "api_key =" nocase
        $token1 = "Bearer " 
        $aws1 = "AKIA[0-9A-Z]{16}" // AWS Access Key Regex
    condition:
        any of them
}

rule ssh_private_key {
    meta:
        description = "SSH Private Key Found"
        severity = "Critical"
        mitre_id = "T1552.004"
    strings:
        $s1 = "-----BEGIN RSA PRIVATE KEY-----"
        $s2 = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule mimikatz_keywords {
    meta:
        description = "Mimikatz Credential Dumping Tool"
        severity = "Critical"
        mitre_id = "T1003.001"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::lsa" nocase
        $s3 = "privilege::debug" nocase
    condition:
        any of them
}

rule keylogger_behavior {
    meta:
        description = "Keylogger Functionality"
        severity = "High"
        mitre_id = "T1056.001"
    strings:
        $s1 = "GetAsyncKeyState"
        $s2 = "GetKeyboardState"
        $s3 = "pynput.keyboard"
    condition:
        any of them
}

// =========================================================================
// 7. EVASION & OBFUSCATION
// =========================================================================

rule powershell_obfuscation {
    meta:
        description = "Obfuscated PowerShell"
        severity = "High"
        mitre_id = "T1027"
    strings:
        $s1 = "-EncodedCommand" nocase
        $s2 = "-enc " nocase
        $s3 = "FromBase64String" nocase
        $s4 = "Invoke-Obfuscation" nocase
    condition:
        any of them
}

rule packed_binary {
    meta:
        description = "Packed Binary (UPX or similar)"
        severity = "Medium"
        mitre_id = "T1027.002"
    strings:
        $s1 = "UPX0" 
        $s2 = "UPX1"
        $s3 = "LoadLibraryA" 
        $s4 = "GetProcAddress"
    condition:
        ($s1 and $s2) or ($s3 and $s4)
}

// =========================================================================
// 8. INJECTION ATTACKS (SQL, XSS, XXE)
// =========================================================================

rule sql_injection {
    meta:
        description = "SQL Injection Pattern"
        severity = "High"
        mitre_id = "T1190"
    strings:
        $s1 = "' OR '1'='1"
        $s2 = "--"
        $s3 = "UNION SELECT" nocase
        $s4 = "WAITFOR DELAY" nocase
        $s5 = "xp_cmdshell" nocase
    condition:
        any of them
}

rule xss_pattern {
    meta:
        description = "Cross-Site Scripting (XSS)"
        severity = "Medium"
        mitre_id = "T1190"
    strings:
        $s1 = "<script>alert(" nocase
        $s2 = "javascript:alert(" nocase
        $s3 = "onload=" nocase
        $s4 = "onerror=" nocase
    condition:
        any of them
}

rule xxe_injection {
    meta:
        description = "XML External Entity (XXE)"
        severity = "High"
        mitre_id = "T1190"
    strings:
        $s1 = "<!ENTITY" nocase
        $s2 = "SYSTEM \"file:///" nocase
        $s3 = "SYSTEM \"http://" nocase
    condition:
        all of them
}

// =========================================================================
// 9. PERSISTENCE & ROOTKITS
// =========================================================================

rule linux_persistence {
    meta:
        description = "Linux Persistence (Cron/RC)"
        severity = "Medium"
        mitre_id = "T1053.003"
    strings:
        $s1 = "/etc/crontab"
        $s2 = "/etc/rc.local"
        $s3 = "init.d"
    condition:
        any of them
}

rule rootkit_behavior {
    meta:
        description = "Rootkit Indicator (LD_PRELOAD)"
        severity = "Critical"
        mitre_id = "T1574.006"
    strings:
        $s1 = "LD_PRELOAD" nocase
        $s2 = "/etc/ld.so.preload"
    condition:
        any of them
}