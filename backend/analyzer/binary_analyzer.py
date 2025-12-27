import pefile
import re
import math
import hashlib
import traceback
# 🔥 CRITICAL: Connects the Binary Engine to the MITRE Brain
try:
    from .mitre_mapping import get_mitre_tag, MITRE_SIGNATURES
except ImportError:
    # Fallback for standalone testing
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"
    MITRE_SIGNATURES = {}

async def analyze_binary_file(content: bytes, filename: str):
    behaviors = []
    metadata = {}
    extracted_text = ""

    # 1. Basic Metadata (Hash & Size)
    metadata["filename"] = filename
    metadata["filesize"] = f"{len(content) / 1024:.2f} KB"
    metadata["sha256"] = hashlib.sha256(content).hexdigest()

    # 2. Advanced String Forensics (The "Strings" command)
    try:
        # Decode bytes to latin-1 to keep all characters
        raw_text = content.decode('latin-1')
        # Find sequences of 4+ printable characters
        strings = re.findall(r'[ -~]{4,}', raw_text)
        extracted_text = "\n".join(strings)
        
        if len(extracted_text) < 10:
            extracted_text = "No readable strings found. File might be packed or encrypted."
        
        # 🔥 UPGRADE 1: Scan for ALL 50+ MITRE Signatures in Strings
        # This allows detecting Python scripts, PHP shells, or Ruby hacks HIDDEN inside the binary
        lower_text = extracted_text.lower()
        for signature in MITRE_SIGNATURES.keys():
            if signature.lower() in lower_text:
                tag = get_mitre_tag(signature, f"Artifact Found: '{signature}' inside binary")
                behaviors.append(tag)

        # 🔥 UPGRADE 2: Detect Source Language of the Binary
        # Check for unique compiler artifacts
        if "go.buildid" in lower_text: behaviors.append("[INFO] Binary Source: Written in Go (Golang)")
        if "rustc" in lower_text or "/src/libstd" in lower_text: behaviors.append("[INFO] Binary Source: Written in Rust")
        if "python" in lower_text and ".py" in lower_text: behaviors.append("[INFO] Binary Source: PyInstaller/Python Executable")
        if "mingw" in lower_text or "cygwin" in lower_text: behaviors.append("[INFO] Binary Source: C/C++ (GCC/MinGW Compiled)")
        if "mscoree.dll" in lower_text: behaviors.append("[INFO] Binary Source: C# / .NET")

    except Exception as e:
        extracted_text = f"String extraction failed: {str(e)}"

    # 3. PE Header Analysis (Windows Executables)
    try:
        pe = pefile.PE(data=content)
        metadata["file_type"] = "Windows PE (Exe/Dll)"
        metadata["compile_timestamp"] = str(pe.FILE_HEADER.TimeDateStamp)

        # A. Check Sections for Entropy (Packing Detection)
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            
            # Entropy > 7.0 usually means the code is compressed/encrypted (Packed)
            if entropy > 7.0:
                behaviors.append(get_mitre_tag("UPX", f"High Entropy ({entropy:.2f}) in '{section_name}' - Potential Packing"))
            
            # B. Check for RWX Sections (Writable + Executable = Code Injection Risk)
            if section.Characteristics & 0x20000000 and section.Characteristics & 0x80000000:
                behaviors.append(get_mitre_tag("VirtualAlloc", f"RWX Section '{section_name}' (Writable & Executable)"))

        # C. Check Imported Functions (API Analysis) - EXPANDED LIST
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        
                        # 🔥 LINK: Map Windows APIs to MITRE Tactics (Expanded)
                        if func_name == "VirtualAlloc": 
                            behaviors.append(get_mitre_tag("VirtualAlloc", "Memory Allocation API"))
                        elif func_name == "CreateRemoteThread": 
                            behaviors.append(get_mitre_tag("CreateRemoteThread", "Remote Thread Injection"))
                        elif func_name == "ShellExecuteA" or func_name == "WinExec": 
                            behaviors.append(get_mitre_tag("ShellExecute", "Command Execution API"))
                        elif func_name == "WSAStartup" or func_name == "socket": 
                            behaviors.append(get_mitre_tag("socket", "Networking API Initialized"))
                        elif func_name == "GetAsyncKeyState" or func_name == "SetWindowsHookEx": 
                            behaviors.append(get_mitre_tag("spyware", "Keystroke Monitoring / Hooking"))
                        elif func_name == "IsDebuggerPresent" or func_name == "CheckRemoteDebuggerPresent":
                            behaviors.append(get_mitre_tag("IsDebuggerPresent", "Anti-Debugging Check"))
                        elif func_name == "InternetOpen" or func_name == "URLDownloadToFile":
                            behaviors.append(get_mitre_tag("requests.get", "File Download / C2 Beaconing"))
                        elif func_name == "RegOpenKey" or func_name == "RegSetValue":
                            behaviors.append(get_mitre_tag("HKCU\\Software", "Registry Persistence Mechanism"))

    except pefile.PEFormatError:
        metadata["file_type"] = "Non-PE File (Likely Linux ELF, Mac Mach-O, or Raw Data)"
        # Simple fallback for ELF headers (Linux)
        if content.startswith(b'\x7fELF'):
            metadata["file_type"] = "Linux ELF Binary"
            behaviors.append("[INFO] Linux Executable detected")
    except Exception as e:
        # 🔥 ADDED TRACEBACK HERE
        print("❌ PE Analysis Error:")
        traceback.print_exc()
        behaviors.append(f"Binary Analysis Error: {str(e)}")

    # Deduplicate behaviors
    behaviors = list(set(behaviors))
    
    return extracted_text, behaviors, metadata

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# import pefile
# import re
# import math
# import hashlib
# import traceback

# # 🔥 CRITICAL FIX: Import the Class Instance
# try:
#     from analyzer.mitre_mapping import MITRE_ENGINE
# except ImportError:
#     MITRE_ENGINE = None

# async def analyze_binary_file(content: bytes, filename: str):
#     behaviors = []
#     metadata = {}
#     extracted_text = ""

#     # 1. Basic Metadata
#     metadata["filename"] = filename
#     metadata["filesize"] = f"{len(content) / 1024:.2f} KB"
#     metadata["sha256"] = hashlib.sha256(content).hexdigest()

#     # 2. String Forensics
#     try:
#         raw_text = content.decode('latin-1')
#         strings = re.findall(r'[ -~]{4,}', raw_text)
#         extracted_text = "\n".join(strings)
        
#         if len(extracted_text) < 10:
#             extracted_text = "No readable strings found. File might be packed or encrypted."
        
#         # 🔥 UPGRADE: Use the Class Engine
#         if MITRE_ENGINE:
#             # We access the internal signatures dict directly for string matching
#             for key, sig_data in MITRE_ENGINE.signatures.items():
#                 # Simple string check (faster than full regex for massive binaries)
#                 # For more accuracy, use MITRE_ENGINE.scan(extracted_text)
#                 if key.lower() in extracted_text.lower(): 
#                     tag = f"[{sig_data['id']}] Found Artifact: '{sig_data['name']}'"
#                     behaviors.append(tag)

#     except Exception as e:
#         print("❌ String Extraction Error:")
#         traceback.print_exc()
#         extracted_text = f"String extraction failed: {str(e)}"

#     # 3. PE Analysis
#     try:
#         pe = pefile.PE(data=content)
#         metadata["file_type"] = "Windows PE (Exe/Dll)"
        
#         for section in pe.sections:
#             entropy = calculate_entropy(section.get_data())
#             if entropy > 7.0:
#                 behaviors.append("[T1027.002] High Entropy Section (Packed)")
            
#             # RWX Check
#             if section.Characteristics & 0xE0000020:
#                 behaviors.append("[T1055] RWX Section (Memory Injection Risk)")

#     except pefile.PEFormatError:
#         metadata["file_type"] = "Non-PE File"
#     except Exception:
#         pass

#     return extracted_text, list(set(behaviors)), metadata

# def calculate_entropy(data):
#     if not data: return 0
#     entropy = 0
#     for x in range(256):
#         p_x = float(data.count(x)) / len(data)
#         if p_x > 0:
#             entropy += - p_x * math.log(p_x, 2)
#     return entropy