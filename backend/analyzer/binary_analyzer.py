import re
import pefile  # For analyzing Windows EXE headers
import hashlib # <--- 🔥 REQUIRED for hash calculation

def get_strings(data, min_length=4):
    """
    Extracts ASCII and Unicode strings from binary data.
    """
    result = ""
    # Regex for ASCII strings
    ascii_strings = re.findall(b"[ -~]{%d,}" % min_length, data)
    for s in ascii_strings:
        result += s.decode("utf-8", errors="ignore") + "\n"
    
    # Regex for Unicode strings (common in Windows)
    unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){%d,}" % min_length, data)
    for s in unicode_strings:
        result += s.decode("utf-16le", errors="ignore") + "\n"
        
    return result

def analyze_binary_file(file_content: bytes, filename: str):
    detected_behaviors = []
    
    # 1. Calculate SHA256 Hash (Required for Report)
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    metadata = {
        "filename": filename, 
        "file_type": "Unknown", 
        "compile_timestamp": "N/A",
        "sha256": file_hash 
    }

    # 2. PE Header Analysis (Windows Executables)
    if filename.lower().endswith((".exe", ".dll", ".sys")):
        try:
            pe = pefile.PE(data=file_content)
            metadata["file_type"] = "Windows PE Executable"
            metadata["compile_timestamp"] = pe.FILE_HEADER.TimeDateStamp
            
            # Check for suspicious sections (e.g., UPX packing)
            for section in pe.sections:
                sec_name = section.Name.decode(errors='ignore').strip('\x00')
                
                if "UPX" in sec_name:
                    detected_behaviors.append("Packed Binary (UPX detected) - Potential Obfuscation")
                if getattr(section, "Characteristics", 0) & 0xE0000020: # Write + Execute + Code
                    detected_behaviors.append(f"Writable+Executable Section found: {sec_name}")

        except Exception as e:
            metadata["error"] = f"PE Parsing Warning: {str(e)}"

    # 3. String Extraction
    extracted_text = get_strings(file_content)
    
    return extracted_text, detected_behaviors, metadata