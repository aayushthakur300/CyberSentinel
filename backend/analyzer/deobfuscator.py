import base64
import re
import binascii
import string
import codecs
import traceback

# --- CONNECT TO MITRE BRAIN ---
try:
    from .mitre_mapping import get_mitre_tag, MITRE_SIGNATURES
except ImportError:
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"
    MITRE_SIGNATURES = {}

# --- HELPER FUNCTIONS ---
def scan_decoded_content(text):
    if not text or len(text) < 4: return ""
    found_tags = []
    text_lower = text.lower()
    for signature in MITRE_SIGNATURES.keys():
        if signature.lower() in text_lower:
            tag = get_mitre_tag(signature, "")
            t_code = tag.split("]")[0] + "]" if "]" in tag else "[THREAT]"
            found_tags.append(t_code)
    return " ".join(list(set(found_tags)))

def is_meaningful_text(text: str) -> bool:
    if not text or len(text) < 3: return False
    # Must be mostly printable
    readable = sum(1 for c in text if c in string.printable and c not in string.whitespace[:2])
    return (readable / len(text)) > 0.85

def xor_brute_force(data: bytes) -> str:
    for key in range(1, 256):
        try:
            decoded_chars = [chr(b ^ key) for b in data]
            candidate = "".join(decoded_chars)
            if is_meaningful_text(candidate):
                if candidate.count('/') > len(candidate) * 0.5: continue
                return f' (XOR Key 0x{key:02X}: "{candidate}")'
        except: continue
    return ""

def attempt_deobfuscation(code: str) -> dict:
    print(f"DEBUG: Starting Deobfuscation. Input Length: {len(code)}")
    final_code = code
    pattern_found = False
    processed_matches = set()

    try:
        # Loop for Recursive Deobfuscation (Pass 1 & 2)
        for _ in range(2):
            
            # =========================================================================
            # 1. BASE64 DETECTION (Length 6+)
            # =========================================================================
            base64_matches = list(set(re.findall(r'[A-Za-z0-9+/=]{6,}', final_code)))
            for b64 in base64_matches:
                if b64 in processed_matches: continue
                try:
                    padding = len(b64) % 4
                    b64_fixed = b64 + '=' * (4 - padding) if padding else b64
                    raw_bytes = base64.b64decode(b64_fixed)
                    
                    # Text Check
                    try:
                        decoded_str = raw_bytes.decode('utf-8')
                        if decoded_str.isprintable() and len(decoded_str) > 3:
                            print(f"DEBUG: Found Base64: {decoded_str}")
                            final_code = final_code.replace(b64, f'{b64} /* DECODED: "{decoded_str}" */')
                            pattern_found = True
                            processed_matches.add(b64)
                            continue
                    except: pass

                    # Binary/XOR Check
                    hex_str = "".join([f"\\x{b:02x}" for b in raw_bytes])
                    xor_result = xor_brute_force(raw_bytes)
                    if xor_result or len(raw_bytes) > 2:
                        annotation = f' /* RAW HEX: "{hex_str}"{xor_result} */'
                        final_code = final_code.replace(b64, f"{b64}{annotation}")
                        pattern_found = True
                        processed_matches.add(b64)
                except: pass

            # =========================================================================
            # 2. HEX STRING DETECTION
            # =========================================================================
            hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){3,}|(?:0x[0-9a-fA-F]{2},?){3,}'
            hex_matches = list(set(re.findall(hex_pattern, final_code)))
            for hx in hex_matches:
                if hx in processed_matches: continue
                try:
                    cleaned = re.sub(r'\\x|0x|,|%|\s', '', hx)
                    raw_bytes = binascii.unhexlify(cleaned)
                    xor_result = xor_brute_force(raw_bytes)
                    decoded_str = raw_bytes.decode('utf-8', errors='ignore')

                    if is_meaningful_text(decoded_str) or xor_result:
                        annotation = f' /* DECODED: "{decoded_str}"{xor_result} */'
                        final_code = final_code.replace(hx, f"{hx}{annotation}")
                        pattern_found = True
                        processed_matches.add(hx)
                except: pass

            # =========================================================================
            # 3. JAVASCRIPT CHAR CODES
            # =========================================================================
            char_blocks = list(set(re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', final_code)))
            for block in char_blocks:
                full_match = f"String.fromCharCode({block})"
                if full_match in processed_matches: continue
                try:
                    nums = [int(n) for n in block.split(',')]
                    decoded = "".join(chr(n) for n in nums)
                    if len(decoded) > 3:
                        threats = scan_decoded_content(decoded)
                        final_code = final_code.replace(full_match, f'{full_match} /* CHARCODE: "{decoded}" {threats} */')
                        pattern_found = True
                        processed_matches.add(full_match)
                except: pass

            # =========================================================================
            # 4. REVERSED STRINGS
            # =========================================================================
            suspicious_reversed = ["llehsrewop", "etucexe", "daolnwod", "tpircs", "ecalper"]
            for word in suspicious_reversed:
                if word in final_code.lower():
                    pattern = re.compile(re.escape(word), re.IGNORECASE)
                    final_code = pattern.sub(lambda m: f'{m.group(0)} /* REVERSED: "{m.group(0)[::-1]}" */', final_code)
                    pattern_found = True

            # =========================================================================
            # 5. INT ARRAYS (ASCII)
            # =========================================================================
            # Matches brackets with numbers inside: [84, 69, 83]
            array_pattern = r'\[\s*((?:\d+\s*,\s*)+\d+)\s*\]'
            arrays = list(set(re.findall(array_pattern, final_code)))
            for arr_content in arrays:
                original_match = f"[{arr_content}]"
                if original_match in processed_matches: continue
                try:
                    nums = [int(n) for n in arr_content.split(',')]
                    if all(0 <= n <= 255 for n in nums):
                        decoded_str = "".join(chr(n) for n in nums)
                        if is_meaningful_text(decoded_str):
                            print(f"DEBUG: Found ASCII Array: {decoded_str}")
                            threats = scan_decoded_content(decoded_str)
                            annotation = f' /* ASCII ARRAY: "{decoded_str}" {threats} */'
                            final_code = final_code.replace(original_match, f"{original_match}{annotation}")
                            pattern_found = True
                            processed_matches.add(original_match)
                except: pass

            # =========================================================================
            # 6. ROT13
            # =========================================================================
            long_words = re.findall(r'[a-zA-Z]{10,}', final_code)
            for word in long_words:
                if word in processed_matches: continue
                try:
                    decoded = codecs.decode(word, 'rot_13')
                    if is_meaningful_text(decoded) and not decoded == word:
                        if any(k in decoded.lower() for k in ["http", "shell", "cmd", "exe", "user", "pass"]):
                            final_code = final_code.replace(word, f'{word} /* ROT13: "{decoded}" */')
                            pattern_found = True
                            processed_matches.add(word)
                except: pass

    except Exception as e:
        print("❌ CRITICAL BACKEND ERROR:")
        traceback.print_exc()

    print(f"DEBUG: Finished. Pattern Found: {pattern_found}")
    
    return {
        "results": final_code,
        "pattern_found": pattern_found
    }
# import base64
# import re
# import binascii
# import string
# import codecs
# import traceback

# # 🔥 CRITICAL FIX: Connect to the New MITRE Class Brain
# try:
#     from analyzer.mitre_mapping import MITRE_ENGINE
# except ImportError:
#     # Fallback if engine is missing during standalone testing
#     MITRE_ENGINE = None

# # =========================================================================
# # HELPER FUNCTIONS
# # =========================================================================

# def scan_decoded_content(text):
#     """
#     Scans decoded text using the central MITRE Engine.
#     Returns a string of tags to append to the code comment.
#     Example output: "[T1059] [T1083]"
#     """
#     if not text or len(text) < 4: 
#         return ""
    
#     found_tags = []
    
#     # Use the Master Engine if available
#     if MITRE_ENGINE:
#         findings = MITRE_ENGINE.scan(text)
#         for f in findings:
#             # We just want the ID for the inline comment to keep it short
#             found_tags.append(f"[{f['id']}]")
    
#     if not found_tags:
#         return ""
        
#     return "THREAT DETECTED: " + " ".join(list(set(found_tags)))

# def is_meaningful_text(text: str) -> bool:
#     """
#     Heuristic to determine if a decoded string is actually human-readable text/code
#     vs just random binary garbage.
#     """
#     if not text or len(text) < 3: return False
#     # Must be mostly printable
#     readable = sum(1 for c in text if c in string.printable and c not in string.whitespace[:2])
#     return (readable / len(text)) > 0.85

# def xor_brute_force(data: bytes) -> str:
#     """
#     Attempts single-byte XOR decryption on a byte string.
#     Returns the Key and Result if meaningful text is found.
#     """
#     for key in range(1, 256):
#         try:
#             decoded_chars = [chr(b ^ key) for b in data]
#             candidate = "".join(decoded_chars)
            
#             if is_meaningful_text(candidate):
#                 # Filter out false positives (too many slashes often means binary data interpreted as text)
#                 if candidate.count('/') > len(candidate) * 0.5: continue
                
#                 # Scan the candidate for threats
#                 threats = scan_decoded_content(candidate)
#                 return f' (XOR Key 0x{key:02X}: "{candidate}" {threats})'
#         except: 
#             continue
#     return ""

# # =========================================================================
# # MAIN DEOBFUSCATION LOGIC
# # =========================================================================

# def attempt_deobfuscation(code: str) -> dict:
#     """
#     Multi-pass deobfuscator that looks for:
#     1. Base64
#     2. Hex Strings
#     3. CharCode Arrays
#     4. Reversed Strings
#     5. Int Arrays
#     6. ROT13
#     """
#     # print(f"DEBUG: Starting Deobfuscation. Input Length: {len(code)}")
#     final_code = code
#     pattern_found = False
#     processed_matches = set()

#     try:
#         # Loop for Recursive Deobfuscation (Pass 1 & 2)
#         # We do 2 passes to handle things like Base64 encoded inside Hex
#         for _ in range(2):
            
#             # =========================================================================
#             # 1. BASE64 DETECTION (Length 6+)
#             # =========================================================================
#             base64_matches = list(set(re.findall(r'[A-Za-z0-9+/=]{6,}', final_code)))
#             for b64 in base64_matches:
#                 if b64 in processed_matches: continue
#                 try:
#                     # Fix padding if necessary
#                     padding = len(b64) % 4
#                     b64_fixed = b64 + '=' * (4 - padding) if padding else b64
#                     raw_bytes = base64.b64decode(b64_fixed)
                    
#                     # Text Check
#                     try:
#                         decoded_str = raw_bytes.decode('utf-8')
#                         if decoded_str.isprintable() and len(decoded_str) > 3:
#                             # Check for nested threats in the decoded string
#                             threats = scan_decoded_content(decoded_str)
                            
#                             annotation = f' /* DECODED BASE64: "{decoded_str}" {threats} */'
#                             final_code = final_code.replace(b64, f'{b64}{annotation}')
#                             pattern_found = True
#                             processed_matches.add(b64)
#                             continue
#                     except: pass

#                     # Binary/XOR Check (if not plain text)
#                     hex_str = "".join([f"\\x{b:02x}" for b in raw_bytes])
#                     xor_result = xor_brute_force(raw_bytes)
#                     if xor_result or len(raw_bytes) > 2:
#                         annotation = f' /* RAW HEX: "{hex_str}"{xor_result} */'
#                         final_code = final_code.replace(b64, f"{b64}{annotation}")
#                         pattern_found = True
#                         processed_matches.add(b64)
#                 except: pass

#             # =========================================================================
#             # 2. HEX STRING DETECTION
#             # =========================================================================
#             # Matches: \x41\x42 or 0x41,0x42
#             hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){3,}|(?:0x[0-9a-fA-F]{2},?){3,}'
#             hex_matches = list(set(re.findall(hex_pattern, final_code)))
#             for hx in hex_matches:
#                 if hx in processed_matches: continue
#                 try:
#                     cleaned = re.sub(r'\\x|0x|,|%|\s', '', hx)
#                     raw_bytes = binascii.unhexlify(cleaned)
#                     xor_result = xor_brute_force(raw_bytes)
#                     decoded_str = raw_bytes.decode('utf-8', errors='ignore')

#                     if is_meaningful_text(decoded_str) or xor_result:
#                         threats = scan_decoded_content(decoded_str)
#                         annotation = f' /* DECODED HEX: "{decoded_str}" {threats} {xor_result} */'
#                         final_code = final_code.replace(hx, f"{hx}{annotation}")
#                         pattern_found = True
#                         processed_matches.add(hx)
#                 except: pass

#             # =========================================================================
#             # 3. JAVASCRIPT CHAR CODES
#             # =========================================================================
#             # Matches: String.fromCharCode(104, 101, 108, 108, 111)
#             char_blocks = list(set(re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', final_code)))
#             for block in char_blocks:
#                 full_match = f"String.fromCharCode({block})"
#                 if full_match in processed_matches: continue
#                 try:
#                     nums = [int(n) for n in block.split(',')]
#                     decoded = "".join(chr(n) for n in nums)
#                     if len(decoded) > 3:
#                         threats = scan_decoded_content(decoded)
#                         final_code = final_code.replace(full_match, f'{full_match} /* CHARCODE: "{decoded}" {threats} */')
#                         pattern_found = True
#                         processed_matches.add(full_match)
#                 except: pass

#             # =========================================================================
#             # 4. REVERSED STRINGS
#             # =========================================================================
#             # Common obfuscation technique: "llehsrewop" -> "powershell"
#             suspicious_reversed = ["llehsrewop", "etucexe", "daolnwod", "tpircs", "ecalper", "tnetnoc_teg", "dne-2v", "atad_tsop"]
#             for word in suspicious_reversed:
#                 if word in final_code.lower():
#                     # Create a case-insensitive regex for the word
#                     pattern = re.compile(re.escape(word), re.IGNORECASE)
#                     # Replace with annotation showing the reversed (readable) version
#                     final_code = pattern.sub(lambda m: f'{m.group(0)} /* REVERSED: "{m.group(0)[::-1]}" */', final_code)
#                     pattern_found = True

#             # =========================================================================
#             # 5. INT ARRAYS (ASCII)
#             # =========================================================================
#             # Matches brackets with numbers inside: [84, 69, 83]
#             array_pattern = r'\[\s*((?:\d+\s*,\s*)+\d+)\s*\]'
#             arrays = list(set(re.findall(array_pattern, final_code)))
#             for arr_content in arrays:
#                 original_match = f"[{arr_content}]"
#                 if original_match in processed_matches: continue
#                 try:
#                     nums = [int(n) for n in arr_content.split(',')]
#                     # Ensure numbers are valid ASCII bytes
#                     if all(0 <= n <= 255 for n in nums):
#                         decoded_str = "".join(chr(n) for n in nums)
#                         if is_meaningful_text(decoded_str):
#                             threats = scan_decoded_content(decoded_str)
#                             annotation = f' /* ASCII ARRAY: "{decoded_str}" {threats} */'
#                             final_code = final_code.replace(original_match, f"{original_match}{annotation}")
#                             pattern_found = True
#                             processed_matches.add(original_match)
#                 except: pass

#             # =========================================================================
#             # 6. ROT13
#             # =========================================================================
#             long_words = re.findall(r'[a-zA-Z]{10,}', final_code)
#             for word in long_words:
#                 if word in processed_matches: continue
#                 try:
#                     decoded = codecs.decode(word, 'rot_13')
#                     # Check if the result looks like a real command/url
#                     if is_meaningful_text(decoded) and not decoded == word:
#                         if any(k in decoded.lower() for k in ["http", "shell", "cmd", "exe", "user", "pass", "system"]):
#                             final_code = final_code.replace(word, f'{word} /* ROT13: "{decoded}" */')
#                             pattern_found = True
#                             processed_matches.add(word)
#                 except: pass

#     except Exception as e:
#         print("❌ CRITICAL BACKEND ERROR (Deobfuscator):")
#         traceback.print_exc()

#     # print(f"DEBUG: Finished. Pattern Found: {pattern_found}")
    
#     return {
#         "results": final_code,
#         "pattern_found": pattern_found
#     }