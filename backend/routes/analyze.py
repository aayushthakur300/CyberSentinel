
# import io
# import logging
# from typing import List, Optional, Dict, Any

# from fastapi import APIRouter, UploadFile, File, HTTPException, Form
# from fastapi.responses import StreamingResponse

# # --- Data Models ---
# from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck

# # --- Analysis Core Engines ---
# from analyzer.static_analyzer import analyze_code
# from analyzer.risk_engine import calculate_risk, calculate_risk_matrix
# from analyzer.ai_explainer import generate_explanation, chat_with_ai
# from analyzer.yara_engine import run_yara_analysis

# # --- Threat Intelligence Brain ---
# try:
#     from analyzer.mitre_mapping import get_mitre_tag
# except ImportError:
#     pass

# # --- Feature Modules ---
# try:
#     from analyzer.binary_analyzer import analyze_binary_file
# except ImportError:
#     pass

# try:
#     from analyzer.deobfuscator import attempt_deobfuscation
# except ImportError:
#     pass

# try:
#     from analyzer.virustotal import check_virustotal
# except ImportError:
#     pass

# try:
#     from analyzer.report_generator import generate_pdf_report
# except ImportError:
#     pass

# # --- Forensic Engines ---
# from analyzer.network_engine import analyze_pcap
# from analyzer.stego_engine import analyze_steganography

# # Setup Logger
# logger = logging.getLogger(__name__)

# # Initialize Router (ONCE ONLY)
# router = APIRouter()

# # =========================================================================
# # 1. SOURCE CODE ANALYSIS (Text/Snippet)
# # =========================================================================
# @router.post("/analyze", response_model=AnalysisResponse)
# async def analyze(input: CodeInput):
#     """
#     Analyzes source code for security vulnerabilities using AST, Regex, and YARA.
#     """
#     if not input.code or not input.code.strip():
#         raise HTTPException(status_code=400, detail="Empty code payload.")

#     try:
#         # 1. Run Static Analysis (Returns MITRE Tags)
#         static_behaviors = analyze_code(input.code)

#         # 2. Run YARA Analysis (Returns Rule Matches)
#         yara_matches = run_yara_analysis(input.code)
#         # Extract the standardized MITRE tag from the YARA engine
#         yara_behaviors = [m.get('behavior_tag', f"YARA: {m['rule']}") for m in yara_matches]

#         all_behaviors = list(set(static_behaviors + yara_behaviors))
        
#         if not all_behaviors:
#             all_behaviors = ["No specific threats detected (Clean Code)"]

#         # 3. Calculate Risk (Uses Professional MITRE Scoring)
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)  # <--- Get Graph Data
        
#         malware_type = "Benign"
#         if risk >= 85: malware_type = "Critical Threat"
#         elif risk >= 50: malware_type = "Suspicious Activity"

#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Send to Frontend
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=input.code,
#             metadata={}
#         )
#     except Exception as e:
#         logger.error(f"Analysis Failed: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 2. BINARY ANALYSIS (.exe, .dll, etc.)
# # =========================================================================
# @router.post("/analyze/binary", response_model=AnalysisResponse)
# async def analyze_binary(file: UploadFile = File(...)):
#     """
#     Analyzes binary files for embedded strings, headers, and known malware signatures.
#     """
#     try:
#         content = await file.read()
        
#         # 1. Run Binary Engine (Returns MITRE Tags for imports, packing, etc.)
#         extracted_text, binary_behaviors, metadata = await analyze_binary_file(content, file.filename)
        
#         # 2. Run Static Analysis on Extracted Strings (Detects hidden scripts)
#         static_behaviors = analyze_code(extracted_text)
        
#         all_behaviors = list(set(binary_behaviors + static_behaviors))
        
#         # 3. Calculate Risk
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors) # <--- Get Graph Data
#         malware_type = "Malicious Binary" if risk >= 75 else "Suspicious File" if risk >= 40 else "Clean File"
        
#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         # 5. Format Output
#         # Truncate strings for the report view to prevent UI lag
#         report_code_view = f"SHA256: {metadata.get('sha256', 'N/A')}\n\n--- STRINGS ---\n{extracted_text[:2000]}..."

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Send to Frontend
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=report_code_view,
#             metadata=metadata
#         )
#     except Exception as e:
#         logger.error(f"Binary Analysis Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 3. STEGANOGRAPHY ANALYSIS (Images)
# # =========================================================================
# @router.post("/analyze/stego")
# async def analyze_stego(file: UploadFile = File(...)):
#     """
#     Analyzes images for LSB steganography, suspicious metadata, and hidden payloads.
#     Returns the actual decoded content if found.
#     """
#     # 1. Validate file type
#     if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
#         raise HTTPException(status_code=400, detail="Invalid file type. Only PNG/JPEG supported for Steganography analysis.")

#     try:
#         # 2. Read content securely
#         content = await file.read()
        
#         # 3. Run Stego Engine
#         results = analyze_steganography(content)
        
#         has_real_data = results.get("has_hidden_data", False)
#         decoded_payload = results.get("decoded_data", "") # Ensure your stego engine returns this key
        
#         # Behaviors contain MITRE tags like [T1027.003]
#         behaviors = results.get("details", [])

#         # 4. Calculate Risk
#         risk = calculate_risk(behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)  # <--- Get Graph Data
#         malware_type = "Clean Image"
#         if has_real_data:
#             malware_type = "Steganography Payload"
#             # Force high risk if hidden data is confirmed
#             if risk < 75: risk = 85
            
#             # Add specific finding to behaviors so AI sees it
#             if decoded_payload:
#                 behaviors.append(f"Decoded Hidden Artifact: '{decoded_payload[:50]}...'")
        
#         if not behaviors: 
#             behaviors.append("No LSB anomalies detected.")

#         # 5. Generate Full Heuristic Report
#         # We pass the behaviors list which now includes the decoded artifact info
#         explanation = generate_explanation(behaviors)

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix=matrix, # <--- Send to Frontend
#             "behaviors": behaviors,
#             "has_hidden_data": has_real_data,
#             "decoded_payload": decoded_payload,  # <-- UI should bind this to "Hidden Data Found"
#             "explanation": explanation,
#             "code": f"Analysis Findings:\n" + "\n".join(behaviors) + f"\n\nExtracted Payload:\n{decoded_payload}",
#             "details": results,
#             "filename": file.filename
#         }
#     except Exception as e:
#         logger.error(f"Stego Error: {e}")
#         raise HTTPException(status_code=500, detail=f"Stego Analysis failed: {str(e)}")


# # =========================================================================
# # 4. NETWORK TRAFFIC ANALYSIS (.pcap)
# # =========================================================================
# @router.post("/analyze/pcap")
# async def analyze_pcap_route(file: UploadFile = File(...)):
#     """
#     Analyzes PCAP files using Deep Packet Inspection (DPI).
#     """
#     # Validate extension
#     if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
#          raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng supported.")

#     try:
#         content = await file.read()
        
#         # Run Network Engine
#         stats = analyze_pcap(content)
        
#         # Merge Ports and Payloads into one MITRE-tagged list for the AI
#         behaviors = []
#         if "suspicious_ports" in stats:
#             behaviors.extend([f"Suspicious Port: {p}" for p in stats["suspicious_ports"]])
#         if "suspicious_payloads" in stats:
#             behaviors.extend([f"Malicious Payload: {p}" for p in stats["suspicious_payloads"]])

#         # Risk Calculation
#         if not behaviors:
#             behaviors = ["Traffic analysis clean. Standard protocols observed."]
#             risk = 0
#             malware_type = "Clean Traffic"
#         else:
#             risk = calculate_risk(behaviors)
#             matrix = calculate_risk_matrix(all_behaviors)  # <--- Get Graph Data
#             malware_type = "Network Attack"

#         # Generate detailed AI report based on specific ports/payloads found
#         explanation = generate_explanation(behaviors)

#         all_behaviors = stats["suspicious_ports"] + stats["suspicious_payloads"]
    
#     # Generate the text report
#         ai_report = generate_explanation(all_behaviors)
    
#     # Add it to the return dictionary
#         stats["ai_explanation"] = ai_report 
    
#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#              "risk_matrix=matrix, # <--- Send to Frontend
#             "behaviors": behaviors,
#             "packet_count": stats.get('packet_count', 0),
#             "explanation": explanation,
#             "metadata": stats
#         }
#     except Exception as e:
#         logger.error(f"PCAP Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 5. UTILITY ROUTES
# # =========================================================================

# @router.post("/deobfuscate")
# async def deobfuscate_route(input: CodeInput):
#     try:
#         # Returns list of dicts with MITRE tags included
#         results = attempt_deobfuscation(input.code)
#         return {"results": results}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/virustotal")
# async def vt_lookup(input: HashCheck):
#     try:
#         return await check_virustotal(input.hash)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/analyze/report/pdf") 
# def get_pdf_report(data: AnalysisResponse):
#     try:
#         pdf_bytes = generate_pdf_report(data.dict())
#         return StreamingResponse(
#             io.BytesIO(pdf_bytes), 
#             media_type="application/pdf",
#             headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
#         )
#     except Exception as e:
#         logger.error(f"PDF Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/chat")
# async def chat(input: ChatInput):
#     try:
#         response = chat_with_ai(input.code, input.question)
#         return {"reply": response}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.get("/threats")
# async def get_recent_threats():
#     # Placeholder for database integration
#     return [
#         {"id": 1, "filename": "invoice_scan.exe", "verdict": "Malicious", "risk_score": 95},
#         {"id": 2, "filename": "update_patch.msi", "verdict": "Suspicious", "risk_score": 60}
#     ]
# import io
# import logging
# from typing import List, Optional, Dict, Any
# import traceback
# from fastapi import APIRouter, UploadFile, File, HTTPException, Form
# from fastapi.responses import StreamingResponse

# # --- Data Models ---
# from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck

# # --- Analysis Core Engines ---
# from analyzer.static_analyzer import analyze_code
# from analyzer.risk_engine import calculate_risk, calculate_risk_matrix
# from analyzer.ai_explainer import generate_explanation, chat_with_ai
# from analyzer.yara_engine import run_yara_analysis

# # --- Threat Intelligence Brain ---
# try:
#     from analyzer.mitre_mapping import get_mitre_tag
# except ImportError:
#     pass

# # --- Feature Modules ---
# try:
#     from analyzer.binary_analyzer import analyze_binary_file
# except ImportError:
#     pass

# try:
#     from analyzer.deobfuscator import attempt_deobfuscation
# except ImportError:
#     pass

# try:
#     from analyzer.virustotal import check_virustotal
# except ImportError:
#     pass

# try:
#     from analyzer.report_generator import generate_pdf_report
# except ImportError:
#     pass

# # --- Forensic Engines ---
# from analyzer.network_engine import analyze_pcap
# from analyzer.stego_engine import analyze_steganography

# # Setup Logger
# logger = logging.getLogger(__name__)

# # Initialize Router (ONCE ONLY)
# router = APIRouter()

# # =========================================================================
# # 1. SOURCE CODE ANALYSIS (Text/Snippet)
# # =========================================================================
# @router.post("/analyze", response_model=AnalysisResponse)
# async def analyze(input: CodeInput):
#     """
#     Analyzes source code for security vulnerabilities using AST, Regex, and YARA.
#     """
#     if not input.code or not input.code.strip():
#         raise HTTPException(status_code=400, detail="Empty code payload.")

#     try:
#         # 1. Run Static Analysis (Returns MITRE Tags)
#         static_behaviors = analyze_code(input.code)

#         # 2. Run YARA Analysis (Returns Rule Matches)
#         yara_matches = run_yara_analysis(input.code)
#         # Extract the standardized MITRE tag from the YARA engine
#         yara_behaviors = [m.get('behavior_tag', f"YARA: {m['rule']}") for m in yara_matches]

#         all_behaviors = list(set(static_behaviors + yara_behaviors))
        
#         if not all_behaviors:
#             all_behaviors = ["No specific threats detected (Clean Code)"]

#         # 3. Calculate Risk (Uses Professional MITRE Scoring)
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)  # <--- Generates 8-Axis Graph Data
        
#         malware_type = "Benign"
#         if risk >= 85: malware_type = "Critical Threat"
#         elif risk >= 50: malware_type = "Suspicious Activity"

#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Sends to Frontend Radar Chart
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=input.code,
#             metadata={}
#         )
#     except Exception as e:
#         logger.error(f"Analysis Failed: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 2. BINARY ANALYSIS (.exe, .dll, etc.)
# # =========================================================================
# @router.post("/analyze/binary", response_model=AnalysisResponse)
# async def analyze_binary(file: UploadFile = File(...)):
#     """
#     Analyzes binary files for embedded strings, headers, and known malware signatures.
#     """
#     try:
#         content = await file.read()
        
#         # 1. Run Binary Engine (Returns MITRE Tags for imports, packing, etc.)
#         extracted_text, binary_behaviors, metadata = await analyze_binary_file(content, file.filename)
        
#         # 2. Run Static Analysis on Extracted Strings (Detects hidden scripts)
#         static_behaviors = analyze_code(extracted_text)
        
#         all_behaviors = list(set(binary_behaviors + static_behaviors))
        
#         # 3. Calculate Risk
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors) # <--- Generates 8-Axis Graph Data
        
#         malware_type = "Malicious Binary" if risk >= 75 else "Suspicious File" if risk >= 40 else "Clean File"
        
#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         # 5. Format Output
#         # Truncate strings for the report view to prevent UI lag
#         report_code_view = f"SHA256: {metadata.get('sha256', 'N/A')}\n\n--- STRINGS ---\n{extracted_text[:2000]}..."

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Sends to Frontend Radar Chart
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=report_code_view,
#             metadata=metadata
#         )
#     except Exception as e:
#         logger.error(f"Binary Analysis Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 3. STEGANOGRAPHY ANALYSIS (Images)
# # =========================================================================
# @router.post("/analyze/stego")
# async def analyze_stego(file: UploadFile = File(...)):
#     """
#     Analyzes images for LSB steganography, suspicious metadata, and hidden payloads.
#     Returns the actual decoded content if found.
#     """
#     # 1. Validate file type
#     if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
#         raise HTTPException(status_code=400, detail="Invalid file type. Only PNG/JPEG supported for Steganography analysis.")

#     try:
#         # 2. Read content securely
#         content = await file.read()
        
#         # 3. Run Stego Engine
#         results = analyze_steganography(content)
        
#         has_real_data = results.get("has_hidden_data", False)
#         decoded_payload = results.get("decoded_data", "") # Ensure your stego engine returns this key
        
#         # Behaviors contain MITRE tags like [T1027.003]
#         behaviors = results.get("details", [])

#         # 4. Calculate Risk
#         # We need to run risk calculation BEFORE appending generic messages
#         if has_real_data and decoded_payload:
#             behaviors.append(f"Decoded Hidden Artifact: '{decoded_payload[:50]}...'")

#         if not behaviors: 
#             behaviors.append("No LSB anomalies detected.")

#         risk = calculate_risk(behaviors)
#         matrix = calculate_risk_matrix(behaviors)  # <--- Generates 8-Axis Graph Data

#         malware_type = "Clean Image"
#         if has_real_data:
#             malware_type = "Steganography Payload"
#             # Force high risk if hidden data is confirmed
#             if risk < 75: risk = 85
            
#         # 5. Generate Full Heuristic Report
#         explanation = generate_explanation(behaviors)

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix, # <--- Sends to Frontend Radar Chart
#             "behaviors": behaviors,
#             "has_hidden_data": has_real_data,
#             "decoded_payload": decoded_payload,  # <-- UI should bind this to "Hidden Data Found"
#             "explanation": explanation,
#             "code": f"Analysis Findings:\n" + "\n".join(behaviors) + f"\n\nExtracted Payload:\n{decoded_payload}",
#             "details": results,
#             "filename": file.filename
#         }
#     except Exception as e:
#         logger.error(f"Stego Error: {e}")
#         raise HTTPException(status_code=500, detail=f"Stego Analysis failed: {str(e)}")


# # =========================================================================
# # 4. NETWORK TRAFFIC ANALYSIS (.pcap)
# # =========================================================================
# @router.post("/analyze/pcap")
# async def analyze_pcap_route(file: UploadFile = File(...)):
#     """
#     Analyzes PCAP files using Deep Packet Inspection (DPI).
#     """
#     # Validate extension
#     if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
#          raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng supported.")

#     try:
#         content = await file.read()
        
#         # Run Network Engine
#         stats = analyze_pcap(content)
        
#         # Merge Ports and Payloads into one MITRE-tagged list for the AI
#         behaviors = []
#         if "suspicious_ports" in stats:
#             behaviors.extend([f"Suspicious Port: {p}" for p in stats["suspicious_ports"]])
#         if "suspicious_payloads" in stats:
#             behaviors.extend([f"Malicious Payload: {p}" for p in stats["suspicious_payloads"]])

#         # Risk Calculation
#         if not behaviors:
#             behaviors = ["Traffic analysis clean. Standard protocols observed."]
#             risk = 0
#             matrix = calculate_risk_matrix([]) # Empty Matrix for clean file
#             malware_type = "Clean Traffic"
#         else:
#             risk = calculate_risk(behaviors)
#             matrix = calculate_risk_matrix(behaviors) # <--- Generates 8-Axis Graph Data
#             malware_type = "Network Attack"

#         # Generate detailed AI report based on specific ports/payloads found
#         explanation = generate_explanation(behaviors)
        
#         # Add explanation to stats dictionary for completeness
#         stats["ai_explanation"] = explanation

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix, # <--- Sends to Frontend Radar Chart
#             "behaviors": behaviors,
#             "packet_count": stats.get('packet_count', 0),
#             "explanation": explanation,
#             "metadata": stats
#         }
#     except Exception as e:
#         logger.error(f"PCAP Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 5. UTILITY ROUTES
# # =========================================================================

# @router.post("/deobfuscate") 
# async def deobfuscate_route(input: CodeInput):
#     try:
#         # data is: {'results': '...', 'pattern_found': True}
#         data = attempt_deobfuscation(input.code)
        
#         # 🔥 CRITICAL FIX 2: NO DOUBLE WRAPPING
#         # Return the dictionary directly so keys are at the top level
#         return data 
        
#     except Exception as e:
#         print(f"Backend Error: {e}") # Log it for yourself
#         raise HTTPException(status_code=500, detail=str(e))
# # =========================================================================
# # 6. VIRUSTOTAL (Hardened & Debug Ready)
# # =========================================================================
# @router.post("/analyze/virustotal")  # 🔥 MATCHES FRONTEND PATH EXACTLY
# async def vt_lookup(input: HashCheck):
#     print(f"DEBUG: Hit /analyze/virustotal with hash: {input.hash}") # Log entry
    
#     try:
#         # 1. Validation (Fail fast if hash is missing or obviously invalid)
#         if not input.hash or len(input.hash) < 32:
#             print("WARN: Invalid hash received.")
#             return {"success": False, "error": "Invalid file hash provided."}

#         # 2. Process Request
#         # We await the async function from your analyzer module
#         result = await check_virustotal(input.hash)
        
#         # 3. Return Result
#         # The check_virustotal function already returns the correct dict structure
#         print(f"DEBUG: VirusTotal Scan Complete. Success: {result.get('success', False)}")
#         return result

#     except Exception as e:
#         # 4. Critical Error Handling
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()  # Prints full stack trace to terminal
#         raise HTTPException(status_code=500, detail=str(e))
    
    
# @router.post("/analyze/report/pdf") 
# def get_pdf_report(data: AnalysisResponse):
#     try:
#         pdf_bytes = generate_pdf_report(data.dict())
#         return StreamingResponse(
#             io.BytesIO(pdf_bytes), 
#             media_type="application/pdf",
#             headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
#         )
#     except Exception as e:
#         logger.error(f"PDF Error: {e}")
#         raise HTTPException(status_code=500, detail=str(e))

# # =========================================================================
# # 8. AI CHAT (Hardened & Debug Ready)
# # =========================================================================
# @router.post("/analyze/chat")  # 🔥 MATCHES FRONTEND PATH EXACTLY
# async def chat(input: ChatInput):
#     print("DEBUG: Hit /analyze/chat endpoint") # Log entry
    
#     try:
#         # 1. Validation (Fail fast if input is empty)
#         if not input.question or not input.question.strip():
#              print("WARN: Empty question received.")
#              return {"reply": "Please enter a valid question."}
             
#         # 2. Process Request
#         print(f"DEBUG: Processing AI Question: {input.question[:30]}...")
#         response = chat_with_ai(input.code, input.question)
        
#         # 3. Return Result (Direct dictionary return)
#         print("DEBUG: AI Response generated successfully.")
#         return {"reply": response}

#     except Exception as e:
#         # 4. Critical Error Handling (Same as Deobfuscator)
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()  # Prints full stack trace to terminal
#         raise HTTPException(status_code=500, detail=str(e))

# @router.get("/threats")
# async def get_recent_threats():
#     # Placeholder for database integration
#     return [
#         {"id": 1, "filename": "invoice_scan.exe", "verdict": "Malicious", "risk_score": 95},
#         {"id": 2, "filename": "update_patch.msi", "verdict": "Suspicious", "risk_score": 60}
#     ]


# import io
# import logging
# import traceback  # <--- 🔥 ADDED: Fixes the crash in exception handlers
# from typing import List, Optional, Dict, Any

# from fastapi import APIRouter, UploadFile, File, HTTPException, Form
# from fastapi.responses import StreamingResponse

# # --- Data Models ---
# from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck

# # --- Analysis Core Engines ---
# from analyzer.static_analyzer import analyze_code
# from analyzer.risk_engine import calculate_risk, calculate_risk_matrix
# from analyzer.ai_explainer import generate_explanation, chat_with_ai

# # [Debugger Note]: Fixed import name based on your file list (yara_engine -> yara_analyzer)
# try:
#     from analyzer.yara_analyzer import run_yara_analysis
# except ImportError:
#     # Graceful fallback if file is named differently
#     try:
#         from analyzer.yara_engine import run_yara_analysis
#     except ImportError:
#         def run_yara_analysis(code): return []

# # --- Threat Intelligence Brain ---
# try:
#     from analyzer.mitre_mapping import get_mitre_tag
# except ImportError:
#     pass

# # --- Feature Modules ---
# try:
#     from analyzer.binary_analyzer import analyze_binary_file
# except ImportError:
#     pass

# try:
#     from analyzer.deobfuscator import attempt_deobfuscation
# except ImportError:
#     pass

# try:
#     from analyzer.virustotal import check_virustotal
# except ImportError:
#     pass

# try:
#     from analyzer.report_generator import generate_pdf_report
# except ImportError:
#     pass

# # --- Forensic Engines ---
# from analyzer.network_engine import analyze_pcap
# from analyzer.stego_engine import analyze_steganography

# # Setup Logger
# logger = logging.getLogger(__name__)

# # Initialize Router (ONCE ONLY)
# router = APIRouter()

# # =========================================================================
# # 1. SOURCE CODE ANALYSIS (Text/Snippet)
# # =========================================================================
# @router.post("/analyze", response_model=AnalysisResponse)
# async def analyze(input: CodeInput):
#     """
#     Analyzes source code for security vulnerabilities using AST, Regex, and YARA.
#     """
#     if not input.code or not input.code.strip():
#         raise HTTPException(status_code=400, detail="Empty code payload.")

#     try:
#         # 1. Run Static Analysis (Returns MITRE Tags)
#         static_behaviors = analyze_code(input.code)

#         # 2. Run YARA Analysis (Returns Rule Matches)
#         yara_matches = run_yara_analysis(input.code)
        
#         # 🔥 CRITICAL FIX: Use .get() to prevent KeyError: 'rule'
#         # We try 'rule', then 'name', then default to 'Unknown Rule'
#         yara_behaviors = []
#         for m in yara_matches:
#             if isinstance(m, dict):
#                 # Safe extraction of the rule name
#                 rule_name = m.get('rule', m.get('name', 'Unknown Rule'))
#                 # Safe extraction of the full tag
#                 tag = m.get('behavior_tag', f"YARA: {rule_name}")
#                 yara_behaviors.append(tag)
#             else:
#                 # Handle case where it might be a simple string
#                 yara_behaviors.append(str(m))

#         all_behaviors = list(set(static_behaviors + yara_behaviors))
        
#         if not all_behaviors:
#             all_behaviors = ["No specific threats detected (Clean Code)"]

#         # 3. Calculate Risk (Uses Professional MITRE Scoring)
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)  # <--- Generates 8-Axis Graph Data
        
#         malware_type = "Benign"
#         if risk >= 85: malware_type = "Critical Threat"
#         elif risk >= 50: malware_type = "Suspicious Activity"

#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Sends to Frontend Radar Chart
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=input.code,
#             metadata={}
#         )
#     except Exception as e:
#         logger.error(f"Analysis Failed: {e}")
#         traceback.print_exc()  # Added traceback
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 2. BINARY ANALYSIS (.exe, .dll, etc.)
# # =========================================================================
# @router.post("/analyze/binary", response_model=AnalysisResponse)
# async def analyze_binary(file: UploadFile = File(...)):
#     """
#     Analyzes binary files for embedded strings, headers, and known malware signatures.
#     """
#     try:
#         content = await file.read()
        
#         # 1. Run Binary Engine (Returns MITRE Tags for imports, packing, etc.)
#         extracted_text, binary_behaviors, metadata = await analyze_binary_file(content, file.filename)
        
#         # 2. Run Static Analysis on Extracted Strings (Detects hidden scripts)
#         static_behaviors = analyze_code(extracted_text)
        
#         all_behaviors = list(set(binary_behaviors + static_behaviors))
        
#         # 3. Calculate Risk
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors) # <--- Generates 8-Axis Graph Data
        
#         malware_type = "Malicious Binary" if risk >= 75 else "Suspicious File" if risk >= 40 else "Clean File"
        
#         # 4. Generate AI Report
#         explanation = generate_explanation(all_behaviors)

#         # 5. Format Output
#         # Truncate strings for the report view to prevent UI lag
#         report_code_view = f"SHA256: {metadata.get('sha256', 'N/A')}\n\n--- STRINGS ---\n{extracted_text[:2000]}..."

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix, # <--- Sends to Frontend Radar Chart
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=report_code_view,
#             metadata=metadata
#         )
#     except Exception as e:
#         logger.error(f"Binary Analysis Error: {e}")
#         traceback.print_exc() # Added traceback
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 3. STEGANOGRAPHY ANALYSIS (Images)
# # =========================================================================
# @router.post("/analyze/stego")
# async def analyze_stego(file: UploadFile = File(...)):
#     """
#     Analyzes images for LSB steganography, suspicious metadata, and hidden payloads.
#     Returns the actual decoded content if found.
#     """
#     # 1. Validate file type
#     if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
#         raise HTTPException(status_code=400, detail="Invalid file type. Only PNG/JPEG supported for Steganography analysis.")

#     try:
#         # 2. Read content securely
#         content = await file.read()
        
#         # 3. Run Stego Engine
#         results = analyze_steganography(content)
        
#         has_real_data = results.get("has_hidden_data", False)
#         decoded_payload = results.get("decoded_data", "") # Ensure your stego engine returns this key
        
#         # Behaviors contain MITRE tags like [T1027.003]
#         behaviors = results.get("details", [])

#         # 4. Calculate Risk
#         # We need to run risk calculation BEFORE appending generic messages
#         if has_real_data and decoded_payload:
#             behaviors.append(f"Decoded Hidden Artifact: '{decoded_payload[:50]}...'")

#         if not behaviors: 
#             behaviors.append("No LSB anomalies detected.")

#         risk = calculate_risk(behaviors)
#         matrix = calculate_risk_matrix(behaviors)  # <--- Generates 8-Axis Graph Data

#         malware_type = "Clean Image"
#         if has_real_data:
#             malware_type = "Steganography Payload"
#             # Force high risk if hidden data is confirmed
#             if risk < 75: risk = 85
            
#         # 5. Generate Full Heuristic Report
#         explanation = generate_explanation(behaviors)

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix, # <--- Sends to Frontend Radar Chart
#             "behaviors": behaviors,
#             "has_hidden_data": has_real_data,
#             "decoded_payload": decoded_payload,  # <-- UI should bind this to "Hidden Data Found"
#             "explanation": explanation,
#             "code": f"Analysis Findings:\n" + "\n".join(behaviors) + f"\n\nExtracted Payload:\n{decoded_payload}",
#             "details": results,
#             "filename": file.filename
#         }
#     except Exception as e:
#         logger.error(f"Stego Error: {e}")
#         traceback.print_exc() # Added traceback
#         raise HTTPException(status_code=500, detail=f"Stego Analysis failed: {str(e)}")


# # =========================================================================
# # 4. NETWORK TRAFFIC ANALYSIS (.pcap)
# # =========================================================================
# @router.post("/analyze/pcap")
# async def analyze_pcap_route(file: UploadFile = File(...)):
#     """
#     Analyzes PCAP files using Deep Packet Inspection (DPI).
#     """
#     # Validate extension
#     if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
#          raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng supported.")

#     try:
#         content = await file.read()
        
#         # Run Network Engine
#         stats = analyze_pcap(content)
        
#         # Merge Ports and Payloads into one MITRE-tagged list for the AI
#         behaviors = []
#         if "suspicious_ports" in stats:
#             behaviors.extend([f"Suspicious Port: {p}" for p in stats["suspicious_ports"]])
#         if "suspicious_payloads" in stats:
#             behaviors.extend([f"Malicious Payload: {p}" for p in stats["suspicious_payloads"]])

#         # Risk Calculation
#         if not behaviors:
#             behaviors = ["Traffic analysis clean. Standard protocols observed."]
#             risk = 0
#             matrix = calculate_risk_matrix([]) # Empty Matrix for clean file
#             malware_type = "Clean Traffic"
#         else:
#             risk = calculate_risk(behaviors)
#             matrix = calculate_risk_matrix(behaviors) # <--- Generates 8-Axis Graph Data
#             malware_type = "Network Attack"

#         # Generate detailed AI report based on specific ports/payloads found
#         explanation = generate_explanation(behaviors)
        
#         # Add explanation to stats dictionary for completeness
#         stats["ai_explanation"] = explanation

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix, # <--- Sends to Frontend Radar Chart
#             "behaviors": behaviors,
#             "packet_count": stats.get('packet_count', 0),
#             "explanation": explanation,
#             "metadata": stats
#         }
#     except Exception as e:
#         logger.error(f"PCAP Error: {e}")
#         traceback.print_exc() # Added traceback
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 5. UTILITY ROUTES
# # =========================================================================

# @router.post("/deobfuscate") 
# async def deobfuscate_route(input: CodeInput):
#     try:
#         # data is: {'results': '...', 'pattern_found': True}
#         data = attempt_deobfuscation(input.code)
        
#         # Return the dictionary directly so keys are at the top level
#         return data 
        
#     except Exception as e:
#         print(f"Backend Error: {e}") 
#         traceback.print_exc() # Added traceback
#         raise HTTPException(status_code=500, detail=str(e))

# # =========================================================================
# # 6. VIRUSTOTAL (Hardened & Debug Ready)
# # =========================================================================
# @router.post("/analyze/virustotal")  # 🔥 MATCHES FRONTEND PATH EXACTLY
# async def vt_lookup(input: HashCheck):
#     print(f"DEBUG: Hit /analyze/virustotal with hash: {input.hash}") # Log entry
    
#     try:
#         # 1. Validation (Fail fast if hash is missing or obviously invalid)
#         if not input.hash or len(input.hash) < 32:
#             print("WARN: Invalid hash received.")
#             return {"success": False, "error": "Invalid file hash provided."}

#         # 2. Process Request
#         # We await the async function from your analyzer module
#         result = await check_virustotal(input.hash)
        
#         # 3. Return Result
#         # The check_virustotal function already returns the correct dict structure
#         print(f"DEBUG: VirusTotal Scan Complete. Success: {result.get('success', False)}")
#         return result

#     except Exception as e:
#         # 4. Critical Error Handling
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()  # Prints full stack trace to terminal
#         raise HTTPException(status_code=500, detail=str(e))
    
    
# @router.post("/analyze/report/pdf") 
# def get_pdf_report(data: AnalysisResponse):
#     try:
#         pdf_bytes = generate_pdf_report(data.dict())
#         return StreamingResponse(
#             io.BytesIO(pdf_bytes), 
#             media_type="application/pdf",
#             headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
#         )
#     except Exception as e:
#         logger.error(f"PDF Error: {e}")
#         traceback.print_exc() # Added traceback
#         raise HTTPException(status_code=500, detail=str(e))

# # =========================================================================
# # 8. AI CHAT (Hardened & Debug Ready)
# # =========================================================================
# @router.post("/analyze/chat")  # 🔥 MATCHES FRONTEND PATH EXACTLY
# async def chat(input: ChatInput):
#     print("DEBUG: Hit /analyze/chat endpoint") # Log entry
    
#     try:
#         # 1. Validation (Fail fast if input is empty)
#         if not input.question or not input.question.strip():
#              print("WARN: Empty question received.")
#              return {"reply": "Please enter a valid question."}
             
#         # 2. Process Request
#         print(f"DEBUG: Processing AI Question: {input.question[:30]}...")
#         response = chat_with_ai(input.code, input.question)
        
#         # 3. Return Result (Direct dictionary return)
#         print("DEBUG: AI Response generated successfully.")
#         return {"reply": response}

#     except Exception as e:
#         # 4. Critical Error Handling (Same as Deobfuscator)
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()  # Prints full stack trace to terminal
#         raise HTTPException(status_code=500, detail=str(e))

# @router.get("/threats")
# async def get_recent_threats():
#     # Placeholder for database integration
#     return [
#         {"id": 1, "filename": "invoice_scan.exe", "verdict": "Malicious", "risk_score": 95},
#         {"id": 2, "filename": "update_patch.msi", "verdict": "Suspicious", "risk_score": 60}
#     ]
# import io
# import logging
# import traceback
# import hashlib  # 🔥 Required for VirusTotal Hashes
# from typing import List, Optional, Dict, Any

# from fastapi import APIRouter, UploadFile, File, HTTPException, Form
# from fastapi.responses import StreamingResponse

# # --- Data Models ---
# from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck

# # --- Analysis Core Engines ---
# from analyzer.static_analyzer import analyze_code
# from analyzer.risk_engine import calculate_risk, calculate_risk_matrix
# from analyzer.ai_explainer import generate_explanation, chat_with_ai
# from analyzer.yara_engine import run_yara_analysis

# # --- Threat Intelligence Brain ---
# try:
#     from analyzer.mitre_mapping import get_mitre_tag
# except ImportError:
#     pass

# # --- Feature Modules ---
# try:
#     from analyzer.binary_analyzer import analyze_binary_file
# except ImportError:
#     pass

# try:
#     from analyzer.deobfuscator import attempt_deobfuscation
# except ImportError:
#     pass

# try:
#     from analyzer.virustotal import check_virustotal
# except ImportError:
#     pass

# try:
#     from analyzer.report_generator import generate_pdf_report
# except ImportError:
#     pass

# # --- Forensic Engines ---
# from analyzer.network_engine import analyze_pcap
# from analyzer.stego_engine import analyze_steganography

# # Setup Logger
# logger = logging.getLogger(__name__)

# # Initialize Router
# router = APIRouter()

# # =========================================================================
# # 1. SOURCE CODE ANALYSIS
# # =========================================================================
# @router.post("/analyze", response_model=AnalysisResponse)
# async def analyze(input: CodeInput):
#     """
#     Analyzes source code for security vulnerabilities.
#     """
#     if not input.code or not input.code.strip():
#         raise HTTPException(status_code=400, detail="Empty code payload.")

#     try:
#         # 1. Analysis
#         static_behaviors = analyze_code(input.code)
#         yara_matches = run_yara_analysis(input.code)
#         yara_behaviors = [m.get('behavior_tag', f"YARA: {m['rule']}") for m in yara_matches]
#         all_behaviors = list(set(static_behaviors + yara_behaviors))
        
#         if not all_behaviors:
#             all_behaviors = ["No specific threats detected (Clean Code)"]

#         # 2. Risk & AI
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)
        
#         malware_type = "Benign"
#         if risk >= 85: malware_type = "Critical Threat"
#         elif risk >= 50: malware_type = "Suspicious Activity"

#         explanation = generate_explanation(all_behaviors)

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix,
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=input.code,
#             metadata={}
#         )
#     except Exception as e:
#         logger.error(f"Analysis Failed: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 2. BINARY ANALYSIS (FIXED FOR VIRUSTOTAL)
# # =========================================================================
# @router.post("/analyze/binary", response_model=AnalysisResponse)
# async def analyze_binary(file: UploadFile = File(...)):
#     """
#     Analyzes binary files and calculates Hash for VirusTotal.
#     """
#     try:
#         content = await file.read()
        
#         # 🔥 STEP 1: Calculate Hashes Immediately
#         sha256_hash = hashlib.sha256(content).hexdigest()
#         md5_hash = hashlib.md5(content).hexdigest()
        
#         # 2. Run Engines
#         # We ignore the engine's internal metadata for the hash to use our fresh one
#         extracted_text, binary_behaviors, _ = await analyze_binary_file(content, file.filename)
#         static_behaviors = analyze_code(extracted_text)
        
#         all_behaviors = list(set(binary_behaviors + static_behaviors))
        
#         # 3. Risk & AI
#         risk = calculate_risk(all_behaviors)
#         matrix = calculate_risk_matrix(all_behaviors)
        
#         malware_type = "Malicious Binary" if risk >= 75 else "Suspicious File"
        
#         explanation = generate_explanation(all_behaviors)

#         # 4. Format Output
#         # Use the variable 'sha256_hash' here directly
#         report_code_view = f"SHA256: {sha256_hash}\nMD5: {md5_hash}\n\n--- STRINGS ---\n{extracted_text[:2000]}..."

#         return AnalysisResponse(
#             malware_type=malware_type,
#             risk_score=risk,
#             risk_matrix=matrix,
#             behaviors=all_behaviors,
#             explanation=explanation,
#             code=report_code_view,
            
#             # 🔥 CRITICAL FIX: Pass metadata as a Keyword Argument
#             metadata={
#                 "sha256": sha256_hash,
#                 "md5": md5_hash
#             }
#         )
#     except Exception as e:
#         logger.error(f"Binary Analysis Error: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 3. STEGANOGRAPHY ANALYSIS (FIXED FOR VIRUSTOTAL)
# # =========================================================================
# @router.post("/analyze/stego")
# async def analyze_stego(file: UploadFile = File(...)):
#     if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
#         raise HTTPException(status_code=400, detail="Invalid file type. Only PNG/JPEG supported.")

#     try:
#         content = await file.read()
        
#         # 🔥 Calculate Hash
#         sha256_hash = hashlib.sha256(content).hexdigest()
#         md5_hash = hashlib.md5(content).hexdigest()

#         # Run Engine
#         results = analyze_steganography(content)
        
#         has_real_data = results.get("has_hidden_data", False)
#         decoded_payload = results.get("decoded_data", "")
#         behaviors = results.get("details", [])

#         if has_real_data and decoded_payload:
#             behaviors.append(f"Decoded Hidden Artifact: '{decoded_payload[:50]}...'")

#         if not behaviors: 
#             behaviors.append("No LSB anomalies detected.")

#         risk = calculate_risk(behaviors)
#         matrix = calculate_risk_matrix(behaviors)

#         malware_type = "Clean Image"
#         if has_real_data:
#             malware_type = "Steganography Payload"
#             if risk < 75: risk = 85
            
#         explanation = generate_explanation(behaviors)

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix,
#             "behaviors": behaviors,
#             "has_hidden_data": has_real_data,
#             "decoded_payload": decoded_payload,
#             "explanation": explanation,
#             "code": f"Analysis Findings:\n" + "\n".join(behaviors) + f"\n\nExtracted Payload:\n{decoded_payload}",
#             "details": results,
#             "filename": file.filename,
            
#             # 🔥 Pass Hash Metadata
#             "metadata": {
#                 "sha256": sha256_hash,
#                 "md5": md5_hash
#             }
#         }
#     except Exception as e:
#         logger.error(f"Stego Error: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=f"Stego Analysis failed: {str(e)}")


# # =========================================================================
# # 4. NETWORK TRAFFIC ANALYSIS
# # =========================================================================
# @router.post("/analyze/pcap")
# async def analyze_pcap_route(file: UploadFile = File(...)):
#     if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
#          raise HTTPException(status_code=400, detail="Invalid file type. Only .pcap or .pcapng supported.")

#     try:
#         content = await file.read()
#         stats = analyze_pcap(content)
        
#         behaviors = []
#         if "suspicious_ports" in stats:
#             behaviors.extend([f"Suspicious Port: {p}" for p in stats["suspicious_ports"]])
#         if "suspicious_payloads" in stats:
#             behaviors.extend([f"Malicious Payload: {p}" for p in stats["suspicious_payloads"]])

#         if not behaviors:
#             behaviors = ["Traffic analysis clean."]
#             risk = 0
#             matrix = calculate_risk_matrix([])
#             malware_type = "Clean Traffic"
#         else:
#             risk = calculate_risk(behaviors)
#             matrix = calculate_risk_matrix(behaviors)
#             malware_type = "Network Attack"

#         explanation = generate_explanation(behaviors)
#         stats["ai_explanation"] = explanation

#         return {
#             "malware_type": malware_type,
#             "risk_score": risk,
#             "risk_matrix": matrix,
#             "behaviors": behaviors,
#             "packet_count": stats.get('packet_count', 0),
#             "explanation": explanation,
#             "metadata": stats
#         }
#     except Exception as e:
#         logger.error(f"PCAP Error: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 5. DEOBFUSCATOR (HARDCODED PATH)
# # =========================================================================
# @router.post("/analyze/deobfuscate") 
# async def deobfuscate_route(input: CodeInput):
#     print("DEBUG: Hit /analyze/deobfuscate endpoint")
#     try:
#         # Return dict directly, NO double wrapping
#         data = attempt_deobfuscation(input.code)
#         return data 
#     except Exception as e:
#         print(f"Backend Error: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 6. VIRUSTOTAL (HARDCODED PATH)
# # =========================================================================
# @router.post("/analyze/virustotal")
# async def vt_lookup(input: HashCheck):
#     print(f"DEBUG: Hit /analyze/virustotal with hash: {input.hash}")
#     try:
#         if not input.hash or len(input.hash) < 32:
#             return {"success": False, "error": "Invalid file hash provided."}

#         # Await the robust engine
#         result = await check_virustotal(input.hash)
#         print(f"DEBUG: VirusTotal Success: {result.get('success', False)}")
#         return result

#     except Exception as e:
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 7. AI CHAT (HARDCODED PATH)
# # =========================================================================
# @router.post("/analyze/chat")
# async def chat(input: ChatInput):
#     print("DEBUG: Hit /analyze/chat endpoint")
#     try:
#         if not input.question or not input.question.strip():
#              return {"reply": "Please enter a valid question."}
             
#         response = chat_with_ai(input.code, input.question)
#         return {"reply": response}

#     except Exception as e:
#         print(f"❌ CRITICAL BACKEND ERROR: {e}") 
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 8. THREAT FEED
# # =========================================================================
# @router.get("/analyze/threats")
# async def get_recent_threats():
#     try:
#         # Fallback/Mock data if DB is missing
#         return [
#             {"id": 1, "filename": "invoice_scan.exe", "verdict": "Malicious", "risk_score": 95},
#             {"id": 2, "filename": "update_patch.msi", "verdict": "Suspicious", "risk_score": 60}
#         ]
#     except Exception as e:
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # =========================================================================
# # 9. PDF REPORT
# # =========================================================================
# @router.post("/analyze/report/pdf") 
# def get_pdf_report(data: AnalysisResponse):
#     try:
#         pdf_bytes = generate_pdf_report(data.dict())
#         return StreamingResponse(
#             io.BytesIO(pdf_bytes), 
#             media_type="application/pdf",
#             headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
#         )
#     except Exception as e:
#         logger.error(f"PDF Error: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))
import io
import logging
import traceback
import hashlib
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from fastapi.responses import StreamingResponse

# --- Data Models ---
from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck

# --- Analysis Core Engines ---
from analyzer.static_analyzer import analyze_code
from analyzer.risk_engine import calculate_risk, calculate_risk_matrix
from analyzer.ai_explainer import generate_explanation, chat_with_ai

# --- MITRE ENGINE (Dictionary Version Fix) ---
try:
    from analyzer.mitre_mapping import MITRE_SIGNATURES
except ImportError:
    MITRE_SIGNATURES = {}

# --- YARA ENGINE (Renamed to yara_engine.py) ---
try:
    from analyzer.yara_engine import run_yara_analysis
except ImportError:
    print("⚠️ WARNING: 'yara_engine.py' not found. Skipping YARA.")
    def run_yara_analysis(c): return []

# --- Feature Modules ---
try:
    from analyzer.binary_analyzer import analyze_binary_file
except ImportError:
    analyze_binary_file = None

try:
    from analyzer.deobfuscator import attempt_deobfuscation
except ImportError:
    attempt_deobfuscation = None

try:
    from analyzer.virustotal import check_virustotal
except ImportError:
    check_virustotal = None

try:
    from analyzer.report_generator import generate_pdf_report
except ImportError:
    generate_pdf_report = None

# --- Forensic Engines ---
from analyzer.network_engine import analyze_pcap
from analyzer.stego_engine import analyze_steganography

# Setup Logger
logger = logging.getLogger(__name__)

router = APIRouter()

# =========================================================================
# HELPER: MITRE SCANNER (Replaces the Class)
# =========================================================================
def scan_text_with_mitre(text_content: str) -> List[str]:
    """Scans text against the MITRE_SIGNATURES dictionary."""
    findings = []
    if not text_content: return findings
    
    text_lower = text_content.lower()
    for signature, meta in MITRE_SIGNATURES.items():
        if signature.lower() in text_lower:
            tag = f"[{meta.get('id', 'T0000')}] {meta.get('name', 'Detected Pattern')}"
            findings.append(tag)
    return findings

# =========================================================================
# 1. SOURCE CODE ANALYSIS
# =========================================================================
@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(input: CodeInput):
    if not input.code or not input.code.strip():
        raise HTTPException(status_code=400, detail="Empty code payload.")

    try:
        # 1. Static Analysis
        static_behaviors = analyze_code(input.code)
        
        # 2. MITRE Regex
        mitre_behaviors = scan_text_with_mitre(input.code)

        # 3. YARA
        yara_matches = run_yara_analysis(input.code)
        yara_behaviors = []
        for m in yara_matches:
            if isinstance(m, dict):
                # Handle dictionary response from YARA engine
                rule = m.get('rule', m.get('name', 'Unknown'))
                tag = f"YARA: {rule}"
                yara_behaviors.append(tag)
            else:
                yara_behaviors.append(str(m))

        # Combine & Deduplicate 4. Aggregation
        all_behaviors = list(set(static_behaviors + mitre_behaviors + yara_behaviors))
        if not all_behaviors: all_behaviors = ["No specific threats detected (Clean Code)"]

        # Risk & AI 
        risk = calculate_risk(all_behaviors)
        matrix = calculate_risk_matrix(all_behaviors)  # ✅ 8-Axis Matrix
        
        malware_type = "Benign"
        if risk >= 85: malware_type = "Critical Threat"
        elif risk >= 50: malware_type = "Suspicious Activity"

        explanation = generate_explanation(all_behaviors, context_text=input.code[:3000])

        return AnalysisResponse(
            malware_type=malware_type,
            risk_score=risk,
            risk_matrix=matrix,
            behaviors=all_behaviors,
            explanation=explanation,
            code=input.code,
            metadata={}
        )
    except Exception as e:
        logger.error(f"Analysis Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# 2. BINARY ANALYSIS (Guaranteed Hash)
# =========================================================================
@router.post("/analyze/binary", response_model=AnalysisResponse)
async def analyze_binary(file: UploadFile = File(...)):
    try:
        content = await file.read()
        
        # 🔥 FORCE HASH CALCULATION
        sha256_hash = hashlib.sha256(content).hexdigest()
        md5_hash = hashlib.md5(content).hexdigest()
        
        final_metadata = {
            "sha256": sha256_hash,
            "md5": md5_hash,
            "filename": file.filename
        }

        # 1. Run Binary Engine
        extracted_text = ""
        binary_behaviors = []
        
        if analyze_binary_file:
            extracted_text, binary_behaviors, _ = await analyze_binary_file(content, file.filename)
        else:
            try: extracted_text = content.decode('latin-1')
            except: extracted_text = content.decode('utf-8', errors='ignore')

        # 2. String Analysis (MITRE + Static)
        mitre_behaviors = scan_text_with_mitre(extracted_text)
        static_behaviors = analyze_code(extracted_text)
        # 3. Risk & Output
        all_behaviors = list(set(binary_behaviors + mitre_behaviors + static_behaviors))
        if not all_behaviors: all_behaviors = ["No specific binary threats detected."]

        # 4. Risk Calculation
        risk = calculate_risk(all_behaviors)
        matrix = calculate_risk_matrix(all_behaviors) # ✅ Fixed: Passing list of strings
        
        malware_type = "Malicious Binary" if risk >= 75 else "Suspicious File" if risk >= 40 else "Clean File"
        
        explanation = generate_explanation(all_behaviors, context_text=extracted_text[:4000])
        report_code_view = f"SHA256: {sha256_hash}\nMD5: {md5_hash}\n\n--- EXTRACTED STRINGS ---\n{extracted_text[:2000]}..."

        return AnalysisResponse(
            malware_type=malware_type,
            risk_score=risk,
            risk_matrix=matrix,
            behaviors=all_behaviors,
            explanation=explanation,
            code=report_code_view,
            metadata=final_metadata # ✅ Hash is Guaranteed here
        )
    except Exception as e:
        logger.error(f"Binary Analysis Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# 3. STEGANOGRAPHY ANALYSIS (Guaranteed Hash)
# =========================================================================
@router.post("/analyze/stego")
async def analyze_stego(file: UploadFile = File(...)):
    if file.content_type not in ["image/png", "image/jpeg", "image/jpg"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only PNG/JPEG supported.")

    try:
        content = await file.read()
        
        # 🔥 FORCE HASH CALCULATION
        sha256_hash = hashlib.sha256(content).hexdigest()
        md5_hash = hashlib.md5(content).hexdigest()

        # Run Engine
        results = analyze_steganography(content)
        
        has_real_data = results.get("has_hidden_data", False)
        decoded_payload = results.get("hidden_message", "") or results.get("decoded_data", "")
        behaviors = results.get("details", [])

        if has_real_data and decoded_payload:
            behaviors.append(f"Decoded Hidden Artifact: '{decoded_payload[:50]}...'")
            # Scan hidden message for threats
            behaviors.extend(scan_text_with_mitre(decoded_payload))
            
        if not behaviors: behaviors.append("No LSB anomalies detected.")

        risk = calculate_risk(behaviors)
        matrix = calculate_risk_matrix(behaviors)

        malware_type = "Clean Image"
        if has_real_data:
            malware_type = "Steganography Payload"
            if risk < 75: risk = 85
            
        context_ai = f"Hidden Message: {decoded_payload}" if has_real_data else "No hidden data."
        explanation = generate_explanation(behaviors, context_text=context_ai)

        return {
            "malware_type": malware_type,
            "risk_score": risk,
            "risk_matrix": matrix,
            "behaviors": behaviors,
            "has_hidden_data": has_real_data,
            "decoded_payload": decoded_payload,
            "explanation": explanation,
            "code": f"Analysis Findings:\n" + "\n".join(behaviors) + f"\n\nExtracted Payload:\n{decoded_payload}",
            "details": results,
            "filename": file.filename,
            "metadata": { 
                "sha256": sha256_hash,
                "md5": md5_hash,
                "filename": file.filename
            }
        }
    except Exception as e:
        logger.error(f"Stego Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Stego Analysis failed: {str(e)}")


# =========================================================================
# 4. NETWORK ANALYSIS
# =========================================================================
@router.post("/analyze/pcap")
async def analyze_pcap_route(file: UploadFile = File(...)):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
         raise HTTPException(status_code=400, detail="Invalid file type.")

    try:
        content = await file.read()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        stats = analyze_pcap(content)
        
        behaviors = []
        if "suspicious_ports" in stats:
            behaviors.extend([f"Suspicious Port: {p}" for p in stats["suspicious_ports"]])
        if "suspicious_payloads" in stats:
            behaviors.extend([f"Malicious Payload: {p}" for p in stats["suspicious_payloads"]])

        risk = calculate_risk(behaviors) if behaviors else 0
        matrix = calculate_risk_matrix(behaviors)
        malware_type = "Network Attack" if risk > 0 else "Clean Traffic"

        explanation = generate_explanation(behaviors)
        stats["ai_explanation"] = explanation

        return {
            "malware_type": malware_type,
            "risk_score": risk,
            "risk_matrix": matrix,
            "behaviors": behaviors,
            "packet_count": stats.get('packet_count', 0),
            "explanation": explanation,
            "metadata": {
                "sha256": sha256_hash,
                "packet_count": stats.get('packet_count', 0)
            }
        }
    except Exception as e:
        logger.error(f"PCAP Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# =========================================================================
# 5. UTILITY ROUTES
# =========================================================================
@router.post("/deobfuscate") 
async def deobfuscate_route(input: CodeInput):
    try:
        if attempt_deobfuscation:
            data = attempt_deobfuscation(input.code)
            return data
        return {"error": "Deobfuscator not loaded"}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/virustotal")
async def vt_lookup(input: HashCheck):
    print(f"DEBUG: Hit /analyze/virustotal with hash: {input.hash}")
    try:
        if not input.hash or len(input.hash) < 32:
            return {"success": False, "error": "Invalid file hash provided."}

        # Await the robust engine
        result = await check_virustotal(input.hash)
        print(f"DEBUG: VirusTotal Success: {result.get('success', False)}")
        return result

    except Exception as e:
        print(f"❌ CRITICAL BACKEND ERROR: {e}") 
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("/analyze/report/pdf") 
def get_pdf_report(data: AnalysisResponse):
    try:
        pdf_bytes = generate_pdf_report(data.dict())
        return StreamingResponse(
            io.BytesIO(pdf_bytes), 
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
        )
    except Exception as e:
        logger.error(f"PDF Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/chat")
async def chat(input: ChatInput):
    print("DEBUG: Hit /analyze/chat endpoint")
    try:
        if not input.question or not input.question.strip():
             return {"reply": "Please enter a valid question."}
             
        response = chat_with_ai(input.code, input.question)
        return {"reply": response}

    except Exception as e:
        print(f"❌ CRITICAL BACKEND ERROR: {e}") 
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analyze/threats")
async def get_recent_threats():
    try:
        # Fallback/Mock data if DB is missing
        return [
            {"id": 1, "filename": "invoice_scan.exe", "verdict": "Malicious", "risk_score": 95},
            {"id": 2, "filename": "update_patch.msi", "verdict": "Suspicious", "risk_score": 60}
        ]
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))