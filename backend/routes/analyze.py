
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