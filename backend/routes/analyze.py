from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from app.schemas import CodeInput, AnalysisResponse, ChatInput, HashCheck
from typing import List

# Import Analysis Engines
from analyzer.static_analyzer import analyze_code
from analyzer.binary_analyzer import analyze_binary_file
from analyzer.yara_engine import run_yara_analysis  # <--- 🔥 YARA Engine
from analyzer.risk_engine import calculate_risk
from analyzer.ai_explainer import generate_explanation, chat_with_ai
from analyzer.utils import attempt_deobfuscation, check_virustotal
from analyzer.pdf_generator import generate_pdf_report

router = APIRouter()

# ---------------------------------------------------------
# 1️⃣ TEXT-BASED ANALYSIS (Source Code)
# ---------------------------------------------------------
@router.post("/analyze", response_model=AnalysisResponse)
def analyze(input: CodeInput):
    # 1. Static Keyword Analysis
    static_behaviors = analyze_code(input.code)
    yara = run_yara_analysis(input.code)
    # 2. 🔥 Real YARA Analysis
    yara_matches = run_yara_analysis(input.code)
    yara_behaviors = [f"YARA: {m['rule']} ({m['severity']})" for m in yara_matches]
    
    # 3. Combine Results
    all_behaviors = static_behaviors + yara_behaviors
    
    # 4. Calculate Risk Score
    risk = calculate_risk(all_behaviors)

    # 5. Determine Malware Label
    if risk >= 70:
        malware_type = "High-Risk Malware"
    elif risk >= 30:
        malware_type = "Suspicious"
    else:
        malware_type = "Benign"

    # 6. Return Full Report
    return AnalysisResponse(
        malware_type=malware_type,
        risk_score=risk,
        behaviors=all_behaviors,
        explanation=generate_explanation(all_behaviors),
        code=input.code  # Pass code for PDF/Frontend
    )

# ---------------------------------------------------------
# 2️⃣ BINARY ANALYSIS (Upload Files - .exe/.dll)
# ---------------------------------------------------------
@router.post("/analyze/binary", response_model=AnalysisResponse)
async def analyze_binary(file: UploadFile = File(...)):
    try:
        # 1. Read the binary file content
        content = await file.read()
        
        # 2. Extract Strings & Analyze Headers (using binary_analyzer engine)
        extracted_text, binary_behaviors, metadata = analyze_binary_file(content, file.filename)
        
        # 3. Run Static Analysis on the Extracted Strings
        # (Re-uses existing keyword rules on the binary's text)
        static_behaviors = analyze_code(extracted_text)

        # 4. 🔥 Run YARA Analysis on the Extracted Text
        yara_matches = run_yara_analysis(extracted_text)
        yara_behaviors = [f"YARA: {m['rule']} ({m['severity']})" for m in yara_matches]
        
        # 5. Merge All Results
        all_behaviors = binary_behaviors + static_behaviors + yara_behaviors
        risk = calculate_risk(all_behaviors)

        # 6. Labeling
        if risk >= 70: 
            malware_type = "Malicious Binary"
        elif risk >= 30: 
            malware_type = "Suspicious File"
        else: 
            malware_type = "Clean File"

        # 7. Generate AI Explanation
        explanation = generate_explanation(all_behaviors)

        # 8. Create a Readable "Code" Representation for the Report
        report_code_view = (
            f"Filename: {metadata['filename']}\n"
            f"File Hash (SHA256): {metadata['sha256']}\n"
            f"File Type: {metadata['file_type']}\n"
            f"Compilation Time: {metadata['compile_timestamp']}\n\n"
            f"--- EXTRACTED STRINGS (PREVIEW) ---\n"
            f"{extracted_text[:2000]}...\n(Truncated for display)"
        )

        return AnalysisResponse(
            malware_type=malware_type,
            risk_score=risk,
            behaviors=all_behaviors,
            explanation=explanation,
            code=report_code_view
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Binary Analysis Failed: {str(e)}")

# ---------------------------------------------------------
# 🤖 Feature 3: Chat with Malware
# ---------------------------------------------------------
@router.post("/chat")
def chat(input: ChatInput):
    response = chat_with_ai(input.code, input.question)
    return {"reply": response}

# ---------------------------------------------------------
# 🕵️‍♀️ Feature 4: De-obfuscator
# ---------------------------------------------------------
@router.post("/deobfuscate")
def deobfuscate(input: CodeInput):
    results = attempt_deobfuscation(input.code)
    return {"results": results}

# ---------------------------------------------------------
# 🌍 Feature 2: VirusTotal
# ---------------------------------------------------------
@router.post("/virustotal")
async def virustotal(input: HashCheck):
    result = await check_virustotal(input.hash)
    return result

# ---------------------------------------------------------
# 📝 Feature 5: PDF Export
# ---------------------------------------------------------
@router.post("/report/pdf")
def get_pdf_report(data: AnalysisResponse):
    # Convert Pydantic model to dictionary
    report_data = data.dict()
    
    # Generate PDF Buffer
    pdf_buffer = generate_pdf_report(report_data)
    
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=Malware_Report.pdf"}
    )