import os
from google import genai
from google.genai import types
from typing import List

# =====================================================
# ENVIRONMENT CONFIGURATION
# =====================================================
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("WARNING: GEMINI_API_KEY not found in environment variables. AI features will fail.")

# =====================================================
# MODEL LIST (PRIORITY ORDER – UNCHANGED)
# =====================================================
ALL_MODELS = [
    # --- TIER 1: LATEST STABLE & FAST (2.5 & 2.0) ---
    'gemini-2.5-flash',
    'gemini-2.5-flash-lite',
    'gemini-2.0-flash',
    'gemini-2.0-flash-001',
    'gemini-2.0-flash-lite',
    'gemini-2.0-flash-lite-001',
    
    # --- TIER 2: HIGH INTELLIGENCE (PRO) ---
    'gemini-2.5-pro',
    'gemini-pro-latest',
    
    # --- TIER 3: PREVIEWS & EXPERIMENTAL ---
    'gemini-2.5-flash-preview-09-2025',
    'gemini-2.5-flash-lite-preview-09-2025',
    'gemini-2.0-flash-lite-preview-02-05',
    'gemini-2.0-flash-lite-preview',
    'gemini-2.0-flash-exp',
    'gemini-exp-1206',
    
    # --- TIER 4: NEXT GEN PREVIEWS (3.0) ---
    'gemini-3-pro-preview',
    'gemini-3-flash-preview',
    'deep-research-pro-preview-12-2025',

    # --- TIER 5: LEGACY / ALIASES ---
    'gemini-flash-latest',
    'gemini-flash-lite-latest',
    'gemini-1.5-flash-latest',
    'gemini-1.5-flash-lite-latest',
    
    # --- TIER 6: GEMMA (OPEN MODELS FALLBACK) ---
    'gemma-3-27b-it',
    'gemma-3-12b-it',
    'gemma-3-4b-it',
    'gemma-3-1b-it',
    'gemma-3n-e4b-it',
    'gemma-3n-e2b-it',
    
    # --- TIER 7: SPECIALIZED ---
    'gemini-robotics-er-1.5-preview',
    'gemini-2.5-computer-use-preview-10-2025',
    'nano-banana-pro-preview'
]

# =====================================================
# SYSTEM INSTRUCTION (SOC ROLE)
# =====================================================
SYSTEM_INSTRUCTION = """
You are a Tier-3 Senior Security Operations Center (SOC) Analyst working for a top cybersecurity firm.
Your job is to analyze technical indicators of compromise (IOCs) and behavioral patterns identified by automated scanning tools.

You must produce a professional, structured threat intelligence report for a technical audience.
"""

# =====================================================
# USER PROMPT TEMPLATE (WITH CONTEXT PREVIEW)
# =====================================================
USER_PROMPT_TEMPLATE = """
Automated static analysis has provided the following data for an artifact.

**1. Detected Behaviors (Rule-Based):**
{behaviors_list}

**2. Extracted Artifacts / Source Context:**
(Analyze these strings/code for hidden payloads, URLs, or command execution)
```text
{context_preview}
```

Task: Generate a Threat Analysis Report covering:

1. Executive Summary: A 2-sentence high-level overview.

2. Language & Attack Vector: Identify language/technique.

3. Technical Breakdown: Analyze behaviors and strings combined.

4. Potential Impact: Consequences of execution.

5. Recommended Immediate Actions: 3 distinct steps.

Do NOT provide code corrections. Focus solely on threat analysis.
"""


# 🔥 SAFETY SETTINGS TO PREVENT TRUNCATION/BLOCKING
# This allows the model to discuss malware/threats for research purposes
SAFETY_SETTINGS = [
    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
]
# =====================================================
# THREAT REPORT GENERATOR
# =====================================================
def generate_explanation(
    behaviors: List[str],
    yara_hits: List[str] = [],
    context_text: str = ""
) -> str:
    """Sends behaviors AND extracted context (strings) to Google Gemini."""

    if not api_key:
        return "AI Analysis unavailable: API key missing."

    # Do NOT quit if behaviors are empty – context may exist
    if not behaviors and not yara_hits and not context_text:
        return "AI Analysis unavailable: No data to analyze."

    client = genai.Client(api_key=api_key)

    # Combine indicators
    combined_indicators = behaviors + [f"YARA Match: {hit}" for hit in yara_hits]

    if not combined_indicators:
        behaviors_text = "No specific rule-based patterns detected."
    else:
        behaviors_text = "\n- " + "\n- ".join(combined_indicators)

    # Context truncation safety
    context_preview = context_text[:3000] if context_text else "No context provided."

    # Build full prompt
    full_prompt = USER_PROMPT_TEMPLATE.format(
        behaviors_list=behaviors_text,
        context_preview=context_preview
    )

    # Iterate through all models (fallback-safe)
    for model_name in ALL_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=[
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_text(
                                text=SYSTEM_INSTRUCTION + "\n\n" + full_prompt
                            )
                        ]
                    )
                ],
                config=types.GenerateContentConfig(
                    temperature=0.4,
                    max_output_tokens=1500
                )
            )

            print(f"SUCCESS: Analysis generated using {model_name}")
            return response.text

        except Exception:
            continue

    return "CRITICAL ERROR: All AI models failed. Check API quotas or network."

# 🔥 SAFETY SETTINGS TO PREVENT TRUNCATION/BLOCKING
# This allows the model to discuss malware/threats for research purposes
SAFETY_SETTINGS = [
    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
]
# =====================================================
# INTERACTIVE CHAT ANALYSIS (REVERSE ENGINEERING MODE)
# =====================================================
def chat_with_ai(code_snippet: str, user_question: str) -> str:
    """Powerful AI Assistant: Simulates a Tier-3 Senior Reverse Engineer."""

    if not api_key:
        return "AI Chat unavailable: API Key missing."

    client = genai.Client(api_key=api_key)

    chat_prompt = f"""
### 🛡️ SYSTEM ROLE: CYBERSENTINEL ELITE ANALYST
You are a world-class Cybersecurity Expert.

### 📂 CONTEXT FOR ANALYSIS
The user is investigating the following code snippet:
```{code_snippet[:6000]}```

### ❓ USER REQUEST
"{user_question}"

### 📋 RESPONSE REQUIREMENTS
1. Detailed Breakdown (line-by-line if needed)
2. Threat Logic (why dangerous)
3. De-obfuscation (Base64 / Hex)
4. Remediation guidance
5. Markdown formatting
"""

    for model_name in ALL_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=[
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=chat_prompt)]
                    )
                ],
                config=types.GenerateContentConfig(
                    temperature=0.5,
                    max_output_tokens=2048,
                    top_p=0.9,
                    top_k=40
                )
            )
            return response.text

        except Exception:
            continue

    return "Chat Error: All AI models failed. Check API quota or network."



 # import os
# from google import genai
# from google.genai import types
# from typing import List

# # --- Configuration ---
# api_key = os.environ.get("GEMINI_API_KEY") 
# if not api_key:
#     print("WARNING: GEMINI_API_KEY not found in environment variables. AI features will fail.")

# # --- Model List (Priority Order) ---
# ALL_MODELS = [
#     # --- TIER 1: LATEST STABLE & FAST (2.5 & 2.0) ---
#     'gemini-2.5-flash',
#     'gemini-2.5-flash-lite',
#     'gemini-2.0-flash',
#     'gemini-2.0-flash-001',
#     'gemini-2.0-flash-lite',
#     'gemini-2.0-flash-lite-001',
    
#     # --- TIER 2: HIGH INTELLIGENCE (PRO) ---
#     'gemini-2.5-pro',
#     'gemini-pro-latest',
    
#     # --- TIER 3: PREVIEWS & EXPERIMENTAL ---
#     'gemini-2.5-flash-preview-09-2025',
#     'gemini-2.5-flash-lite-preview-09-2025',
#     'gemini-2.0-flash-lite-preview-02-05',
#     'gemini-2.0-flash-lite-preview',
#     'gemini-2.0-flash-exp',
#     'gemini-exp-1206',
    
#     # --- TIER 4: NEXT GEN PREVIEWS (3.0) ---
#     'gemini-3-pro-preview',
#     'gemini-3-flash-preview',
#     'deep-research-pro-preview-12-2025',

#     # --- TIER 5: LEGACY / ALIASES ---
#     'gemini-flash-latest',
#     'gemini-flash-lite-latest',
#     'gemini-1.5-flash-latest',
#     'gemini-1.5-flash-lite-latest',
    
#     # --- TIER 6: GEMMA (OPEN MODELS FALLBACK) ---
#     'gemma-3-27b-it',
#     'gemma-3-12b-it',
#     'gemma-3-4b-it',
#     'gemma-3-1b-it',
#     'gemma-3n-e4b-it',
#     'gemma-3n-e2b-it',
    
#     # --- TIER 7: SPECIALIZED ---
#     'gemini-robotics-er-1.5-preview',
#     'gemini-2.5-computer-use-preview-10-2025',
#     'nano-banana-pro-preview'
# ]

# # # --- FALLBACK REPORTS (The Safety Net) ---
# MOCK_REPORT_CLEAN = """
# ### **Heuristic Analysis: Clean**
# * **Assessment:** The analysis detected no malicious indicators, anomalies, or hidden payloads.
# * **Technical:** Standard protocol compliance observed. No LSB modifications in image data.
# * **Recommendation:** No further action required. File appears benign.
# """

# MOCK_REPORT_THREAT = """
# ### **Heuristic Analysis: THREAT DETECTED**
# * **Assessment:** Critical security indicators were identified during the scan.
# * **Technical:** Potential C2 communication or hidden Steganographic payload detected.
# * **Impact:** Risk of data exfiltration or unauthorized command execution.
# * **Recommendation:** Isolate the file/network immediately and perform deep forensics.
# """
# # --- Enhanced Prompt Definitions ---
# SYSTEM_INSTRUCTION = """
# You are a Tier-3 Senior Security Operations Center (SOC) Analyst working for a top cybersecurity firm. 
# Your job is to analyze technical indicators of compromise (IOCs) and behavioral patterns identified by automated scanning tools.

# You must produce a professional, structured threat intelligence report for a technical audience (other security engineers and IT administrators).

# Your report must be objective, cautious in its conclusions, and highlight potential impacts clearly. Do not use alarmist language, but be direct about risks.

# Keep the response concise but deeply informative. Use Markdown formatting to structure the report with clear headings.
# """

# USER_PROMPT_TEMPLATE = """
# Automated static analysis has flagged the following suspicious behaviors in the provided source code (Language: Auto-Detect).

# **Technical Indicators Found:**
# {behaviors_list}

# **Additional Context:**
# Any YARA rule hits mentioned above indicate specific, known attack patterns.

# **Task:**
# Based *only* on these indicators, generate a Threat Analysis Report covering:

# 1.  **Executive Summary:** A 2-sentence high-level overview of the threat level.
# 2.  **Language & Attack Vector:** Identify the programming language (e.g., C++, PowerShell, Go) and the specific attack technique.
# 3.  **Technical Breakdown:** Analyze the combination of these specific behaviors.
# 4.  **Potential Impact:** If this code were executed with administrative privileges, what could happen?
# 5.  **Recommended Immediate Actions:** 3 distinct, actionable steps.

# Do NOT provide code corrections. Focus solely on threat analysis.
# """
# # 🔥 SAFETY SETTINGS TO PREVENT TRUNCATION/BLOCKING
# # This allows the model to discuss malware/threats for research purposes
# SAFETY_SETTINGS = [
#     types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
#     types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
#     types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
#     types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
# ]

# def generate_explanation(behaviors: List[str], yara_hits: List[str] = []) -> str:
#     """
#     Sends behaviors to Google Gemini to generate a professional threat report.
#     Implements round-robin fallback if models fail or quotas are exceeded.
#     """
#     if not api_key:
#         return "AI Analysis unavailable: API key missing."
    
#     if not behaviors and not yara_hits:
#         return "AI Analysis unavailable: No behaviors detected."

#     # Initialize Client (New SDK)
#     client = genai.Client(api_key=api_key)

#     combined_indicators = behaviors + [f"YARA Match: {hit}" for hit in yara_hits]
#     behaviors_text = "\n- ".join(combined_indicators)
#     full_prompt = USER_PROMPT_TEMPLATE.format(behaviors_list=behaviors_text)

#     # Loop through all models in priority order
#     for model_name in ALL_MODELS:
#         try:
#             # New SDK Syntax for Generate Content
#             response = client.models.generate_content(
#                 model=model_name,
#                 contents=[
#                     types.Content(
#                         role="user",
#                         parts=[
#                             types.Part.from_text(text=SYSTEM_INSTRUCTION + "\n\n" + full_prompt)
#                         ]
#                     )
#                 ],
#                 config=types.GenerateContentConfig(
#                     temperature=0.4,
#                     max_output_tokens=1500
#                 )
#             )
            
#             # If successful, return immediately
#             print(f"SUCCESS: Analysis generated using {model_name}")
#             return response.text

#         except Exception:
#             # Quota exceeded or model error: Silent fail, move to next
#             print("Switching to next model...")
#             continue

#     # If loop finishes without returning, all models failed
#     return "CRITICAL ERROR: All AI models failed to generate a report. Please check API Quotas or network connection."

# # 🤖 FEATURE: CHAT WITH AI ---
# # backend/analyzer/ai_explainer.py
# # backend/analyzer/ai_explainer.py

# def chat_with_ai(code_snippet: str, user_question: str) -> str:
#     """
#     Powerful AI Assistant: Simulates a Tier-3 Senior Reverse Engineer.
#     Provides deep, structured, and complete technical breakdowns.
#     """
#     if not api_key:
#         return "AI Chat unavailable: API Key missing."

#     client = genai.Client(api_key=api_key)

#     # 🔥 IMPROVED PROMPT STRUCTURE
#     chat_prompt = f"""
#     ### 🛡️ SYSTEM ROLE: CYBERSENTINEL ELITE ANALYST
#     You are a world-class Cybersecurity Expert. Your goal is to provide exhaustive, 
#     highly technical, and actionable intelligence regarding the provided code.

#     ### 📂 CONTEXT FOR ANALYSIS
#     The user is investigating the following code snippet:
#     ```
#     {code_snippet[:6000]} 
#     ```

#     ### ❓ USER REQUEST
#     "{user_question}"

#     ### 📋 RESPONSE REQUIREMENTS (STRICT ADHERENCE)
#     1. **Detailed Breakdown:** Do not summarize if a deep dive is required. Explain line-by-line if necessary.
#     2. **Threat Logic:** Explain the 'Why'. Why is this dangerous? What is the attacker's end goal?
#     3. **De-obfuscation:** If any part of the code is encoded (Base64, Hex, etc.), decode it and explain the hidden payload.
#     4. **Remediation:** Provide specific code examples on how to secure this snippet or mitigate the threat.
#     5. **Formatting:** Use structured Markdown: 
#        - **Bold** for critical threats.
#        - `Inline code` for variables/functions.
#        - Large code blocks for fixes.

#     ### ⚠️ IMPORTANT: Provide a complete and exhaustive answer. Do not stop mid-sentence.
#     """

#     for model_name in ALL_MODELS:
#         try:
#             response = client.models.generate_content(
#                 model=model_name,
#                 contents=[
#                     types.Content(
#                         role="user",
#                         parts=[types.Part.from_text(text=chat_prompt)]
#                     )
#                 ],
#                 config=types.GenerateContentConfig(
#                     # 🔥 HIGHER TOKENS FOR COMPLETE ANSWERS
#                     temperature=0.5,       # More deterministic/accurate
#                     max_output_tokens=2048, # Significantly increased to prevent cutoff
#                     top_p=0.9,
#                     top_k=40
#                 )
#             )
#             return response.text

#         except Exception as e:
#             print(f"DEBUG: Model {model_name} failed. Error: {str(e)}")
#             continue
            
#     return "Chat Error: All AI models failed to provide a complete response. Check API quota or network."

 # ------>1st version #
# import os
# import logging
# from google import genai
# from google.genai import types
# from typing import List

# # Setup Logger
# logger = logging.getLogger(__name__)

# # --- Configuration ---
# api_key = os.environ.get("GEMINI_API_KEY") 

# # --- Model List ---
# ALL_MODELS = [
   
#     'gemini-2.5-flash',
#     'gemini-2.5-flash-lite',
#     'gemini-2.0-flash',
#     'gemini-2.0-flash-001',
#     'gemini-2.0-flash-lite',
#     'gemini-2.0-flash-lite-001',
    
#     # --- TIER 2: HIGH INTELLIGENCE (PRO) ---
#     'gemini-2.5-pro',
#     'gemini-pro-latest',
    
#     # --- TIER 3: PREVIEWS & EXPERIMENTAL ---
#     'gemini-2.5-flash-preview-09-2025',
#     'gemini-2.5-flash-lite-preview-09-2025',
#     'gemini-2.0-flash-lite-preview-02-05',
#     'gemini-2.0-flash-lite-preview',
#     'gemini-2.0-flash-exp',
#     'gemini-exp-1206',
    
#     # --- TIER 4: NEXT GEN PREVIEWS (3.0) ---
#     'gemini-3-pro-preview',
#     'gemini-3-flash-preview',
#     'deep-research-pro-preview-12-2025',

#     # --- TIER 5: LEGACY / ALIASES ---
#     'gemini-flash-latest',
#     'gemini-flash-lite-latest',
#     'gemini-1.5-flash-latest',
#     'gemini-1.5-flash-lite-latest',
    
#     # --- TIER 6: GEMMA (OPEN MODELS FALLBACK) ---
#     'gemma-3-27b-it',
#     'gemma-3-12b-it',
#     'gemma-3-4b-it',
#     'gemma-3-1b-it',
#     'gemma-3n-e4b-it',
#     'gemma-3n-e2b-it',
    
#     # --- TIER 7: SPECIALIZED ---
#     'gemini-robotics-er-1.5-preview',
#     'gemini-2.5-computer-use-preview-10-2025',
#     'nano-banana-pro-preview'         # Legacy
# ]

# # --- FALLBACK REPORTS (The Safety Net) ---
# MOCK_REPORT_CLEAN = """
# ### **Heuristic Analysis: Clean**
# * **Assessment:** The analysis detected no malicious indicators, anomalies, or hidden payloads.
# * **Technical:** Standard protocol compliance observed. No LSB modifications in image data.
# * **Recommendation:** No further action required. File appears benign.
# """

# MOCK_REPORT_THREAT = """
# ### **Heuristic Analysis: THREAT DETECTED**
# * **Assessment:** Critical security indicators were identified during the scan.
# * **Technical:** Potential C2 communication or hidden Steganographic payload detected.
# * **Impact:** Risk of data exfiltration or unauthorized command execution.
# * **Recommendation:** Isolate the file/network immediately and perform deep forensics.
# """

# SYSTEM_INSTRUCTION = """
# You are a Senior Cyber Forensic Analyst. Generate a professional "Heuristic Analysis Report".
# Be concise, objective, and technical. Use Markdown.
# """

# USER_PROMPT_TEMPLATE = """
# **Forensic Scan Results:**
# {behaviors_list}

# **Task:**
# Generate a concise Threat Report with:
# 1. **Executive Summary**
# 2. **Technical Analysis**
# 3. **Impact Assessment**
# 4. **Recommendation**
# """
# # # 🔥 SAFETY SETTINGS TO PREVENT TRUNCATION/BLOCKING
# # # This allows the model to discuss malware/threats for research purposes
# # SAFETY_SETTINGS = [
# #     types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
# #     types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
# #     types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
# #     types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
# # ]
# def generate_explanation(behaviors: List[str], yara_hits: List[str] = []) -> str:
#     """
#     Generates a forensic report. Uses FALLBACK if AI fails.
#     """
#     # 1. Check for API Key - If missing, use Fallback immediately
#     if not api_key:
#         logger.warning("⚠️ API Key missing. Using Offline Fallback.")
#         return MOCK_REPORT_THREAT if any("CRITICAL" in b for b in behaviors) else MOCK_REPORT_CLEAN

#     # 2. Initialize Client
#     try:
#         client = genai.Client(api_key=api_key)
#     except Exception as e:
#         logger.error(f"AI Client Init Failed: {e}")
#         return MOCK_REPORT_THREAT if any("CRITICAL" in b for b in behaviors) else MOCK_REPORT_CLEAN

#     # 3. Prepare Prompt
#     if not behaviors and not yara_hits:
#         behaviors = ["No suspicious indicators found. Analysis shows clean patterns."]

#     combined_indicators = behaviors + [f"YARA Rule Match: {hit}" for hit in yara_hits]
#     behaviors_text = "\n- ".join(combined_indicators)
#     full_prompt = USER_PROMPT_TEMPLATE.format(behaviors_list=behaviors_text)

#     # 4. Attempt Generation
#     for model_name in ALL_MODELS:
#         try:
#             response = client.models.generate_content(
#                 model=model_name,
#                 contents=[types.Content(role="user", parts=[types.Part.from_text(text=SYSTEM_INSTRUCTION + "\n\n" + full_prompt)])],
#                 config=types.GenerateContentConfig(temperature=0.3, max_output_tokens=800)
#             )
#             if response.text:
#                 logger.info(f"✅ AI Report Generated using {model_name}")
#                 return response.text

#         except Exception as e:
#             logger.warning(f"⚠️ Model {model_name} failed: {str(e)}")
#             continue

#     # 5. Ultimate Fallback (If all models fail)
#     logger.error("❌ All AI Models failed. Returning Offline Report.")
#     return MOCK_REPORT_THREAT if any("CRITICAL" in b for b in behaviors) else MOCK_REPORT_CLEAN

# def chat_with_ai(code_snippet: str, user_question: str) -> str:
#     """Chat Handler with Fallback"""
#     if not api_key: return "⚠️ Chat Unavailable: API Key missing."
    
#     client = genai.Client(api_key=api_key)
#     chat_prompt = f"CONTEXT:\n{code_snippet[:4000]}\n\nQUESTION:\n{user_question}"

#     for model_name in ALL_MODELS:
#         try:
#             response = client.models.generate_content(
#                 model=model_name,
#                 contents=[types.Content(role="user", parts=[types.Part.from_text(text=chat_prompt)])]
#             )
#             if response.text: return response.text
#         except: continue
            
#     return "❌ AI Chat Unresponsive."