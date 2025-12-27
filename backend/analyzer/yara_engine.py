import yara
import os
import logging

# 🔥 Connect to MITRE Brain (Fallback)
try:
    from .mitre_mapping import get_mitre_tag
except ImportError:
    def get_mitre_tag(k, m): return f"[GENERIC] {m}"

# Setup Logger
logger = logging.getLogger(__name__)

# Path to your .yar file
RULES_FILE_PATH = os.path.join(os.path.dirname(__file__), "rules.yar")

def compile_rules():
    """Compiles YARA rules once to improve performance."""
    if not os.path.exists(RULES_FILE_PATH):
        logger.warning(f"⚠️ YARA rules file not found at: {RULES_FILE_PATH}")
        return None
    try:
        return yara.compile(filepath=RULES_FILE_PATH)
    except Exception as e:
        logger.error(f"⚠️ YARA Compilation Error: {e}")
        return None

# Load rules globally when server starts
_COMPILED_RULES = compile_rules()

def get_score_from_severity(severity_str):
    """Maps text severity to numeric score for the Radar Chart."""
    severity = severity_str.lower()
    if "critical" in severity: return 100
    if "high" in severity: return 75
    if "medium" in severity: return 50
    return 25

def run_yara_analysis(content: str):
    """
    Runs the YARA engine against string content.
    Returns a list of standardized MITRE behavior tags.
    """
    if _COMPILED_RULES is None:
        return []

    matches = []
    try:
        # YARA expects a string or bytes. We ensure it scans the text.
        yara_matches = _COMPILED_RULES.match(data=content)
        
        for match in yara_matches:
            rule_name = match.rule
            description = match.meta.get('description', rule_name)
            severity = match.meta.get('severity', 'High')
            
            # 🔥 CRITICAL FIX: Read Metadata & Handle Missing ID
            mitre_id = match.meta.get('mitre_id')
            
            if not mitre_id:
                # Fallback: Default to a generic execution ID if missing
                mitre_id = "T1202"

            # 🔥 CRITICAL FIX: Calculate Score (Was missing in your snippet)
            score = get_score_from_severity(severity)

            # 🔥 ALIGNMENT FIX: Use keys 'id', 'name', 'score'
            matches.append({
                "id": mitre_id,         # Matches MITRE_ENGINE key
                "name": description,    # Matches MITRE_ENGINE key
                "score": score,         # Matches MITRE_ENGINE key
                "severity": severity,   # Extra info
                "source": "YARA"        # To track where it came from
            })
            
    except Exception as e:
        logger.error(f"YARA Match Error: {e}")

    return matches
# import yara
# import os
# import logging

# # Setup Logger
# logger = logging.getLogger(__name__)

# # =========================================================================
# # CONFIGURATION & INITIALIZATION
# # =========================================================================

# # Path to your .yar file (assumed to be in the same folder as this script)
# RULES_FILE_PATH = os.path.join(os.path.dirname(__file__), "rules.yar")

# def compile_rules():
#     """
#     Compiles YARA rules once at startup to improve performance.
#     Returns the compiled rules object or None if failed.
#     """
#     if not os.path.exists(RULES_FILE_PATH):
#         logger.warning(f"⚠️ YARA rules file not found at: {RULES_FILE_PATH}")
#         return None
#     try:
#         return yara.compile(filepath=RULES_FILE_PATH)
#     except Exception as e:
#         logger.error(f"⚠️ YARA Compilation Error: {e}")
#         return None

# # Load rules globally when server starts
# _COMPILED_RULES = compile_rules()

# # =========================================================================
# # HELPER FUNCTIONS
# # =========================================================================

# def get_score_from_severity(severity_str):
#     """
#     Maps text severity (Critical, High, etc.) to numeric score 
#     for the 8-Axis Radar Chart.
#     """
#     if not severity_str: return 20
#     severity = severity_str.lower()
    
#     if "critical" in severity: return 100
#     if "high" in severity: return 75
#     if "medium" in severity: return 50
#     return 25

# # =========================================================================
# # MAIN ANALYSIS ENGINE
# # =========================================================================

# def run_yara_analysis(content: str):
#     """
#     Runs the YARA engine against string content.
#     Returns a list of standardized dictionaries compatible with the Risk Engine.
#     """
#     # 1. Safety Checks
#     if _COMPILED_RULES is None:
#         return []
#     if not content:
#         return []

#     matches = []
    
#     try:
#         # 2. Run YARA Matcher
#         # YARA expects the 'data' argument to scan strings/bytes
#         yara_matches = _COMPILED_RULES.match(data=content)
        
#         # 3. Process Findings
#         for match in yara_matches:
#             # Extract basic info
#             rule_name = match.rule
            
#             # Extract Metadata (defined in rules.yar)
#             # Default to the rule name if description is missing
#             description = match.meta.get('description', f"YARA Match: {rule_name}")
#             severity = match.meta.get('severity', 'High')
            
#             # 🔥 CRITICAL: Handle Missing MITRE ID
#             # If the rule doesn't have a 'mitre_id', we assign a generic one 
#             # so the Risk Engine (utils.py) doesn't crash.
#             mitre_id = match.meta.get('mitre_id')
#             if not mitre_id:
#                 mitre_id = "T1202" # Generic "Indirect Command Execution" ID

#             # Calculate Score
#             score = get_score_from_severity(severity)

#             # 🔥 ALIGNMENT: Create the exact Dict format required by 'analyze.py'
#             matches.append({
#                 "id": mitre_id,         # Key for Risk Engine
#                 "name": description,    # Display Name
#                 "score": score,         # Key for Risk Engine
#                 "severity": severity,   # Extra Context
#                 "rule": rule_name,      # Specific Rule ID
#                 "source": "YARA"        # Origin
#             })
            
#     except Exception as e:
#         logger.error(f"YARA Match Error: {e}")

#     return matches