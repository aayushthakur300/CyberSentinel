import yara
import os

# Path to your .yar file
RULES_FILE_PATH = os.path.join(os.path.dirname(__file__), "rules.yar")

def compile_rules():
    """Compiles YARA rules once to improve performance."""
    if not os.path.exists(RULES_FILE_PATH):
        print(f"⚠️ YARA rules file not found at: {RULES_FILE_PATH}")
        return None
    try:
        return yara.compile(filepath=RULES_FILE_PATH)
    except Exception as e:
        print(f"⚠️ YARA Compilation Error: {e}")
        return None

# Load rules globally when server starts
_COMPILED_RULES = compile_rules()

def run_yara_analysis(content: str):
    """
    Runs the YARA engine against the provided string content.
    """
    if _COMPILED_RULES is None:
        return []

    matches = []
    try:
        # Match against the string content
        yara_matches = _COMPILED_RULES.match(data=content)
        
        for match in yara_matches:
            matches.append({
                "rule": match.rule,
                "description": match.meta.get('description', 'No description'),
                "severity": match.meta.get('severity', 'Unknown')
            })
            
    except Exception as e:
        print(f"YARA Match Error: {e}")

    return matches