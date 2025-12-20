import re
from .behavior_rules import BEHAVIOR_RULES

def analyze_code(code: str):
    """
    Scans the provided code string against regex rules to find suspicious behaviors.
    """
    detected_behaviors = []
    
    # Normalize code to prevent simple case mismatching
    # (We scan the lower/normalized version, but keep logic simple here)
    
    for rule in BEHAVIOR_RULES:
        # Check if the pattern exists in the code
        if re.search(rule["pattern"], code, re.IGNORECASE):
            detected_behaviors.append(rule["name"])
            
    return detected_behaviors