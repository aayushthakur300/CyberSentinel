# backend/analyzer/risk_engine.py

# 1. Define Threat Weights
RISK_WEIGHTS = {
    # 🔴 CRITICAL (Immediate 85-100)
    "Ransomware_Behavior": 100,
    "Reverse Shell": 100,
    "WannaCry_Ransomware": 100,
    "Privilege Escalation": 95,
    "Keylogging": 90,
    "Shadow Copy Deletion": 100,
    
    # 🔥 FIX: Added "Command Execution" to match Source Code Rules
    "Command Execution": 85, 

    # 🟠 SUSPICIOUS (Medium 50-75)
    "Persistence": 75,
    "Hidden_Payload": 70,
    "Network Exfiltration": 65,
    "Obfuscation": 60,
    "Packed Binary (UPX)": 50,
    "High_Risk_Command_Exec": 80,  # Kept for YARA compatibility
    "Suspicious_Command_Exec": 50, # Kept for YARA compatibility
    
    # 🟡 CAUTION (Low 10-30)
    "File Tampering": 30,
    "Network_Activity": 20,
    "Writable+Executable Section": 30,
    "Crypto Mining": 45,
    "Database Injection": 40
}

def calculate_risk(behaviors):
    """
    Calculates risk by taking the MAX threat score and adding small 
    penalties for additional behaviors.
    """
    if not behaviors:
        return 0

    scores = []
    
    for behavior in behaviors:
        # Clean up string (e.g. "YARA: Rule (High)" -> "Rule")
        clean_name = behavior.split('(')[0].replace("YARA: ", "").strip()
        
        # Get score (Default to 10 for unknown low-level events)
        score = RISK_WEIGHTS.get(clean_name, RISK_WEIGHTS.get(behavior, 10))
        scores.append(score)

    if not scores:
        return 0

    # 1. Take the Highest Threat found (Base Score)
    max_risk = max(scores)
    
    # 2. Calculate remaining sum of other threats
    remaining_sum = sum(scores) - max_risk
    
    # 3. Add only 10% of the remaining threats as a "Density Penalty"
    final_score = max_risk + (remaining_sum * 0.10)

    # 4. Cap at 100
    return int(min(final_score, 100))