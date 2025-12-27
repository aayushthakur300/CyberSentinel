from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class CodeInput(BaseModel):
    """Input for source code and text-based de-obfuscation."""
    code: str = Field(..., description="The source code or text to be analyzed")

class ChatInput(BaseModel):
    """Input for the AI Analyst Chat feature."""
    code: str = Field(..., description="Code context for the AI")
    question: str = Field(..., description="User question about the code")

class HashCheck(BaseModel):
    """Input for VirusTotal reputation lookups."""
    hash: str = Field(..., description="SHA256 hash of the file")

class AnalysisResponse(BaseModel):
    """
    Standardized response for all analysis engines.
    Matches the FAANG-standard for predictable API contracts.
    """
    malware_type: str
    risk_score: int
    risk_matrix: Dict[str, int]   # <--- ✅ CORRECT: This enables the 8-axis Graph
    behaviors: List[str]
    explanation: str
    code: Optional[str] = "" 
    metadata: Optional[Dict[str, Any]] = {} 

class StegoResponse(BaseModel):
    """Specialized response for Steganography findings."""
    has_hidden_data: bool
    hidden_message: Optional[str] = None
    details: List[str] = []
    risk_score: Optional[int] = 0
    # Note: If you ever enforce this model on the /analyze/stego route, 
    # you MUST add 'risk_matrix: Dict[str, int]' here too. 
    # Currently, your router uses a raw dictionary for stego, so it works fine without it.