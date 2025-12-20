from pydantic import BaseModel
from typing import List, Optional

class CodeInput(BaseModel):
    # Field is required for analysis
    code: str 

class ChatInput(BaseModel):
    code: str
    question: str

class AnalysisResponse(BaseModel):
    malware_type: str
    risk_score: int
    behaviors: List[str]
    explanation: str
    # Fixed: Adding a default value prevents 422 if the field is missing in response logic
    code: Optional[str] = "" 

class HashCheck(BaseModel):
    hash: str