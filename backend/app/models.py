from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from .database import Base

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    
    # 🔥 New Fields for Binary Analysis
    filename = Column(String, default="source_code.py")
    file_hash = Column(String, index=True, nullable=True) # Stores SHA256
    
    # Analysis Data
    malware_type = Column(String)
    risk_score = Column(Integer)
    
    # Storing Lists as Text (JSON string) is safer for SQLite
    behaviors = Column(Text) 
    explanation = Column(Text)
    
    # 🔥 Timestamp (Auto-add when created)
    created_at = Column(DateTime(timezone=True), server_default=func.now())