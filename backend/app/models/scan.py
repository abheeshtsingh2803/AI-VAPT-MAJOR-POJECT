from pydantic import BaseModel
from datetime import datetime
import uuid
from typing import Optional

class ScanStart(BaseModel):
    target_url: str
    scan_type: str

class ScanResult(BaseModel):
    id: str = str(uuid.uuid4())
    user_id: str
    target_url: str
    scan_type: str
    status: str = "pending"
    total_vulnerabilities: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    vulnerabilities: list = []
    ai_summary: Optional[str] = None
    created_at: datetime = datetime.utcnow()
    completed_at: Optional[datetime] = None

class ScanStatistics(BaseModel):
    total_scans: int
    completed_scans: int
    total_vulnerabilities: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int