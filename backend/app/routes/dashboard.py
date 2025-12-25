from fastapi import APIRouter, Depends
from app.dependencies import get_current_user
from app.core.database import db
from app.models.scan import ScanStatistics

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/statistics", response_model=ScanStatistics)
async def statistics(user=Depends(get_current_user)):
    scans = await db.scans.find({"user_id": user.id}).to_list(1000)
    scan_ids = [s["id"] for s in scans]

    total_vulns = await db.vulnerabilities.count_documents({"scan_id": {"$in": scan_ids}})

    return ScanStatistics(
        total_scans=len(scans),
        completed_scans=len([s for s in scans if s["status"] == "completed"]),
        total_vulnerabilities=total_vulns,
        high_risk_count=0,
        medium_risk_count=0,
        low_risk_count=0
    )
