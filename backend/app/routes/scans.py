from fastapi import APIRouter, Depends, HTTPException
from app.dependencies import get_current_user
from app.core.database import db
from app.models.scan import ScanResult, ScanStart
from app.services.scanner import scan_web_application
from app.services.ai_analysis import get_ai_analysis
import asyncio
from datetime import datetime

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("/start", response_model=ScanResult)
async def start_scan(scan_data: ScanStart, user=Depends(get_current_user)):
    scan = ScanResult(
        user_id=user.id,
        target_url=scan_data.target_url,
        scan_type=scan_data.scan_type
    )

    await db.scans.insert_one(scan.dict())
    asyncio.create_task(run_scan(scan.id, scan.target_url))
    return scan

@router.get("/", response_model=list[ScanResult])
async def get_user_scans(user=Depends(get_current_user)):
    scans = await db.scans.find({"user_id": user.id}).to_list(None)
    return scans

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    scan = await db.scans.find_one({"id": scan_id, "user_id": user.id})
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan

@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(scan_id: str, user=Depends(get_current_user)):
    scan = await db.scans.find_one({"id": scan_id, "user_id": user.id})
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"vulnerabilities": scan.get("vulnerabilities", [])}

async def run_scan(scan_id: str, url: str):
    vulns = await scan_web_application(url)
    ai_summary = await get_ai_analysis(vulns, url)

    high_risk = sum(1 for v in vulns if v.get('severity') == 'High')
    medium_risk = sum(1 for v in vulns if v.get('severity') == 'Medium')
    low_risk = sum(1 for v in vulns if v.get('severity') == 'Low')

    await db.scans.update_one(
        {"id": scan_id},
        {"$set": {
            "status": "completed",
            "total_vulnerabilities": len(vulns),
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "vulnerabilities": vulns,
            "ai_summary": ai_summary,
            "completed_at": datetime.utcnow()
        }}
    )
