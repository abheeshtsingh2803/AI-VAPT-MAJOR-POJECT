from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import JWTError, jwt
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="VAPT Platform", description="AI-Powered Vulnerability Assessment & Penetration Testing")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    role: str = "analyst"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class VulnerabilityCreate(BaseModel):
    target_url: str
    scan_type: str = "web_app"

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    location: str
    recommendation: str
    cvss_score: float
    ai_analysis: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    target_url: str
    scan_type: str
    status: str = "pending"
    total_vulnerabilities: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    ai_summary: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

class ScanStatistics(BaseModel):
    total_scans: int
    completed_scans: int
    total_vulnerabilities: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return User(**user)

# Vulnerability Scanner Functions
async def scan_web_application(url: str) -> List[Dict[str, Any]]:
    """Basic web application vulnerability scanner"""
    vulnerabilities = []
    
    try:
        async with aiohttp.ClientSession() as session:
            # Test for common vulnerabilities
            vulnerabilities.extend(await check_xss_vulnerabilities(session, url))
            vulnerabilities.extend(await check_sql_injection(session, url))
            vulnerabilities.extend(await check_security_headers(session, url))
            vulnerabilities.extend(await check_directory_traversal(session, url))
            vulnerabilities.extend(await check_csrf_protection(session, url))
            
    except Exception as e:
        logging.error(f"Error scanning {url}: {str(e)}")
    
    return vulnerabilities

async def check_xss_vulnerabilities(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Check for XSS vulnerabilities"""
    vulnerabilities = []
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>"
    ]
    
    try:
        async with session.get(url) as response:
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all(['input', 'textarea'])
                if inputs:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'title': 'Potential Cross-Site Scripting (XSS)',
                        'description': f'Form found at {url} may be vulnerable to XSS attacks',
                        'location': str(form),
                        'recommendation': 'Implement input validation and output encoding',
                        'cvss_score': 7.5
                    })
                    
    except Exception as e:
        logging.error(f"XSS check error: {str(e)}")
    
    return vulnerabilities

async def check_sql_injection(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Check for SQL injection vulnerabilities"""
    vulnerabilities = []
    sql_payloads = ["'", "' OR 1=1--", "'; DROP TABLE users;--"]
    
    try:
        # Check URL parameters
        if '=' in url:
            base_url = url.split('=')[0] + "='"
            async with session.get(base_url) as response:
                content = await response.text()
                if any(error in content.lower() for error in ['sql syntax', 'mysql error', 'ora-', 'postgresql']):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'title': 'SQL Injection Vulnerability',
                        'description': f'URL parameter at {url} appears vulnerable to SQL injection',
                        'location': url,
                        'recommendation': 'Use parameterized queries and input validation',
                        'cvss_score': 9.0
                    })
                    
    except Exception as e:
        logging.error(f"SQL injection check error: {str(e)}")
    
    return vulnerabilities

async def check_security_headers(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Check for missing security headers"""
    vulnerabilities = []
    
    try:
        async with session.get(url) as response:
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content Security Policy header'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Security Header',
                        'severity': 'Medium',
                        'title': f'Missing Security Header: {header}',
                        'description': message,
                        'location': url,
                        'recommendation': f'Implement {header} security header',
                        'cvss_score': 5.0
                    })
                    
    except Exception as e:
        logging.error(f"Security headers check error: {str(e)}")
    
    return vulnerabilities

async def check_directory_traversal(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Check for directory traversal vulnerabilities"""
    vulnerabilities = []
    traversal_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
    
    try:
        for payload in traversal_payloads:
            test_url = f"{url}?file={payload}"
            async with session.get(test_url) as response:
                content = await response.text()
                if 'root:' in content or '[drivers]' in content:
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'title': 'Directory Traversal Vulnerability',
                        'description': f'Directory traversal detected at {test_url}',
                        'location': test_url,
                        'recommendation': 'Implement proper input validation and file access controls',
                        'cvss_score': 7.5
                    })
                    break
                    
    except Exception as e:
        logging.error(f"Directory traversal check error: {str(e)}")
    
    return vulnerabilities

async def check_csrf_protection(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Check for CSRF protection"""
    vulnerabilities = []
    
    try:
        async with session.get(url) as response:
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                csrf_token = form.find(['input'], {'name': re.compile(r'csrf|token', re.I)})
                if not csrf_token:
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'severity': 'Medium',
                        'title': 'Missing CSRF Protection',
                        'description': 'Form lacks CSRF protection tokens',
                        'location': str(form),
                        'recommendation': 'Implement CSRF tokens for all state-changing operations',
                        'cvss_score': 6.0
                    })
                    
    except Exception as e:
        logging.error(f"CSRF check error: {str(e)}")
    
    return vulnerabilities

async def get_ai_analysis(vulnerabilities: List[Dict[str, Any]], target_url: str) -> str:
    """Get AI analysis of vulnerabilities using GPT-5"""
    try:
        chat = LlmChat(
            api_key=os.environ.get('EMERGENT_LLM_KEY'),
            session_id=str(uuid.uuid4()),
            system_message="You are a cybersecurity expert analyzing vulnerability assessment results. Provide detailed analysis, risk assessment, and actionable remediation recommendations."
        ).with_model("openai", "gpt-5")
        
        vulnerability_summary = "\n".join([
            f"- {vuln['severity']} Risk: {vuln['title']} at {vuln['location']}"
            for vuln in vulnerabilities
        ])
        
        user_message = UserMessage(
            text=f"""
            Analyze the following vulnerability assessment results for {target_url}:
            
            Vulnerabilities Found:
            {vulnerability_summary}
            
            Please provide:
            1. Overall security posture assessment
            2. Risk prioritization
            3. Business impact analysis
            4. Detailed remediation roadmap
            5. Compliance considerations
            """
        )
        
        response = await chat.send_message(user_message)
        return response
        
    except Exception as e:
        logging.error(f"AI analysis error: {str(e)}")
        return "AI analysis temporarily unavailable"

# Auth Routes
@api_router.post("/auth/register", response_model=Token)
async def register(user: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash password and create user
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    user_obj = User(**{k: v for k, v in user_dict.items() if k != 'password'})
    
    # Save to database
    await db.users.insert_one({**user_obj.dict(), "password": hashed_password})
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/auth/login", response_model=Token)
async def login(user: UserLogin):
    # Authenticate user
    db_user = await db.users.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# VAPT Routes
@api_router.post("/scans/start", response_model=ScanResult)
async def start_vulnerability_scan(scan_request: VulnerabilityCreate, current_user: User = Depends(get_current_user)):
    """Start a new vulnerability scan"""
    
    # Create scan record
    scan = ScanResult(
        user_id=current_user.id,
        target_url=scan_request.target_url,
        scan_type=scan_request.scan_type,
        status="running"
    )
    
    # Save scan to database
    await db.scans.insert_one(scan.dict())
    
    # Start scan in background
    asyncio.create_task(perform_vulnerability_scan(scan.id, scan_request.target_url))
    
    return scan

async def perform_vulnerability_scan(scan_id: str, target_url: str):
    """Perform the actual vulnerability scan"""
    try:
        # Update scan status
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "scanning"}}
        )
        
        # Perform vulnerability scanning
        vulnerabilities = await scan_web_application(target_url)
        
        # Save vulnerabilities to database
        vulnerability_objects = []
        high_count = medium_count = low_count = 0
        
        for vuln in vulnerabilities:
            vulnerability = Vulnerability(
                scan_id=scan_id,
                vulnerability_type=vuln['type'],
                severity=vuln['severity'],
                title=vuln['title'],
                description=vuln['description'],
                location=vuln['location'],
                recommendation=vuln['recommendation'],
                cvss_score=vuln['cvss_score']
            )
            
            vulnerability_objects.append(vulnerability.dict())
            
            if vuln['severity'] == 'Critical' or vuln['severity'] == 'High':
                high_count += 1
            elif vuln['severity'] == 'Medium':
                medium_count += 1
            else:
                low_count += 1
        
        # Save vulnerabilities
        if vulnerability_objects:
            await db.vulnerabilities.insert_many(vulnerability_objects)
        
        # Get AI analysis
        ai_summary = await get_ai_analysis(vulnerabilities, target_url)
        
        # Update scan with results
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
                "total_vulnerabilities": len(vulnerabilities),
                "high_risk": high_count,
                "medium_risk": medium_count,
                "low_risk": low_count,
                "ai_summary": ai_summary,
                "completed_at": datetime.now(timezone.utc)
            }}
        )
        
    except Exception as e:
        logging.error(f"Scan error: {str(e)}")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed"}}
        )

@api_router.get("/scans", response_model=List[ScanResult])
async def get_scans(current_user: User = Depends(get_current_user)):
    """Get all scans for the current user"""
    scans = await db.scans.find({"user_id": current_user.id}).sort("created_at", -1).to_list(100)
    return [ScanResult(**scan) for scan in scans]

@api_router.get("/scans/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
async def get_scan_vulnerabilities(scan_id: str, current_user: User = Depends(get_current_user)):
    """Get vulnerabilities for a specific scan"""
    vulnerabilities = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(1000)
    return [Vulnerability(**vuln) for vuln in vulnerabilities]

@api_router.get("/dashboard/statistics", response_model=ScanStatistics)
async def get_dashboard_statistics(current_user: User = Depends(get_current_user)):
    """Get dashboard statistics"""
    
    # Get scan statistics
    total_scans = await db.scans.count_documents({"user_id": current_user.id})
    completed_scans = await db.scans.count_documents({"user_id": current_user.id, "status": "completed"})
    
    # Get vulnerability statistics
    user_scan_ids = [scan["id"] for scan in await db.scans.find({"user_id": current_user.id}, {"id": 1}).to_list(1000)]
    
    total_vulnerabilities = await db.vulnerabilities.count_documents({"scan_id": {"$in": user_scan_ids}})
    high_risk_count = await db.vulnerabilities.count_documents({
        "scan_id": {"$in": user_scan_ids},
        "severity": {"$in": ["Critical", "High"]}
    })
    medium_risk_count = await db.vulnerabilities.count_documents({
        "scan_id": {"$in": user_scan_ids},
        "severity": "Medium"
    })
    low_risk_count = await db.vulnerabilities.count_documents({
        "scan_id": {"$in": user_scan_ids},
        "severity": "Low"
    })
    
    return ScanStatistics(
        total_scans=total_scans,
        completed_scans=completed_scans,
        total_vulnerabilities=total_vulnerabilities,
        high_risk_count=high_risk_count,
        medium_risk_count=medium_risk_count,
        low_risk_count=low_risk_count
    )

# Health check
@api_router.get("/")
async def root():
    return {"message": "VAPT Platform API", "status": "operational"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()