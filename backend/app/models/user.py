from pydantic import BaseModel
from datetime import datetime
import uuid

class User(BaseModel):
    id: str = str(uuid.uuid4())
    username: str
    email: str
    role: str = "analyst"
    created_at: datetime = datetime.utcnow()

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
