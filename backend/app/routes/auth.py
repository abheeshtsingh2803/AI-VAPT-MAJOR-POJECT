from fastapi import APIRouter, HTTPException
from app.core.database import db
from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import UserCreate, UserLogin, Token

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/register", response_model=Token)
async def register(user: UserCreate):
    if await db.users.find_one({"username": user.username}):
        raise HTTPException(400, "Username exists")

    hashed = hash_password(user.password)
    await db.users.insert_one({
        "username": user.username,
        "email": user.email,
        "password": hashed
    })

    return {"access_token": create_access_token(user.username), "token_type": "bearer"}

@router.post("/login", response_model=Token)
async def login(user: UserLogin):
    db_user = await db.users.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(401, "Invalid credentials")

    return {"access_token": create_access_token(user.username), "token_type": "bearer"}
