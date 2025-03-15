#!/usr/bin/env python3
"""
FastAPI REST API for Kenyan SME Cybersecurity System
This module serves as the main entry point for the API layer connecting
the frontend to the MongoDB backend.
"""

import logging
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId
import os
import jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Kenya SME Cybersecurity API",
    description="API for the Kenya SME Cybersecurity System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection parameters
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://spicelife576:skiPPer8711@cluster0.pmbmm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
DB_NAME = os.getenv("DB_NAME", "KenyaSMECybersec")

# JWT Settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-jwt-tokens")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Initialize OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models for PyObjectId - Updated for Pydantic v2 compatibility
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, info=None):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            core_schema.str_schema(),
            serialization=core_schema.to_string_serializer(),
        )


# MongoDB connection management
@app.on_event("startup")
async def startup_db_client():
    """Connect to MongoDB when the application starts."""
    app.mongodb_client = AsyncIOMotorClient(MONGO_URI, server_api=ServerApi('1'))
    app.mongodb = app.mongodb_client[DB_NAME]
    logger.info(f"Connected to MongoDB: {DB_NAME}")


@app.on_event("shutdown")
async def shutdown_db_client():
    """Close MongoDB connection when the application shuts down."""
    app.mongodb_client.close()
    logger.info("MongoDB connection closed")


# Authentication models and functions
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    org_id: Optional[str] = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Validate and return the current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        org_id: str = payload.get("org_id")
        role: str = payload.get("role")
        
        if email is None:
            raise credentials_exception
            
        token_data = TokenData(email=email, org_id=org_id, role=role)
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = await app.mongodb.users.find_one({"email": token_data.email})
    
    if user is None:
        raise credentials_exception
        
    return user


# Authentication routes
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Generate and return an access token."""
    user = await app.mongodb.users.find_one({"email": form_data.username})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # In production, use proper password verification (e.g., bcrypt)
    # For simplicity, we're just comparing the passwords directly in this example
    if form_data.password != user.get("passwordHash"):  # Replace with proper password check
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login time
    await app.mongodb.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"lastLogin": datetime.now(), "updatedAt": datetime.now()}}
    )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user["email"],
            "org_id": str(user["organizationId"]),
            "role": user["role"]
        },
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """API health check endpoint."""
    try:
        # Check if we can ping MongoDB
        await app.mongodb_client.admin.command('ping')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"API is unhealthy: {str(e)}"
        )


# Import and register routes
from routes import register_routes
register_routes(app)

# Main application entrypoint
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)