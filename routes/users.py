"""
User API Routes
This module contains API endpoints for managing users.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr, ConfigDict
import bcrypt
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/users", tags=["Users"])

# Pydantic models
class UserBase(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    role: str


class UserCreate(UserBase):
    organizationId: str
    password: str


class UserUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    active: Optional[bool] = None


class UserDB(UserBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    active: bool
    lastLogin: Optional[datetime] = None
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class UserChangePassword(BaseModel):
    current_password: str
    new_password: str


# Password hashing
def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


# Routes
@router.get("/", response_model=List[UserDB])
async def get_users(
    org_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of users.
    Admin users can see all users or filter by organization.
    Non-admin users can only see users in their organization.
    """
    if current_user["role"] != "admin":
        # Non-admin users can only see users in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {}
    if org_id:
        query["organizationId"] = ObjectId(org_id)
    
    # Get users
    users = await app.mongodb.users.find(query).skip(skip).limit(limit).to_list(limit)
    return users


@router.get("/me", response_model=UserDB)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    return current_user


@router.get("/{user_id}", response_model=UserDB)
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single user by ID."""
    # Check if user has permission to access this user
    user = await app.mongodb.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Check if user has access to this user's information
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(user["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this user's information"
        )
    
    return user


@router.post("/", response_model=UserDB, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new user."""
    # Check if user has permission to create users in this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != user.organizationId:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users for this organization"
        )
    
    # Check if user with same email already exists
    existing_user = await app.mongodb.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with email '{user.email}' already exists"
        )
    
    # Validate role
    valid_roles = ["admin", "manager", "analyst", "user"]
    if user.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )
    
    # Only admins can create admin users
    if user.role == "admin" and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can create other admin users"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(user.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {user.organizationId} not found"
        )
    
    # Prepare user data
    user_data = user.model_dump(exclude={"password"})
    timestamp = datetime.now()
    
    # Hash password
    password_hash = hash_password(user.password)
    
    # Add additional fields
    user_data.update({
        "passwordHash": password_hash,
        "organizationId": ObjectId(user.organizationId),
        "active": True,
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert user
    result = await app.mongodb.users.insert_one(user_data)
    
    # Get the created user
    created_user = await app.mongodb.users.find_one({"_id": result.inserted_id})
    
    return created_user


@router.put("/{user_id}", response_model=UserDB)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a user by ID."""
    # Check if user exists
    existing_user = await app.mongodb.users.find_one({"_id": ObjectId(user_id)})
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Check if user has permission to update this user
    is_admin = current_user["role"] == "admin"
    is_self = str(current_user["_id"]) == user_id
    same_org = str(current_user["organizationId"]) == str(existing_user["organizationId"])
    
    if not (is_admin or (is_self and not user_update.role) or (same_org and current_user["role"] == "manager")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )
    
    # If trying to update role, check permissions
    if user_update.role:
        # Only admins can change roles
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin users can change user roles"
            )
        
        # Validate role
        valid_roles = ["admin", "manager", "analyst", "user"]
        if user_update.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            )
    
    # If trying to update email, check if new email already exists
    if user_update.email and user_update.email != existing_user["email"]:
        email_exists = await app.mongodb.users.find_one({
            "email": user_update.email,
            "_id": {"$ne": ObjectId(user_id)}
        })
        if email_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email '{user_update.email}' already exists"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in user_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Update user
    await app.mongodb.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    # Get updated user
    updated_user = await app.mongodb.users.find_one({"_id": ObjectId(user_id)})
    
    return updated_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a user by ID."""
    # Check if user exists
    existing_user = await app.mongodb.users.find_one({"_id": ObjectId(user_id)})
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Check if user has permission to delete this user
    is_admin = current_user["role"] == "admin"
    same_org = str(current_user["organizationId"]) == str(existing_user["organizationId"])
    
    if not (is_admin or (same_org and current_user["role"] == "manager")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this user"
        )
    
    # Cannot delete self
    if str(current_user["_id"]) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own user account"
        )
    
    # Delete user
    await app.mongodb.users.delete_one({"_id": ObjectId(user_id)})
    
    return None


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    password_change: UserChangePassword,
    current_user: dict = Depends(get_current_user)
):
    """Change user password."""
    # Verify current password
    if not verify_password(password_change.current_password, current_user["passwordHash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Hash new password
    new_password_hash = hash_password(password_change.new_password)
    
    # Update password
    await app.mongodb.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"passwordHash": new_password_hash, "updatedAt": datetime.now()}}
    )
    
    return None