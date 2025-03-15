"""
Settings API Routes
This module contains API endpoints for managing system settings.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/settings", tags=["Settings"])

# Pydantic models
class SettingBase(BaseModel):
    configType: str
    config: Dict[str, Any]
    isEnabled: bool = True


class SettingCreate(SettingBase):
    organizationId: str


class SettingUpdate(BaseModel):
    config: Optional[Dict[str, Any]] = None
    isEnabled: Optional[bool] = None


class SettingDB(SettingBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    lastModifiedBy: PyObjectId
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_settings(
    org_id: Optional[str] = None,
    config_type: Optional[str] = None,
    enabled_only: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of settings with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see settings in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if config_type:
        query["configType"] = config_type
    
    if enabled_only:
        query["isEnabled"] = True
    
    # Get settings
    settings = await app.mongodb.settings.find(query).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for setting in settings:
        setting["_id"] = str(setting["_id"])
        setting["organizationId"] = str(setting["organizationId"])
        setting["lastModifiedBy"] = str(setting["lastModifiedBy"])
    
    return settings


@router.get("/{setting_id}", response_model=Dict[str, Any])
async def get_setting(
    setting_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single setting by ID."""
    setting = await app.mongodb.settings.find_one({"_id": ObjectId(setting_id)})
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting with ID {setting_id} not found"
        )
    
    # Check if user has access to this setting
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(setting["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this setting"
        )
    
    # Convert ObjectId to string for JSON serialization
    setting["_id"] = str(setting["_id"])
    setting["organizationId"] = str(setting["organizationId"])
    setting["lastModifiedBy"] = str(setting["lastModifiedBy"])
    
    return setting


@router.get("/organization/{org_id}/type/{config_type}", response_model=Dict[str, Any])
async def get_setting_by_type(
    org_id: str,
    config_type: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a setting by organization ID and config type."""
    # Check if user has access to this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access settings for this organization"
        )
    
    # Build query
    query = {
        "organizationId": ObjectId(org_id),
        "configType": config_type
    }
    
    # Get setting
    setting = await app.mongodb.settings.find_one(query)
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting with config type {config_type} not found for organization {org_id}"
        )
    
    # Convert ObjectId to string for JSON serialization
    setting["_id"] = str(setting["_id"])
    setting["organizationId"] = str(setting["organizationId"])
    setting["lastModifiedBy"] = str(setting["lastModifiedBy"])
    
    return setting


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_setting(
    setting: SettingCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new setting."""
    # Check if user has permission to create settings in this organization
    if current_user["role"] not in ["admin", "manager"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != setting.organizationId):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create settings for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(setting.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {setting.organizationId} not found"
        )
    
    # Validate config type
    valid_config_types = ["notification", "scanning", "response", "reporting", "alerting", "integration"]
    if setting.configType not in valid_config_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid config type. Must be one of: {', '.join(valid_config_types)}"
        )
    
    # Check if setting with same config type already exists for this organization
    existing_setting = await app.mongodb.settings.find_one({
        "organizationId": ObjectId(setting.organizationId),
        "configType": setting.configType
    })
    
    if existing_setting:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Setting with config type '{setting.configType}' already exists for this organization"
        )
    
    # Prepare setting data
    setting_data = setting.model_dump()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    setting_data["organizationId"] = ObjectId(setting.organizationId)
    
    # Add additional fields
    setting_data.update({
        "lastModifiedBy": current_user["_id"],
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert setting
    result = await app.mongodb.settings.insert_one(setting_data)
    
    # Get the created setting
    created_setting = await app.mongodb.settings.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_setting["_id"] = str(created_setting["_id"])
    created_setting["organizationId"] = str(created_setting["organizationId"])
    created_setting["lastModifiedBy"] = str(created_setting["lastModifiedBy"])
    
    return created_setting


@router.put("/{setting_id}", response_model=Dict[str, Any])
async def update_setting(
    setting_id: str,
    setting_update: SettingUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a setting by ID."""
    # Check if setting exists
    existing_setting = await app.mongodb.settings.find_one({"_id": ObjectId(setting_id)})
    if not existing_setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting with ID {setting_id} not found"
        )
    
    # Check if user has permission to update this setting
    if current_user["role"] not in ["admin", "manager"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_setting["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this setting"
        )
    
    # Prepare update data
    update_data = {k: v for k, v in setting_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    update_data["lastModifiedBy"] = current_user["_id"]
    
    # Update setting
    await app.mongodb.settings.update_one(
        {"_id": ObjectId(setting_id)},
        {"$set": update_data}
    )
    
    # Get updated setting
    updated_setting = await app.mongodb.settings.find_one({"_id": ObjectId(setting_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_setting["_id"] = str(updated_setting["_id"])
    updated_setting["organizationId"] = str(updated_setting["organizationId"])
    updated_setting["lastModifiedBy"] = str(updated_setting["lastModifiedBy"])
    
    return updated_setting


@router.delete("/{setting_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_setting(
    setting_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a setting by ID."""
    # Check if setting exists
    existing_setting = await app.mongodb.settings.find_one({"_id": ObjectId(setting_id)})
    if not existing_setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting with ID {setting_id} not found"
        )
    
    # Check if user has permission to delete this setting
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_setting["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this setting"
        )
    
    # Delete setting
    await app.mongodb.settings.delete_one({"_id": ObjectId(setting_id)})
    
    return None


@router.patch("/organization/{org_id}/type/{config_type}/toggle", response_model=Dict[str, Any])
async def toggle_setting(
    org_id: str,
    config_type: str,
    enabled: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Toggle a setting's enabled status."""
    # Check if user has permission to update settings in this organization
    if current_user["role"] not in ["admin", "manager"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update settings for this organization"
        )
    
    # Check if setting exists
    existing_setting = await app.mongodb.settings.find_one({
        "organizationId": ObjectId(org_id),
        "configType": config_type
    })
    
    if not existing_setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting with config type {config_type} not found for organization {org_id}"
        )
    
    # Update setting
    await app.mongodb.settings.update_one(
        {
            "organizationId": ObjectId(org_id),
            "configType": config_type
        },
        {
            "$set": {
                "isEnabled": enabled,
                "lastModifiedBy": current_user["_id"],
                "updatedAt": datetime.now()
            }
        }
    )
    
    # Get updated setting
    updated_setting = await app.mongodb.settings.find_one({
        "organizationId": ObjectId(org_id),
        "configType": config_type
    })
    
    # Convert ObjectId to string for JSON serialization
    updated_setting["_id"] = str(updated_setting["_id"])
    updated_setting["organizationId"] = str(updated_setting["organizationId"])
    updated_setting["lastModifiedBy"] = str(updated_setting["lastModifiedBy"])
    
    return updated_setting