"""
Organization API Routes
This module contains API endpoints for managing organizations.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/organizations", tags=["Organizations"])

# Pydantic models - updated for Pydantic v2 compatibility
class SubscriptionModel(BaseModel):
    plan: str
    startDate: datetime
    endDate: Optional[datetime] = None
    paymentStatus: str


class OrganizationBase(BaseModel):
    name: str
    industry: str
    size: str
    location: Optional[str] = None
    contactPerson: Optional[str] = None
    contactEmail: str
    contactPhone: Optional[str] = None
    subscription: SubscriptionModel
    deploymentType: str
    
    model_config = ConfigDict(extra="ignore")


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    size: Optional[str] = None
    location: Optional[str] = None
    contactPerson: Optional[str] = None
    contactEmail: Optional[str] = None
    contactPhone: Optional[str] = None
    subscription: Optional[SubscriptionModel] = None
    deploymentType: Optional[str] = None
    
    model_config = ConfigDict(extra="ignore")


class OrganizationDB(OrganizationBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Routes
@router.get("/", response_model=List[OrganizationDB])
async def get_organizations(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get a list of organizations.
    Admin users can see all organizations, other users can only see their own.
    """
    # Check if user is admin
    if current_user["role"] != "admin":
        # Non-admin users can only see their own organization
        org_id = current_user["organizationId"]
        organization = await app.mongodb.organizations.find_one({"_id": org_id})
        if organization:
            return [organization]
        return []
    
    # Admin users can see all organizations
    organizations = await app.mongodb.organizations.find().skip(skip).limit(limit).to_list(limit)
    return organizations


@router.get("/{org_id}", response_model=OrganizationDB)
async def get_organization(
    org_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a single organization by ID."""
    # Check if user has access to this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization"
        )
    
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {org_id} not found"
        )
    
    return organization


@router.post("/", response_model=OrganizationDB, status_code=status.HTTP_201_CREATED)
async def create_organization(
    organization: OrganizationCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new organization (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can create organizations"
        )
    
    # Check if organization with same name already exists
    existing_org = await app.mongodb.organizations.find_one({"name": organization.name})
    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Organization with name '{organization.name}' already exists"
        )
    
    # Prepare organization data
    org_data = organization.model_dump()
    timestamp = datetime.now()
    org_data.update({
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert organization
    result = await app.mongodb.organizations.insert_one(org_data)
    
    # Get the created organization
    created_org = await app.mongodb.organizations.find_one({"_id": result.inserted_id})
    
    return created_org


@router.put("/{org_id}", response_model=OrganizationDB)
async def update_organization(
    org_id: str,
    organization_update: OrganizationUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update an organization by ID."""
    # Check if user has access to this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this organization"
        )
    
    # Check if organization exists
    existing_org = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
    if not existing_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {org_id} not found"
        )
    
    # Prepare update data
    update_data = {k: v for k, v in organization_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # If trying to update name, check if new name already exists
    if "name" in update_data and update_data["name"] != existing_org["name"]:
        name_exists = await app.mongodb.organizations.find_one({
            "name": update_data["name"],
            "_id": {"$ne": ObjectId(org_id)}
        })
        if name_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Organization with name '{update_data['name']}' already exists"
            )
    
    # Update organization
    await app.mongodb.organizations.update_one(
        {"_id": ObjectId(org_id)},
        {"$set": update_data}
    )
    
    # Get updated organization
    updated_org = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
    
    return updated_org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete an organization by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete organizations"
        )
    
    # Check if organization exists
    existing_org = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
    if not existing_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {org_id} not found"
        )
    
    # Delete organization
    await app.mongodb.organizations.delete_one({"_id": ObjectId(org_id)})
    
    # Delete related data (users, devices, etc.)
    await app.mongodb.users.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.devices.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.threats.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.vulnerabilities.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.logs.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.networkTraffic.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.reports.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.settings.delete_many({"organizationId": ObjectId(org_id)})
    await app.mongodb.dashboardWidgets.delete_many({"organizationId": ObjectId(org_id)})
    
    return None