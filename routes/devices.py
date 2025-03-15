"""
Device API Routes
This module contains API endpoints for managing devices.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/devices", tags=["Devices"])

# Pydantic models
class DeviceBase(BaseModel):
    hostname: str
    ipAddress: str
    macAddress: Optional[str] = None
    deviceType: str
    operatingSystem: Optional[str] = None
    osVersion: Optional[str] = None
    isMonitored: bool = True
    installedSoftware: Optional[List[str]] = None


class DeviceCreate(DeviceBase):
    organizationId: str


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ipAddress: Optional[str] = None
    macAddress: Optional[str] = None
    deviceType: Optional[str] = None
    operatingSystem: Optional[str] = None
    osVersion: Optional[str] = None
    securityStatus: Optional[str] = None
    vulnerabilityCount: Optional[int] = None
    isMonitored: Optional[bool] = None
    installedSoftware: Optional[List[str]] = None


class DeviceDB(DeviceBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    lastSeen: Optional[datetime] = None
    securityStatus: str
    vulnerabilityCount: int
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Routes
@router.get("/", response_model=List[DeviceDB])
async def get_devices(
    org_id: Optional[str] = None,
    device_type: Optional[str] = None,
    security_status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of devices with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see devices in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if device_type:
        query["deviceType"] = device_type
    
    if security_status:
        query["securityStatus"] = security_status
    
    # Get devices
    devices = await app.mongodb.devices.find(query).skip(skip).limit(limit).to_list(limit)
    return devices


@router.get("/{device_id}", response_model=DeviceDB)
async def get_device(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single device by ID."""
    device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has access to this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this device"
        )
    
    return device


@router.post("/", response_model=DeviceDB, status_code=status.HTTP_201_CREATED)
async def create_device(
    device: DeviceCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new device."""
    # Check if user has permission to create devices in this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != device.organizationId:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create devices for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(device.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {device.organizationId} not found"
        )
    
    # Validate device type
    valid_device_types = ["server", "workstation", "laptop", "mobile", "network", "iot"]
    if device.deviceType not in valid_device_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid device type. Must be one of: {', '.join(valid_device_types)}"
        )
    
    # Check if device with same hostname or IP already exists in this organization
    existing_device = await app.mongodb.devices.find_one({
        "organizationId": ObjectId(device.organizationId),
        "$or": [
            {"hostname": device.hostname},
            {"ipAddress": device.ipAddress}
        ]
    })
    
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Device with same hostname or IP address already exists in this organization"
        )
    
    # Prepare device data
    device_data = device.model_dump()
    timestamp = datetime.now()
    
    # Add additional fields
    device_data.update({
        "organizationId": ObjectId(device.organizationId),
        "lastSeen": timestamp,
        "securityStatus": "unknown",  # Initial status
        "vulnerabilityCount": 0,
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert device
    result = await app.mongodb.devices.insert_one(device_data)
    
    # Get the created device
    created_device = await app.mongodb.devices.find_one({"_id": result.inserted_id})
    
    return created_device


@router.put("/{device_id}", response_model=DeviceDB)
async def update_device(
    device_id: str,
    device_update: DeviceUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a device by ID."""
    # Check if device exists
    existing_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not existing_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has permission to update this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this device"
        )
    
    # If trying to update device type, validate it
    if device_update.deviceType:
        valid_device_types = ["server", "workstation", "laptop", "mobile", "network", "iot"]
        if device_update.deviceType not in valid_device_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid device type. Must be one of: {', '.join(valid_device_types)}"
            )
    
    # If trying to update security status, validate it
    if device_update.securityStatus:
        valid_statuses = ["secure", "vulnerable", "compromised", "unknown"]
        if device_update.securityStatus not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid security status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # If trying to update hostname or IP, check if already exists
    org_id = existing_device["organizationId"]
    
    if device_update.hostname and device_update.hostname != existing_device["hostname"]:
        hostname_exists = await app.mongodb.devices.find_one({
            "organizationId": org_id,
            "hostname": device_update.hostname,
            "_id": {"$ne": ObjectId(device_id)}
        })
        
        if hostname_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Device with hostname '{device_update.hostname}' already exists in this organization"
            )
    
    if device_update.ipAddress and device_update.ipAddress != existing_device["ipAddress"]:
        ip_exists = await app.mongodb.devices.find_one({
            "organizationId": org_id,
            "ipAddress": device_update.ipAddress,
            "_id": {"$ne": ObjectId(device_id)}
        })
        
        if ip_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Device with IP address '{device_update.ipAddress}' already exists in this organization"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in device_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Update device
    await app.mongodb.devices.update_one(
        {"_id": ObjectId(device_id)},
        {"$set": update_data}
    )
    
    # Get updated device
    updated_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    
    return updated_device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a device by ID."""
    # Check if device exists
    existing_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not existing_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has permission to delete this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this device"
        )
    
    # Delete device
    await app.mongodb.devices.delete_one({"_id": ObjectId(device_id)})
    
    # Delete related data (threats, vulnerabilities, logs, etc.)
    await app.mongodb.threats.delete_many({"deviceId": ObjectId(device_id)})
    await app.mongodb.vulnerabilities.delete_many({"deviceId": ObjectId(device_id)})
    await app.mongodb.logs.delete_many({"deviceId": ObjectId(device_id)})
    await app.mongodb.networkTraffic.delete_many({"deviceId": ObjectId(device_id)})
    await app.mongodb.responseActions.delete_many({"deviceId": ObjectId(device_id)})
    
    return None


@router.put("/{device_id}/security-status", response_model=DeviceDB)
async def update_device_security_status(
    device_id: str,
    status: str = Query(..., description="Security status: secure, vulnerable, compromised, or unknown"),
    current_user: dict = Depends(get_current_user)
):
    """Update device security status."""
    # Check if device exists
    existing_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not existing_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has permission to update this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this device"
        )
    
    # Validate status
    valid_statuses = ["secure", "vulnerable", "compromised", "unknown"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid security status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Update device status
    await app.mongodb.devices.update_one(
        {"_id": ObjectId(device_id)},
        {"$set": {
            "securityStatus": status,
            "lastSeen": datetime.now(),
            "updatedAt": datetime.now()
        }}
    )
    
    # Get updated device
    updated_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    
    return updated_device


@router.get("/{device_id}/threats", response_model=List[Dict[str, Any]])
async def get_device_threats(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all threats for a device."""
    # Check if device exists
    existing_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not existing_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has permission to access this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this device's threats"
        )
    
    # Get threats for this device
    threats = await app.mongodb.threats.find({"deviceId": ObjectId(device_id)}).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for threat in threats:
        threat["_id"] = str(threat["_id"])
        threat["deviceId"] = str(threat["deviceId"])
        threat["organizationId"] = str(threat["organizationId"])
        if "detectionModelId" in threat and threat["detectionModelId"]:
            threat["detectionModelId"] = str(threat["detectionModelId"])
        if "responseActionIds" in threat and threat["responseActionIds"]:
            threat["responseActionIds"] = [str(id) for id in threat["responseActionIds"]]
        if "resolvedBy" in threat and threat["resolvedBy"]:
            threat["resolvedBy"] = str(threat["resolvedBy"])
    
    return threats


@router.get("/{device_id}/vulnerabilities", response_model=List[Dict[str, Any]])
async def get_device_vulnerabilities(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all vulnerabilities for a device."""
    # Check if device exists
    existing_device = await app.mongodb.devices.find_one({"_id": ObjectId(device_id)})
    if not existing_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {device_id} not found"
        )
    
    # Check if user has permission to access this device
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_device["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this device's vulnerabilities"
        )
    
    # Get vulnerabilities for this device
    vulnerabilities = await app.mongodb.vulnerabilities.find({"deviceId": ObjectId(device_id)}).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for vuln in vulnerabilities:
        vuln["_id"] = str(vuln["_id"])
        vuln["deviceId"] = str(vuln["deviceId"])
        vuln["organizationId"] = str(vuln["organizationId"])
    
    return vulnerabilities