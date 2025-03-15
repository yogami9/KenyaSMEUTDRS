"""
Vulnerability API Routes
This module contains API endpoints for managing vulnerabilities.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

# Pydantic models
class VulnerabilityBase(BaseModel):
    deviceId: str
    cveId: str
    title: str
    description: str
    severity: str
    cvssScore: float
    affectedSoftware: str
    affectedVersion: str
    remediationSteps: Optional[str] = None
    patchAvailable: bool = False
    patchLink: Optional[str] = None
    exploitAvailable: bool = False
    status: str = "open"


class VulnerabilityCreate(VulnerabilityBase):
    organizationId: str


class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvssScore: Optional[float] = None
    remediationSteps: Optional[str] = None
    patchAvailable: Optional[bool] = None
    patchLink: Optional[str] = None
    exploitAvailable: Optional[bool] = None
    status: Optional[str] = None
    fixedAt: Optional[datetime] = None


class VulnerabilityDB(VulnerabilityBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    deviceId: PyObjectId
    discoveredAt: datetime
    fixedAt: Optional[datetime] = None
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_vulnerabilities(
    org_id: Optional[str] = None,
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    cve_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of vulnerabilities with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see vulnerabilities in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if device_id:
        query["deviceId"] = ObjectId(device_id)
    
    if severity:
        query["severity"] = severity
    
    if status:
        query["status"] = status
    
    if cve_id:
        query["cveId"] = {"$regex": cve_id, "$options": "i"}
    
    # Get vulnerabilities
    vulnerabilities = await app.mongodb.vulnerabilities.find(query).sort("discoveredAt", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for vuln in vulnerabilities:
        vuln["_id"] = str(vuln["_id"])
        vuln["deviceId"] = str(vuln["deviceId"])
        vuln["organizationId"] = str(vuln["organizationId"])
    
    return vulnerabilities


@router.get("/{vuln_id}", response_model=Dict[str, Any])
async def get_vulnerability(
    vuln_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single vulnerability by ID."""
    vulnerability = await app.mongodb.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {vuln_id} not found"
        )
    
    # Check if user has access to this vulnerability
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(vulnerability["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this vulnerability"
        )
    
    # Convert ObjectId to string for JSON serialization
    vulnerability["_id"] = str(vulnerability["_id"])
    vulnerability["deviceId"] = str(vulnerability["deviceId"])
    vulnerability["organizationId"] = str(vulnerability["organizationId"])
    
    return vulnerability


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    vulnerability: VulnerabilityCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new vulnerability."""
    # Check if user has permission to create vulnerabilities in this organization
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != vulnerability.organizationId):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create vulnerabilities for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(vulnerability.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {vulnerability.organizationId} not found"
        )
    
    # Check if device exists
    device = await app.mongodb.devices.find_one({"_id": ObjectId(vulnerability.deviceId)})
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {vulnerability.deviceId} not found"
        )
    
    # Check if device belongs to the organization
    if str(device["organizationId"]) != vulnerability.organizationId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device does not belong to the specified organization"
        )
    
    # Validate severity
    valid_severities = ["low", "medium", "high", "critical"]
    if vulnerability.severity not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )
    
    # Validate status
    valid_statuses = ["open", "in_progress", "patched", "mitigated", "accepted"]
    if vulnerability.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Prepare vulnerability data
    vulnerability_data = vulnerability.model_dump()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    vulnerability_data["organizationId"] = ObjectId(vulnerability.organizationId)
    vulnerability_data["deviceId"] = ObjectId(vulnerability.deviceId)
    
    # Add additional fields
    vulnerability_data.update({
        "discoveredAt": timestamp,
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert vulnerability
    result = await app.mongodb.vulnerabilities.insert_one(vulnerability_data)
    
    # Update device vulnerability count and security status
    await app.mongodb.devices.update_one(
        {"_id": ObjectId(vulnerability.deviceId)},
        {
            "$inc": {"vulnerabilityCount": 1},
            "$set": {
                "securityStatus": "vulnerable",
                "lastSeen": timestamp,
                "updatedAt": timestamp
            }
        }
    )
    
    # Get the created vulnerability
    created_vulnerability = await app.mongodb.vulnerabilities.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_vulnerability["_id"] = str(created_vulnerability["_id"])
    created_vulnerability["deviceId"] = str(created_vulnerability["deviceId"])
    created_vulnerability["organizationId"] = str(created_vulnerability["organizationId"])
    
    return created_vulnerability


@router.put("/{vuln_id}", response_model=Dict[str, Any])
async def update_vulnerability(
    vuln_id: str,
    vulnerability_update: VulnerabilityUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a vulnerability by ID."""
    # Check if vulnerability exists
    existing_vulnerability = await app.mongodb.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not existing_vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {vuln_id} not found"
        )
    
    # Check if user has permission to update this vulnerability
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_vulnerability["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this vulnerability"
        )
    
    # Validate severity if provided
    if vulnerability_update.severity:
        valid_severities = ["low", "medium", "high", "critical"]
        if vulnerability_update.severity not in valid_severities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
            )
    
    # Validate status if provided
    if vulnerability_update.status:
        valid_statuses = ["open", "in_progress", "patched", "mitigated", "accepted"]
        if vulnerability_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in vulnerability_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # If status is being changed to patched, mitigated, or accepted, add fixedAt timestamp
    was_open = existing_vulnerability.get("status") in ["open", "in_progress"]
    is_now_fixed = vulnerability_update.status in ["patched", "mitigated", "accepted"]
    
    if was_open and is_now_fixed and not update_data.get("fixedAt"):
        update_data["fixedAt"] = datetime.now()
    
    # Update vulnerability
    await app.mongodb.vulnerabilities.update_one(
        {"_id": ObjectId(vuln_id)},
        {"$set": update_data}
    )
    
    # Get updated vulnerability
    updated_vulnerability = await app.mongodb.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_vulnerability["_id"] = str(updated_vulnerability["_id"])
    updated_vulnerability["deviceId"] = str(updated_vulnerability["deviceId"])
    updated_vulnerability["organizationId"] = str(updated_vulnerability["organizationId"])
    
    # If vulnerability is now fixed, update device security status if no more active vulnerabilities
    if was_open and is_now_fixed:
        device_id = updated_vulnerability["deviceId"]
        
        # Count active vulnerabilities for this device
        active_vulnerabilities = await app.mongodb.vulnerabilities.count_documents({
            "deviceId": ObjectId(device_id),
            "status": {"$in": ["open", "in_progress"]}
        })
        
        # Count active threats for this device
        active_threats = await app.mongodb.threats.count_documents({
            "deviceId": ObjectId(device_id),
            "status": {"$nin": ["resolved", "false_positive"]}
        })
        
        # If no active vulnerabilities or threats, set device to secure
        if active_vulnerabilities == 0 and active_threats == 0:
            await app.mongodb.devices.update_one(
                {"_id": ObjectId(device_id)},
                {
                    "$set": {
                        "securityStatus": "secure",
                        "updatedAt": datetime.now()
                    }
                }
            )
    
    return updated_vulnerability


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vuln_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a vulnerability by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete vulnerabilities"
        )
    
    # Check if vulnerability exists
    existing_vulnerability = await app.mongodb.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not existing_vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {vuln_id} not found"
        )
    
    # Delete vulnerability
    await app.mongodb.vulnerabilities.delete_one({"_id": ObjectId(vuln_id)})
    
    # Update device vulnerability count
    device_id = existing_vulnerability["deviceId"]
    
    # Decrement only if vulnerability was active
    if existing_vulnerability.get("status") in ["open", "in_progress"]:
        await app.mongodb.devices.update_one(
            {"_id": device_id},
            {"$inc": {"vulnerabilityCount": -1}}
        )
        
        # Update device security status if needed
        active_vulnerabilities = await app.mongodb.vulnerabilities.count_documents({
            "deviceId": device_id,
            "status": {"$in": ["open", "in_progress"]}
        })
        
        active_threats = await app.mongodb.threats.count_documents({
            "deviceId": device_id,
            "status": {"$nin": ["resolved", "false_positive"]}
        })
        
        if active_vulnerabilities == 0 and active_threats == 0:
            await app.mongodb.devices.update_one(
                {"_id": device_id},
                {
                    "$set": {
                        "securityStatus": "secure",
                        "updatedAt": datetime.now()
                    }
                }
            )
    
    return None


@router.get("/summary/statistics", response_model=Dict[str, Any])
async def get_vulnerability_statistics(
    org_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get vulnerability statistics for an organization."""
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see vulnerabilities in their organization
        org_id = str(current_user["organizationId"])
    
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {"organizationId": ObjectId(org_id)}},
        {"$group": {
            "_id": {
                "severity": "$severity",
                "status": "$status"
            },
            "count": {"$sum": 1}
        }},
        {"$group": {
            "_id": "$_id.severity",
            "statuses": {
                "$push": {
                    "status": "$_id.status",
                    "count": "$count"
                }
            },
            "totalCount": {"$sum": "$count"}
        }},
        {"$sort": {"_id": 1}}
    ]
    
    # Run aggregation
    vuln_counts = await app.mongodb.vulnerabilities.aggregate(pipeline).to_list(1000)
    
    # Process results
    summary = {
        "total": 0,
        "by_severity": {},
        "by_status": {},
        "open_critical": 0,
        "open_high": 0
    }
    
    # Initialize by_status counters
    for status in ["open", "in_progress", "patched", "mitigated", "accepted"]:
        summary["by_status"][status] = 0
    
    # Process aggregation results
    for severity_group in vuln_counts:
        severity = severity_group["_id"]
        count = severity_group["totalCount"]
        summary["total"] += count
        summary["by_severity"][severity] = count
        
        # Process status counts
        for status_item in severity_group["statuses"]:
            status = status_item["status"]
            status_count = status_item["count"]
            
            summary["by_status"][status] = summary["by_status"].get(status, 0) + status_count
            
            # Count open critical and high vulnerabilities
            if status in ["open", "in_progress"]:
                if severity == "critical":
                    summary["open_critical"] += status_count
                elif severity == "high":
                    summary["open_high"] += status_count
    
    # Calculate average time to fix (only for fixed vulnerabilities)
    pipeline = [
        {"$match": {
            "organizationId": ObjectId(org_id),
            "status": {"$in": ["patched", "mitigated"]},
            "fixedAt": {"$exists": True},
            "discoveredAt": {"$exists": True}
        }},
        {"$project": {
            "fixTime": {"$subtract": ["$fixedAt", "$discoveredAt"]}
        }},
        {"$group": {
            "_id": None,
            "avgFixTime": {"$avg": "$fixTime"},
            "count": {"$sum": 1}
        }}
    ]
    
    fix_time_result = await app.mongodb.vulnerabilities.aggregate(pipeline).to_list(1)
    
    if fix_time_result and len(fix_time_result) > 0:
        # Convert milliseconds to days
        avg_fix_time_ms = fix_time_result[0]["avgFixTime"]
        avg_fix_time_days = round(avg_fix_time_ms / (1000 * 60 * 60 * 24), 1)
        summary["avg_fix_time_days"] = avg_fix_time_days
        summary["fixed_vulnerabilities_count"] = fix_time_result[0]["count"]
    else:
        summary["avg_fix_time_days"] = 0
        summary["fixed_vulnerabilities_count"] = 0
    
    return summary