"""
Threat API Routes
This module contains API endpoints for managing threats.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId
from pydantic import BaseModel, Field
from main import get_current_user, app

router = APIRouter(prefix="/threats", tags=["Threats"])

# Pydantic models
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, 
        core_schema: dict, 
        handler: Any
    ) -> dict:
        """
        Replace __modify_schema__ with __get_pydantic_json_schema__ for Pydantic v2 compatibility.
        """
        json_schema = handler(core_schema)
        json_schema.update(type="string")
        return json_schema


class ThreatBase(BaseModel):
    deviceId: str
    detectionMethod: str
    detectionModelId: Optional[str] = None
    threatType: str
    severity: str
    confidence: Optional[float] = None
    signature: Optional[str] = None
    description: Optional[str] = None
    sourceIp: Optional[str] = None
    destinationIp: Optional[str] = None
    rawData: Optional[Dict[str, Any]] = None


class ThreatCreate(ThreatBase):
    organizationId: str


class ThreatUpdate(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    mitigationSteps: Optional[List[str]] = None
    resolutionNotes: Optional[str] = None
    resolvedAt: Optional[datetime] = None
    resolvedBy: Optional[str] = None


class ThreatDB(ThreatBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    deviceId: PyObjectId
    detectionModelId: Optional[PyObjectId] = None
    timestamp: datetime
    status: str
    responseActionIds: Optional[List[PyObjectId]] = None
    mitigationSteps: Optional[List[str]] = None
    resolutionNotes: Optional[str] = None
    resolvedAt: Optional[datetime] = None
    resolvedBy: Optional[PyObjectId] = None
    createdAt: datetime
    updatedAt: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}





# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_threats(
    org_id: Optional[str] = None,
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of threats with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see threats in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if device_id:
        query["deviceId"] = ObjectId(device_id)
    
    if severity:
        query["severity"] = severity
    
    if status:
        query["status"] = status
    
    if threat_type:
        query["threatType"] = threat_type
    
    # Date range query
    if from_date or to_date:
        date_query = {}
        if from_date:
            date_query["$gte"] = from_date
        if to_date:
            date_query["$lte"] = to_date
        
        if date_query:
            query["timestamp"] = date_query
    
    # Get threats
    threats = await app.mongodb.threats.find(query).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    
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


@router.get("/{threat_id}", response_model=Dict[str, Any])
async def get_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single threat by ID."""
    threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with ID {threat_id} not found"
        )
    
    # Check if user has access to this threat
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(threat["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this threat"
        )
    
    # Convert ObjectId to string for JSON serialization
    threat["_id"] = str(threat["_id"])
    threat["deviceId"] = str(threat["deviceId"])
    threat["organizationId"] = str(threat["organizationId"])
    if "detectionModelId" in threat and threat["detectionModelId"]:
        threat["detectionModelId"] = str(threat["detectionModelId"])
    if "responseActionIds" in threat and threat["responseActionIds"]:
        threat["responseActionIds"] = [str(id) for id in threat["responseActionIds"]]
    if "resolvedBy" in threat and threat["resolvedBy"]:
        threat["resolvedBy"] = str(threat["resolvedBy"])
    
    return threat


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_threat(
    threat: ThreatCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new threat."""
    # Check if user has permission to create threats in this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != threat.organizationId:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create threats for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(threat.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {threat.organizationId} not found"
        )
    
    # Check if device exists
    device = await app.mongodb.devices.find_one({"_id": ObjectId(threat.deviceId)})
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID {threat.deviceId} not found"
        )
    
    # Check if device belongs to the organization
    if str(device["organizationId"]) != threat.organizationId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device does not belong to the specified organization"
        )
    
    # Validate threat type
    valid_threat_types = ["malware", "ransomware", "phishing", "ddos", "intrusion", "dataExfiltration", "anomaly", "other"]
    if threat.threatType not in valid_threat_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid threat type. Must be one of: {', '.join(valid_threat_types)}"
        )
    
    # Validate severity
    valid_severities = ["low", "medium", "high", "critical"]
    if threat.severity not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )
    
    # Validate detection method
    valid_detection_methods = ["signature", "anomaly", "ai"]
    if threat.detectionMethod not in valid_detection_methods:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid detection method. Must be one of: {', '.join(valid_detection_methods)}"
        )
    
    # If AI detection method, check if model exists
    if threat.detectionMethod == "ai" and threat.detectionModelId:
        model = await app.mongodb.aiModels.find_one({"_id": ObjectId(threat.detectionModelId)})
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"AI Model with ID {threat.detectionModelId} not found"
            )
    
    # Prepare threat data
    threat_data = threat.dict()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    threat_data["organizationId"] = ObjectId(threat.organizationId)
    threat_data["deviceId"] = ObjectId(threat.deviceId)
    if threat.detectionModelId:
        threat_data["detectionModelId"] = ObjectId(threat.detectionModelId)
    
    # Add additional fields
    threat_data.update({
        "timestamp": timestamp,
        "status": "detected",
        "responseActionIds": [],
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert threat
    result = await app.mongodb.threats.insert_one(threat_data)
    
    # Update device vulnerability count
    await app.mongodb.devices.update_one(
        {"_id": ObjectId(threat.deviceId)},
        {
            "$inc": {"vulnerabilityCount": 1},
            "$set": {
                "securityStatus": "vulnerable",
                "lastSeen": timestamp,
                "updatedAt": timestamp
            }
        }
    )
    
    # Get the created threat
    created_threat = await app.mongodb.threats.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_threat["_id"] = str(created_threat["_id"])
    created_threat["deviceId"] = str(created_threat["deviceId"])
    created_threat["organizationId"] = str(created_threat["organizationId"])
    if "detectionModelId" in created_threat and created_threat["detectionModelId"]:
        created_threat["detectionModelId"] = str(created_threat["detectionModelId"])
    if "responseActionIds" in created_threat and created_threat["responseActionIds"]:
        created_threat["responseActionIds"] = [str(id) for id in created_threat["responseActionIds"]]
    
    return created_threat


@router.put("/{threat_id}", response_model=Dict[str, Any])
async def update_threat(
    threat_id: str,
    threat_update: ThreatUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a threat by ID."""
    # Check if threat exists
    existing_threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    if not existing_threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with ID {threat_id} not found"
        )
    
    # Check if user has permission to update this threat
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_threat["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this threat"
        )
    
    # Validate severity if provided
    if threat_update.severity:
        valid_severities = ["low", "medium", "high", "critical"]
        if threat_update.severity not in valid_severities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
            )
    
    # Validate status if provided
    if threat_update.status:
        valid_statuses = ["detected", "analyzing", "mitigating", "resolved", "false_positive"]
        if threat_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # If resolving threat, require resolution notes
    if threat_update.status == "resolved" and not (threat_update.resolutionNotes or existing_threat.get("resolutionNotes")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Resolution notes are required when resolving a threat"
        )
    
    # Prepare update data
    update_data = {k: v for k, v in threat_update.dict().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # If status is being changed to resolved, add resolved info
    if threat_update.status == "resolved" and existing_threat.get("status") != "resolved":
        if not update_data.get("resolvedAt"):
            update_data["resolvedAt"] = datetime.now()
        if not update_data.get("resolvedBy"):
            update_data["resolvedBy"] = current_user["_id"]
    
    # Convert string IDs to ObjectIds if needed
    if "resolvedBy" in update_data and isinstance(update_data["resolvedBy"], str):
        update_data["resolvedBy"] = ObjectId(update_data["resolvedBy"])
    
    # Update threat
    await app.mongodb.threats.update_one(
        {"_id": ObjectId(threat_id)},
        {"$set": update_data}
    )
    
    # Get updated threat
    updated_threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_threat["_id"] = str(updated_threat["_id"])
    updated_threat["deviceId"] = str(updated_threat["deviceId"])
    updated_threat["organizationId"] = str(updated_threat["organizationId"])
    if "detectionModelId" in updated_threat and updated_threat["detectionModelId"]:
        updated_threat["detectionModelId"] = str(updated_threat["detectionModelId"])
    if "responseActionIds" in updated_threat and updated_threat["responseActionIds"]:
        updated_threat["responseActionIds"] = [str(id) for id in updated_threat["responseActionIds"]]
    if "resolvedBy" in updated_threat and updated_threat["resolvedBy"]:
        updated_threat["resolvedBy"] = str(updated_threat["resolvedBy"])
    
    # If threat is resolved or false positive, update device status if no more active threats
    if threat_update.status in ["resolved", "false_positive"]:
        device_id = updated_threat["deviceId"]
        active_threats = await app.mongodb.threats.count_documents({
            "deviceId": ObjectId(device_id),
            "status": {"$nin": ["resolved", "false_positive"]}
        })
        
        if active_threats == 0:
            # Check if there are vulnerabilities
            vulns = await app.mongodb.vulnerabilities.count_documents({
                "deviceId": ObjectId(device_id),
                "status": {"$nin": ["patched", "mitigated", "accepted"]}
            })
            
            new_status = "secure" if vulns == 0 else "vulnerable"
            
            await app.mongodb.devices.update_one(
                {"_id": ObjectId(device_id)},
                {"$set": {
                    "securityStatus": new_status,
                    "updatedAt": datetime.now()
                }}
            )
    
    return updated_threat


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a threat by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete threats"
        )
    
    # Check if threat exists
    existing_threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    if not existing_threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with ID {threat_id} not found"
        )
    
    # Delete threat
    await app.mongodb.threats.delete_one({"_id": ObjectId(threat_id)})
    
    # Delete related response actions
    await app.mongodb.responseActions.delete_many({"threatId": ObjectId(threat_id)})
    
    # Update device vulnerability count
    device_id = existing_threat["deviceId"]
    await app.mongodb.devices.update_one(
        {"_id": device_id},
        {"$inc": {"vulnerabilityCount": -1}}
    )
    
    # Update device security status if needed
    active_threats = await app.mongodb.threats.count_documents({
        "deviceId": device_id,
        "status": {"$nin": ["resolved", "false_positive"]}
    })
    
    if active_threats == 0:
        # Check if there are vulnerabilities
        vulns = await app.mongodb.vulnerabilities.count_documents({
            "deviceId": device_id,
            "status": {"$nin": ["patched", "mitigated", "accepted"]}
        })
        
        new_status = "secure" if vulns == 0 else "vulnerable"
        
        await app.mongodb.devices.update_one(
            {"_id": device_id},
            {"$set": {
                "securityStatus": new_status,
                "updatedAt": datetime.now()
            }}
        )
    
    return None


@router.post("/{threat_id}/actions", response_model=Dict[str, Any])
async def create_response_action(
    threat_id: str,
    action_type: str = Query(..., description="Action type (e.g., block_ip, isolate_device)"),
    parameters: Optional[Dict[str, Any]] = None,
    current_user: dict = Depends(get_current_user)
):
    """Create a response action for a threat."""
    # Check if threat exists
    threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with ID {threat_id} not found"
        )
    
    # Check if user has permission to create actions for this threat
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(threat["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create response actions for this threat"
        )
    
    # Validate action type
    valid_action_types = ["block_ip", "isolate_device", "kill_process", "delete_file", "patch", "restart_service", "notification", "other"]
    if action_type not in valid_action_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action type. Must be one of: {', '.join(valid_action_types)}"
        )
    
    # Prepare action data
    timestamp = datetime.now()
    action_data = {
        "threatId": ObjectId(threat_id),
        "deviceId": threat["deviceId"],
        "organizationId": threat["organizationId"],
        "actionType": action_type,
        "status": "pending",
        "parameters": parameters or {},
        "isAutomated": False,
        "initiatedBy": "user",
        "userId": current_user["_id"],
        "createdAt": timestamp,
        "updatedAt": timestamp
    }
    
    # Insert action
    result = await app.mongodb.responseActions.insert_one(action_data)
    
    # Update threat with response action ID
    await app.mongodb.threats.update_one(
        {"_id": ObjectId(threat_id)},
        {
            "$push": {"responseActionIds": result.inserted_id},
            "$set": {
                "status": "mitigating",
                "updatedAt": timestamp
            }
        }
    )
    
    # Get the created action
    created_action = await app.mongodb.responseActions.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_action["_id"] = str(created_action["_id"])
    created_action["threatId"] = str(created_action["threatId"])
    created_action["deviceId"] = str(created_action["deviceId"])
    created_action["organizationId"] = str(created_action["organizationId"])
    created_action["userId"] = str(created_action["userId"])
    
    return created_action


@router.get("/{threat_id}/actions", response_model=List[Dict[str, Any]])
async def get_threat_actions(
    threat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all response actions for a threat."""
    # Check if threat exists
    threat = await app.mongodb.threats.find_one({"_id": ObjectId(threat_id)})
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with ID {threat_id} not found"
        )
    
    # Check if user has permission to access this threat
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(threat["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access actions for this threat"
        )
    
    # Get actions for this threat
    actions = await app.mongodb.responseActions.find({"threatId": ObjectId(threat_id)}).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for action in actions:
        action["_id"] = str(action["_id"])
        action["threatId"] = str(action["threatId"])
        action["deviceId"] = str(action["deviceId"])
        action["organizationId"] = str(action["organizationId"])
        if "userId" in action and action["userId"]:
            action["userId"] = str(action["userId"])
    
    return actions


@router.get("/summary/by-organization", response_model=Dict[str, Any])
async def get_threats_summary_by_organization(
    org_id: Optional[str] = None,
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(get_current_user)
):
    """Get a summary of threats by organization."""
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see threats in their organization
        org_id = str(current_user["organizationId"])
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {
            "organizationId": ObjectId(org_id),
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }},
        {"$group": {
            "_id": {
                "severity": "$severity",
                "status": "$status",
                "threatType": "$threatType"
            },
            "count": {"$sum": 1}
        }},
        {"$group": {
            "_id": "$_id.severity",
            "statuses": {
                "$push": {
                    "status": "$_id.status",
                    "count": "$count",
                    "threatType": "$_id.threatType"
                }
            },
            "totalCount": {"$sum": "$count"}
        }},
        {"$sort": {"_id": 1}}
    ]
    
    # Run aggregation
    threat_summary = await app.mongodb.threats.aggregate(pipeline).to_list(1000)
    
    # Process results
    summary = {
        "total": 0,
        "by_severity": {},
        "by_status": {},
        "by_type": {}
    }
    
    # Initialize by_status and by_type counters
    for status in ["detected", "analyzing", "mitigating", "resolved", "false_positive"]:
        summary["by_status"][status] = 0
    
    for threat_type in ["malware", "ransomware", "phishing", "ddos", "intrusion", "dataExfiltration", "anomaly", "other"]:
        summary["by_type"][threat_type] = 0
    
    # Process aggregation results
    for severity_group in threat_summary:
        severity = severity_group["_id"]
        count = severity_group["totalCount"]
        summary["total"] += count
        summary["by_severity"][severity] = count
        
        # Process status and type counts
        for status_item in severity_group["statuses"]:
            status = status_item["status"]
            type_count = status_item["count"]
            threat_type = status_item.get("threatType", "other")
            
            summary["by_status"][status] = summary["by_status"].get(status, 0) + type_count
            summary["by_type"][threat_type] = summary["by_type"].get(threat_type, 0) + type_count
    
    # Add time range info
    summary["time_range"] = {
        "start_date": start_date,
        "end_date": end_date,
        "days": days
    }
    
    return summary
