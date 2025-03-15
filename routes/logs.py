"""
Logs API Routes
This module contains API endpoints for managing security logs.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/logs", tags=["Logs"])

# Pydantic models
class LogBase(BaseModel):
    organizationId: Optional[str] = None
    deviceId: Optional[str] = None
    userId: Optional[str] = None
    source: str
    eventType: str
    level: str
    message: str
    metadata: Optional[Dict[str, Any]] = None
    ipAddress: Optional[str] = None
    isAnomalous: Optional[bool] = False
    anomalyScore: Optional[float] = None
    relatedThreatId: Optional[str] = None


class LogCreate(LogBase):
    pass


class LogDB(LogBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: Optional[PyObjectId] = None
    deviceId: Optional[PyObjectId] = None
    userId: Optional[PyObjectId] = None
    timestamp: datetime
    relatedThreatId: Optional[PyObjectId] = None

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Helper function for ObjectId validation
def validate_object_id(id_str: str, param_name: str = "ID") -> ObjectId:
    """Validate and convert string to ObjectId or raise HTTPException."""
    try:
        if not ObjectId.is_valid(id_str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {param_name} format: {id_str}. Must be a valid ObjectId."
            )
        return ObjectId(id_str)
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {param_name} format: {id_str}. Must be a valid ObjectId."
        )


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_logs(
    org_id: Optional[str] = None,
    device_id: Optional[str] = None,
    user_id: Optional[str] = None,
    level: Optional[str] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    is_anomalous: Optional[bool] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of logs with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see logs in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {}
    
    if org_id:
        query["organizationId"] = validate_object_id(org_id, "organization ID")
    
    if device_id:
        query["deviceId"] = validate_object_id(device_id, "device ID")
    
    if user_id:
        query["userId"] = validate_object_id(user_id, "user ID")
    
    if level:
        query["level"] = level
    
    if source:
        query["source"] = source
    
    if event_type:
        query["eventType"] = event_type
    
    if is_anomalous is not None:
        query["isAnomalous"] = is_anomalous
    
    # Date range query
    if from_date or to_date:
        date_query = {}
        if from_date:
            date_query["$gte"] = from_date
        if to_date:
            date_query["$lte"] = to_date
        
        if date_query:
            query["timestamp"] = date_query
    
    # Get logs
    logs = await app.mongodb.logs.find(query).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for log in logs:
        log["_id"] = str(log["_id"])
        if "organizationId" in log and log["organizationId"]:
            log["organizationId"] = str(log["organizationId"])
        if "deviceId" in log and log["deviceId"]:
            log["deviceId"] = str(log["deviceId"])
        if "userId" in log and log["userId"]:
            log["userId"] = str(log["userId"])
        if "relatedThreatId" in log and log["relatedThreatId"]:
            log["relatedThreatId"] = str(log["relatedThreatId"])
    
    return logs


@router.get("/{log_id}", response_model=Dict[str, Any])
async def get_log(
    log_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single log by ID."""
    # Validate the log_id parameter - this will catch the {{log_id}} template issue
    object_id = validate_object_id(log_id, "log ID")
    
    # Now safely use the validated ObjectId
    log = await app.mongodb.logs.find_one({"_id": object_id})
    
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log with ID {log_id} not found"
        )
    
    # Check if user has access to this log
    if current_user["role"] != "admin" and "organizationId" in log and \
       str(current_user["organizationId"]) != str(log["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this log"
        )
    
    # Convert ObjectId to string for JSON serialization
    log["_id"] = str(log["_id"])
    if "organizationId" in log and log["organizationId"]:
        log["organizationId"] = str(log["organizationId"])
    if "deviceId" in log and log["deviceId"]:
        log["deviceId"] = str(log["deviceId"])
    if "userId" in log and log["userId"]:
        log["userId"] = str(log["userId"])
    if "relatedThreatId" in log and log["relatedThreatId"]:
        log["relatedThreatId"] = str(log["relatedThreatId"])
    
    return log


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_log(
    log: LogCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new log entry."""
    # Prepare log data
    log_data = log.model_dump()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds if provided
    if log.organizationId:
        log_data["organizationId"] = validate_object_id(log.organizationId, "organization ID")
    else:
        # Use current user's organization if not specified
        log_data["organizationId"] = current_user["organizationId"]
    
    if log.deviceId:
        log_data["deviceId"] = validate_object_id(log.deviceId, "device ID")
    
    if log.userId:
        log_data["userId"] = validate_object_id(log.userId, "user ID")
    
    if log.relatedThreatId:
        log_data["relatedThreatId"] = validate_object_id(log.relatedThreatId, "related threat ID")
    
    # Validate level
    valid_levels = ["info", "warning", "error", "critical"]
    if log.level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid log level. Must be one of: {', '.join(valid_levels)}"
        )
    
    # Add timestamp
    log_data["timestamp"] = timestamp
    
    # Insert log
    result = await app.mongodb.logs.insert_one(log_data)
    
    # Get the created log
    created_log = await app.mongodb.logs.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_log["_id"] = str(created_log["_id"])
    if "organizationId" in created_log and created_log["organizationId"]:
        created_log["organizationId"] = str(created_log["organizationId"])
    if "deviceId" in created_log and created_log["deviceId"]:
        created_log["deviceId"] = str(created_log["deviceId"])
    if "userId" in created_log and created_log["userId"]:
        created_log["userId"] = str(created_log["userId"])
    if "relatedThreatId" in created_log and created_log["relatedThreatId"]:
        created_log["relatedThreatId"] = str(created_log["relatedThreatId"])
    
    # If log is anomalous and critical/error, check if a threat should be created
    if log.isAnomalous and log.level in ["critical", "error"] and log.deviceId:
        try:
            # Check if device exists
            device_id = validate_object_id(log.deviceId, "device ID")
            device = await app.mongodb.devices.find_one({"_id": device_id})
            
            if device:
                # Create a threat based on this anomalous log
                threat_data = {
                    "organizationId": created_log["organizationId"],
                    "deviceId": device_id,
                    "detectionMethod": "anomaly",
                    "threatType": "anomaly",
                    "severity": "high" if log.level == "critical" else "medium",
                    "confidence": log.anomalyScore or 0.7,
                    "description": f"Anomalous behavior detected: {log.message}",
                    "timestamp": timestamp,
                    "status": "detected",
                    "responseActionIds": [],
                    "createdAt": timestamp,
                    "updatedAt": timestamp
                }
                
                if log.ipAddress:
                    threat_data["sourceIp"] = log.ipAddress
                
                # Insert threat
                threat_result = await app.mongodb.threats.insert_one(threat_data)
                
                # Update device status
                await app.mongodb.devices.update_one(
                    {"_id": device_id},
                    {
                        "$inc": {"vulnerabilityCount": 1},
                        "$set": {
                            "securityStatus": "vulnerable",
                            "lastSeen": timestamp,
                            "updatedAt": timestamp
                        }
                    }
                )
                
                # Update the log with the related threat ID
                await app.mongodb.logs.update_one(
                    {"_id": result.inserted_id},
                    {"$set": {"relatedThreatId": threat_result.inserted_id}}
                )
                
                # Update the created_log object to include the threat ID
                created_log["relatedThreatId"] = str(threat_result.inserted_id)
        except HTTPException:
            # If device ID validation fails, we'll skip threat creation but still return the log
            pass
    
    return created_log


@router.delete("/{log_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_log(
    log_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a log by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete logs"
        )
    
    # Validate the log_id parameter
    object_id = validate_object_id(log_id, "log ID")
    
    # Check if log exists
    existing_log = await app.mongodb.logs.find_one({"_id": object_id})
    if not existing_log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log with ID {log_id} not found"
        )
    
    # Delete log
    await app.mongodb.logs.delete_one({"_id": object_id})
    
    return None


@router.get("/summary/by-level", response_model=Dict[str, Any])
async def get_logs_summary_by_level(
    org_id: Optional[str] = None,
    days: int = Query(7, ge=1, le=90),
    current_user: dict = Depends(get_current_user)
):
    """Get a summary of logs by level for a specific time period."""
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see logs in their organization
        org_id = str(current_user["organizationId"])
    
    # Validate organization ID
    org_object_id = validate_object_id(org_id, "organization ID")
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {
            "organizationId": org_object_id,
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }},
        {"$group": {
            "_id": {
                "level": "$level",
                "day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.day": 1}},
        {"$group": {
            "_id": "$_id.level",
            "daily": {
                "$push": {
                    "date": "$_id.day",
                    "count": "$count"
                }
            },
            "total": {"$sum": "$count"}
        }}
    ]
    
    # Run aggregation
    log_summary = await app.mongodb.logs.aggregate(pipeline).to_list(1000)
    
    # Format results
    days_range = [(end_date - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days, 0, -1)]
    
    summary = {
        "period": {
            "start": start_date.strftime('%Y-%m-%d'),
            "end": end_date.strftime('%Y-%m-%d'),
            "days": days
        },
        "total_logs": 0,
        "by_level": {},
        "by_status": {},
        "daily_data": {}
    }
    
    # Initialize daily data structure
    for day in days_range:
        summary["daily_data"][day] = {
            "total": 0,
            "info": 0,
            "warning": 0,
            "error": 0,
            "critical": 0
        }
    
    # Process aggregation results
    for level_data in log_summary:
        level = level_data["_id"]
        total = level_data["total"]
        
        # Update totals
        summary["total_logs"] += total
        summary["by_level"][level] = total
        
        # Update daily data
        for day_data in level_data["daily"]:
            date = day_data["date"]
            count = day_data["count"]
            
            if date in summary["daily_data"]:
                summary["daily_data"][date][level] = count
                summary["daily_data"][date]["total"] += count
    
    # Calculate percentages
    if summary["total_logs"] > 0:
        for level, count in summary["by_level"].items():
            summary["by_level"][f"{level}_percent"] = round((count / summary["total_logs"]) * 100, 1)
    
    # Get top anomalous logs
    anomalous_logs = await app.mongodb.logs.find({
        "organizationId": org_object_id,
        "isAnomalous": True,
        "timestamp": {"$gte": start_date, "$lte": end_date}
    }).sort("anomalyScore", -1).limit(5).to_list(5)
    
    # Convert ObjectId to string
    for log in anomalous_logs:
        log["_id"] = str(log["_id"])
        if "organizationId" in log and log["organizationId"]:
            log["organizationId"] = str(log["organizationId"])
        if "deviceId" in log and log["deviceId"]:
            log["deviceId"] = str(log["deviceId"])
        if "userId" in log and log["userId"]:
            log["userId"] = str(log["userId"])
        if "relatedThreatId" in log and log["relatedThreatId"]:
            log["relatedThreatId"] = str(log["relatedThreatId"])
    
    summary["top_anomalies"] = anomalous_logs
    
    return summary