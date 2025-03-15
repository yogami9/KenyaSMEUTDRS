"""
Network Traffic API Routes
This module contains API endpoints for managing network traffic data.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId
from pydantic import BaseModel, Field
from main import get_current_user, app

router = APIRouter(prefix="/network-traffic", tags=["Network Traffic"])

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


class NetworkTrafficBase(BaseModel):
    timeWindow: str
    startTime: datetime
    endTime: datetime
    totalPackets: int
    totalBytes: int
    inboundBytes: int
    outboundBytes: int
    protocolSummary: Dict[str, int]
    portSummary: Dict[str, int]
    topSourceIps: List[Dict[str, Any]]
    topDestinationIps: List[Dict[str, Any]]
    anomalyScore: Optional[float] = 0.0


class NetworkTrafficCreate(NetworkTrafficBase):
    organizationId: str
    deviceId: Optional[str] = None


class NetworkTrafficDB(NetworkTrafficBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    deviceId: Optional[PyObjectId] = None
    createdAt: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_network_traffic(
    org_id: Optional[str] = None,
    device_id: Optional[str] = None,
    time_window: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    min_anomaly_score: Optional[float] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of network traffic records with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see traffic in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if device_id:
        query["deviceId"] = ObjectId(device_id)
    
    if time_window:
        query["timeWindow"] = time_window
    
    # Date range query
    if from_date or to_date:
        date_query = {}
        if from_date:
            date_query["$gte"] = from_date
        if to_date:
            date_query["$lte"] = to_date
        
        if date_query:
            query["startTime"] = date_query
    
    if min_anomaly_score is not None:
        query["anomalyScore"] = {"$gte": min_anomaly_score}
    
    # Get network traffic data
    traffic_data = await app.mongodb.networkTraffic.find(query).sort("startTime", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for data in traffic_data:
        data["_id"] = str(data["_id"])
        data["organizationId"] = str(data["organizationId"])
        if "deviceId" in data and data["deviceId"]:
            data["deviceId"] = str(data["deviceId"])
    
    return traffic_data


@router.get("/{traffic_id}", response_model=Dict[str, Any])
async def get_network_traffic_by_id(
    traffic_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single network traffic record by ID."""
    traffic_data = await app.mongodb.networkTraffic.find_one({"_id": ObjectId(traffic_id)})
    if not traffic_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network traffic record with ID {traffic_id} not found"
        )
    
    # Check if user has access to this traffic data
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(traffic_data["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this network traffic data"
        )
    
    # Convert ObjectId to string for JSON serialization
    traffic_data["_id"] = str(traffic_data["_id"])
    traffic_data["organizationId"] = str(traffic_data["organizationId"])
    if "deviceId" in traffic_data and traffic_data["deviceId"]:
        traffic_data["deviceId"] = str(traffic_data["deviceId"])
    
    return traffic_data


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_network_traffic(
    traffic: NetworkTrafficCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new network traffic record."""
    # Check if user has permission to create traffic data in this organization
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != traffic.organizationId):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create network traffic data for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(traffic.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {traffic.organizationId} not found"
        )
    
    # Validate time window
    valid_time_windows = ["5min", "15min", "1hour", "6hour", "24hour"]
    if traffic.timeWindow not in valid_time_windows:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time window. Must be one of: {', '.join(valid_time_windows)}"
        )
    
    # Check device if deviceId is provided
    if traffic.deviceId:
        device = await app.mongodb.devices.find_one({"_id": ObjectId(traffic.deviceId)})
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with ID {traffic.deviceId} not found"
            )
        
        # Check if device belongs to the organization
        if str(device["organizationId"]) != traffic.organizationId:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device does not belong to the specified organization"
            )
    
    # Prepare traffic data
    traffic_data = traffic.dict()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    traffic_data["organizationId"] = ObjectId(traffic.organizationId)
    if traffic.deviceId:
        traffic_data["deviceId"] = ObjectId(traffic.deviceId)
    
    # Add creation timestamp
    traffic_data["createdAt"] = timestamp
    
    # Insert traffic data
    result = await app.mongodb.networkTraffic.insert_one(traffic_data)
    
    # Get the created traffic record
    created_traffic = await app.mongodb.networkTraffic.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_traffic["_id"] = str(created_traffic["_id"])
    created_traffic["organizationId"] = str(created_traffic["organizationId"])
    if "deviceId" in created_traffic and created_traffic["deviceId"]:
        created_traffic["deviceId"] = str(created_traffic["deviceId"])
    
    # If traffic has a high anomaly score, create a log entry
    if traffic.anomalyScore and traffic.anomalyScore > 0.7:
        log_data = {
            "organizationId": ObjectId(traffic.organizationId),
            "deviceId": ObjectId(traffic.deviceId) if traffic.deviceId else None,
            "timestamp": timestamp,
            "source": "network_monitor",
            "eventType": "anomalous_traffic",
            "level": "warning" if traffic.anomalyScore < 0.9 else "critical",
            "message": f"Detected anomalous network traffic pattern (score: {traffic.anomalyScore})",
            "metadata": {
                "trafficId": str(result.inserted_id),
                "anomalyScore": traffic.anomalyScore,
                "timeWindow": traffic.timeWindow,
                "totalBytes": traffic.totalBytes
            },
            "isAnomalous": True,
            "anomalyScore": traffic.anomalyScore
        }
        
        await app.mongodb.logs.insert_one(log_data)
    
    return created_traffic


@router.delete("/{traffic_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_network_traffic(
    traffic_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a network traffic record by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete network traffic records"
        )
    
    # Check if traffic record exists
    existing_traffic = await app.mongodb.networkTraffic.find_one({"_id": ObjectId(traffic_id)})
    if not existing_traffic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network traffic record with ID {traffic_id} not found"
        )
    
    # Delete traffic record
    await app.mongodb.networkTraffic.delete_one({"_id": ObjectId(traffic_id)})
    
    return None


@router.get("/summary/by-organization/{org_id}", response_model=Dict[str, Any])
async def get_traffic_summary_by_organization(
    org_id: str,
    hours: int = Query(24, ge=1, le=168),
    current_user: dict = Depends(get_current_user)
):
    """Get a summary of network traffic for an organization."""
    # Check if user has access to this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access traffic data for this organization"
        )
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(hours=hours)
    
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {
            "organizationId": ObjectId(org_id),
            "startTime": {"$gte": start_date, "$lte": end_date}
        }},
        {"$group": {
            "_id": None,
            "totalTraffic": {"$sum": "$totalBytes"},
            "inboundTraffic": {"$sum": "$inboundBytes"},
            "outboundTraffic": {"$sum": "$outboundBytes"},
            "totalPackets": {"$sum": "$totalPackets"},
            "recordCount": {"$sum": 1},
            "avgAnomalyScore": {"$avg": "$anomalyScore"},
            "maxAnomalyScore": {"$max": "$anomalyScore"}
        }}
    ]
    
    # Run aggregation
    summary_result = await app.mongodb.networkTraffic.aggregate(pipeline).to_list(1)
    
    # Prepare summary
    if summary_result and len(summary_result) > 0:
        summary = summary_result[0]
        summary.pop("_id", None)
        
        # Convert bytes to megabytes
        summary["totalTrafficMB"] = round(summary["totalTraffic"] / (1024 * 1024), 2)
        summary["inboundTrafficMB"] = round(summary["inboundTraffic"] / (1024 * 1024), 2)
        summary["outboundTrafficMB"] = round(summary["outboundTraffic"] / (1024 * 1024), 2)
        
        # Round anomaly scores
        summary["avgAnomalyScore"] = round(summary["avgAnomalyScore"], 3)
        summary["maxAnomalyScore"] = round(summary["maxAnomalyScore"], 3)
    else:
        summary = {
            "totalTraffic": 0,
            "inboundTraffic": 0,
            "outboundTraffic": 0,
            "totalPackets": 0,
            "recordCount": 0,
            "avgAnomalyScore": 0,
            "maxAnomalyScore": 0,
            "totalTrafficMB": 0,
            "inboundTrafficMB": 0,
            "outboundTrafficMB": 0
        }
    
    # Get protocol distribution
    protocol_pipeline = [
        {"$match": {
            "organizationId": ObjectId(org_id),
            "startTime": {"$gte": start_date, "$lte": end_date}
        }},
        {"$project": {
            "protocols": {"$objectToArray": "$protocolSummary"}
        }},
        {"$unwind": "$protocols"},
        {"$group": {
            "_id": "$protocols.k",
            "totalBytes": {"$sum": "$protocols.v"}
        }},
        {"$sort": {"totalBytes": -1}},
        {"$limit": 10}
    ]
    
    protocol_results = await app.mongodb.networkTraffic.aggregate(protocol_pipeline).to_list(10)
    
    protocols = {}
    for protocol in protocol_results:
        protocols[protocol["_id"]] = protocol["totalBytes"]
    
    summary["protocolDistribution"] = protocols
    
    # Get top source IPs
    source_ip_pipeline = [
        {"$match": {
            "organizationId": ObjectId(org_id),
            "startTime": {"$gte": start_date, "$lte": end_date}
        }},
        {"$unwind": "$topSourceIps"},
        {"$group": {
            "_id": "$topSourceIps.ip",
            "totalBytes": {"$sum": "$topSourceIps.bytes"}
        }},
        {"$sort": {"totalBytes": -1}},
        {"$limit": 5}
    ]
    
    source_ip_results = await app.mongodb.networkTraffic.aggregate(source_ip_pipeline).to_list(5)
    
    summary["topSourceIps"] = [{
        "ip": result["_id"],
        "bytes": result["totalBytes"],
        "megabytes": round(result["totalBytes"] / (1024 * 1024), 2)
    } for result in source_ip_results]
    
    # Add time range info
    summary["timeRange"] = {
        "startTime": start_date,
        "endTime": end_date,
        "hours": hours
    }
    
    return summary


@router.get("/anomalies", response_model=List[Dict[str, Any]])
async def get_anomalous_traffic(
    org_id: Optional[str] = None,
    threshold: float = Query(0.7, ge=0, le=1),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    """Get anomalous network traffic records."""
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see traffic in their organization
        org_id = str(current_user["organizationId"])
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(hours=hours)
    
    # Build query
    query = {
        "organizationId": ObjectId(org_id),
        "startTime": {"$gte": start_date, "$lte": end_date},
        "anomalyScore": {"$gte": threshold}
    }
    
    # Get anomalous traffic data
    anomalous_traffic = await app.mongodb.networkTraffic.find(query).sort("anomalyScore", -1).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for data in anomalous_traffic:
        data["_id"] = str(data["_id"])
        data["organizationId"] = str(data["organizationId"])
        if "deviceId" in data and data["deviceId"]:
            data["deviceId"] = str(data["deviceId"])
    
    return anomalous_traffic
