"""
Network Traffic API Routes
This module contains API endpoints for managing network traffic data.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, status, Query, Request
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime, timedelta
from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel, Field, model_validator, field_validator, ConfigDict
from main import get_current_user, app, PyObjectId

# Configure module logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-traffic", tags=["Network Traffic"])

# Pydantic models
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
    
    # Validate time window values
    @field_validator('timeWindow')
    @classmethod
    def validate_time_window(cls, v):
        valid_windows = ["5min", "15min", "1hour", "6hour", "24hour"]
        if v not in valid_windows:
            raise ValueError(f"Time window must be one of: {', '.join(valid_windows)}")
        return v
    
    # Validate that end time is after start time
    @model_validator(mode='after')
    def validate_times(self):
        if self.endTime <= self.startTime:
            raise ValueError("End time must be after start time")
        return self


class NetworkTrafficCreate(NetworkTrafficBase):
    organizationId: str
    deviceId: Optional[str] = None
    
    # Validate ObjectId format for IDs
    @field_validator('organizationId', 'deviceId')
    @classmethod
    def validate_object_id(cls, v, info):
        if v is None and info.field_name == 'deviceId':
            return None  # deviceId is optional
        if not ObjectId.is_valid(v):
            raise ValueError(f"Invalid {info.field_name} format. Must be a valid ObjectId.")
        return v


class NetworkTrafficDB(NetworkTrafficBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    deviceId: Optional[PyObjectId] = None
    createdAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Helper functions
def validate_object_id(id_str: str, param_name: str) -> ObjectId:
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


def serialize_object_ids(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert ObjectId values to strings for JSON serialization."""
    if "_id" in data:
        data["_id"] = str(data["_id"])
    if "organizationId" in data and data["organizationId"]:
        data["organizationId"] = str(data["organizationId"])
    if "deviceId" in data and data["deviceId"]:
        data["deviceId"] = str(data["deviceId"])
    return data


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_network_traffic(
    request: Request,
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
    query = {"organizationId": validate_object_id(org_id, "org_id")}
    
    if device_id:
        query["deviceId"] = validate_object_id(device_id, "device_id")
    
    if time_window:
        valid_time_windows = ["5min", "15min", "1hour", "6hour", "24hour"]
        if time_window not in valid_time_windows:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid time window. Must be one of: {', '.join(valid_time_windows)}"
            )
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
        if min_anomaly_score < 0 or min_anomaly_score > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anomaly score must be between 0 and 1"
            )
        query["anomalyScore"] = {"$gte": min_anomaly_score}
    
    try:
        # Get network traffic data
        traffic_data = await app.mongodb.networkTraffic.find(query).sort("startTime", -1).skip(skip).limit(limit).to_list(limit)
        
        # Convert ObjectId to string for JSON serialization
        for data in traffic_data:
            serialize_object_ids(data)
        
        logger.info(f"Retrieved {len(traffic_data)} network traffic records for org {org_id}")
        return traffic_data
        
    except Exception as e:
        logger.error(f"Error retrieving network traffic: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving network traffic data: {str(e)}"
        )


@router.get("/{traffic_id}", response_model=Dict[str, Any])
async def get_network_traffic_by_id(
    traffic_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single network traffic record by ID."""
    try:
        # Validate ObjectId format
        object_id = validate_object_id(traffic_id, "traffic_id")
        
        # Get the traffic record
        traffic_data = await app.mongodb.networkTraffic.find_one({"_id": object_id})
        
        if not traffic_data:
            logger.warning(f"Network traffic ID {traffic_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Network traffic record with ID {traffic_id} not found"
            )
        
        # Check if user has access to this traffic data
        if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(traffic_data["organizationId"]):
            logger.warning(f"User {current_user['email']} attempted unauthorized access to traffic {traffic_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this network traffic data"
            )
        
        # Convert ObjectId to string for JSON serialization
        serialize_object_ids(traffic_data)
        
        return traffic_data
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except InvalidId:
        logger.warning(f"Invalid traffic ID format: {traffic_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid traffic ID format: {traffic_id}. Must be a valid ObjectId."
        )
        
    except Exception as e:
        logger.error(f"Error retrieving network traffic {traffic_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving network traffic data: {str(e)}"
        )


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_network_traffic(
    traffic: NetworkTrafficCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new network traffic record."""
    try:
        # Check if user has permission to create traffic data in this organization
        if current_user["role"] not in ["admin", "manager", "analyst"] or \
           (current_user["role"] != "admin" and str(current_user["organizationId"]) != traffic.organizationId):
            logger.warning(f"User {current_user['email']} attempted unauthorized traffic creation for org {traffic.organizationId}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create network traffic data for this organization"
            )
        
        # Check if organization exists
        organization = await app.mongodb.organizations.find_one({"_id": ObjectId(traffic.organizationId)})
        if not organization:
            logger.warning(f"Organization {traffic.organizationId} not found during traffic creation")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization with ID {traffic.organizationId} not found"
            )
        
        # Check device if deviceId is provided
        if traffic.deviceId:
            device = await app.mongodb.devices.find_one({"_id": ObjectId(traffic.deviceId)})
            if not device:
                logger.warning(f"Device {traffic.deviceId} not found during traffic creation")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Device with ID {traffic.deviceId} not found"
                )
            
            # Check if device belongs to the organization
            if str(device["organizationId"]) != traffic.organizationId:
                logger.warning(f"Device {traffic.deviceId} does not belong to organization {traffic.organizationId}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Device does not belong to the specified organization"
                )
        
        # Prepare traffic data
        traffic_data = traffic.model_dump()
        timestamp = datetime.now()
        
        # Convert string IDs to ObjectIds
        traffic_data["organizationId"] = ObjectId(traffic.organizationId)
        if traffic.deviceId:
            traffic_data["deviceId"] = ObjectId(traffic.deviceId)
        
        # Add creation timestamp
        traffic_data["createdAt"] = timestamp
        
        # Validate anomaly score
        if "anomalyScore" in traffic_data and (traffic_data["anomalyScore"] < 0 or traffic_data["anomalyScore"] > 1):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Anomaly score must be between 0 and 1"
            )
        
        # Insert traffic data
        result = await app.mongodb.networkTraffic.insert_one(traffic_data)
        
        # Get the created traffic record
        created_traffic = await app.mongodb.networkTraffic.find_one({"_id": result.inserted_id})
        
        # Convert ObjectId to string for JSON serialization
        serialize_object_ids(created_traffic)
        
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
            logger.warning(f"Created anomalous traffic alert with score {traffic.anomalyScore}")
        
        logger.info(f"Created network traffic record {result.inserted_id}")
        return created_traffic
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except Exception as e:
        logger.error(f"Error creating network traffic: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating network traffic record: {str(e)}"
        )


@router.delete("/{traffic_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_network_traffic(
    traffic_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a network traffic record by ID (admin only)."""
    try:
        # Verify admin role
        if current_user["role"] != "admin":
            logger.warning(f"Non-admin user {current_user['email']} attempted to delete traffic {traffic_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin users can delete network traffic records"
            )
        
        # Validate ObjectId format
        object_id = validate_object_id(traffic_id, "traffic_id")
        
        # Check if traffic record exists
        existing_traffic = await app.mongodb.networkTraffic.find_one({"_id": object_id})
        if not existing_traffic:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Network traffic record with ID {traffic_id} not found"
            )
        
        # Delete traffic record
        result = await app.mongodb.networkTraffic.delete_one({"_id": object_id})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Network traffic record with ID {traffic_id} not found"
            )
        
        logger.info(f"Admin {current_user['email']} deleted network traffic {traffic_id}")
        return None
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except InvalidId:
        logger.warning(f"Invalid traffic ID format in delete: {traffic_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid traffic ID format: {traffic_id}. Must be a valid ObjectId."
        )
        
    except Exception as e:
        logger.error(f"Error deleting network traffic {traffic_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting network traffic record: {str(e)}"
        )


@router.get("/summary/by-organization/{org_id}", response_model=Dict[str, Any])
async def get_traffic_summary_by_organization(
    org_id: str,
    hours: int = Query(24, ge=1, le=168),
    current_user: dict = Depends(get_current_user)
):
    """Get a summary of network traffic for an organization."""
    try:
        # Validate ObjectId format
        object_id = validate_object_id(org_id, "org_id")
        
        # Check if user has access to this organization
        if current_user["role"] != "admin" and str(current_user["organizationId"]) != org_id:
            logger.warning(f"User {current_user['email']} attempted unauthorized access to org summary {org_id}")
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
                "organizationId": object_id,
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
                "organizationId": object_id,
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
                "organizationId": object_id,
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
        
        logger.info(f"Generated traffic summary for org {org_id} over {hours} hours")
        return summary
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except InvalidId:
        logger.warning(f"Invalid org ID format in summary: {org_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid organization ID format: {org_id}. Must be a valid ObjectId."
        )
        
    except Exception as e:
        logger.error(f"Error generating traffic summary for org {org_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating traffic summary: {str(e)}"
        )


@router.get("/anomalies", response_model=List[Dict[str, Any]])
async def get_anomalous_traffic(
    org_id: Optional[str] = None,
    threshold: float = Query(0.7, ge=0, le=1),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    """Get anomalous network traffic records."""
    try:
        # Determine organization ID based on user role
        if current_user["role"] != "admin" or not org_id:
            # Non-admin users can only see traffic in their organization
            org_id = str(current_user["organizationId"])
        
        # Validate ObjectId format
        object_id = validate_object_id(org_id, "org_id")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(hours=hours)
        
        # Build query
        query = {
            "organizationId": object_id,
            "startTime": {"$gte": start_date, "$lte": end_date},
            "anomalyScore": {"$gte": threshold}
        }
        
        # Get anomalous traffic data
        anomalous_traffic = await app.mongodb.networkTraffic.find(query).sort("anomalyScore", -1).limit(limit).to_list(limit)
        
        # Convert ObjectId to string for JSON serialization
        for data in anomalous_traffic:
            serialize_object_ids(data)
        
        logger.info(f"Retrieved {len(anomalous_traffic)} anomalous traffic records for org {org_id}")
        return anomalous_traffic
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except InvalidId:
        logger.warning(f"Invalid org ID format in anomalies: {org_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid organization ID format: {org_id}. Must be a valid ObjectId."
        )
        
    except Exception as e:
        logger.error(f"Error retrieving anomalous traffic for org {org_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving anomalous traffic data: {str(e)}"
        )