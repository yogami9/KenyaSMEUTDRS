"""
Dashboard Widgets API Routes
This module contains API endpoints for managing dashboard widgets.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field
from main import get_current_user, app

router = APIRouter(prefix="/dashboard-widgets", tags=["Dashboard Widgets"])

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


class PositionModel(BaseModel):
    x: int
    y: int
    width: int
    height: int


class WidgetBase(BaseModel):
    widgetType: str
    position: PositionModel
    configuration: Dict[str, Any] = {}
    isVisible: bool = True


class WidgetCreate(WidgetBase):
    organizationId: str
    userId: str


class WidgetUpdate(BaseModel):
    widgetType: Optional[str] = None
    position: Optional[PositionModel] = None
    configuration: Optional[Dict[str, Any]] = None
    isVisible: Optional[bool] = None


class WidgetDB(WidgetBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    userId: PyObjectId
    createdAt: datetime
    updatedAt: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_dashboard_widgets(
    org_id: Optional[str] = None,
    user_id: Optional[str] = None,
    widget_type: Optional[str] = None,
    visible_only: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of dashboard widgets with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see widgets in their organization
        org_id = str(current_user["organizationId"])
    
    # Determine user ID based on query parameters
    if not user_id:
        user_id = str(current_user["_id"])
    else:
        # If user_id is provided and not for current user, check permissions
        if user_id != str(current_user["_id"]) and current_user["role"] not in ["admin", "manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access other users' dashboard widgets"
            )
    
    # Build query
    query = {
        "organizationId": ObjectId(org_id),
        "userId": ObjectId(user_id)
    }
    
    if widget_type:
        query["widgetType"] = widget_type
    
    if visible_only:
        query["isVisible"] = True
    
    # Get widgets
    widgets = await app.mongodb.dashboardWidgets.find(query).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for widget in widgets:
        widget["_id"] = str(widget["_id"])
        widget["organizationId"] = str(widget["organizationId"])
        widget["userId"] = str(widget["userId"])
    
    return widgets


@router.get("/{widget_id}", response_model=Dict[str, Any])
async def get_dashboard_widget(
    widget_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single dashboard widget by ID."""
    widget = await app.mongodb.dashboardWidgets.find_one({"_id": ObjectId(widget_id)})
    if not widget:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dashboard widget with ID {widget_id} not found"
        )
    
    # Check if user has access to this widget
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(widget["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this dashboard widget"
        )
    
    # If not admin or manager, check if widget belongs to the user
    if current_user["role"] not in ["admin", "manager"] and str(current_user["_id"]) != str(widget["userId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access other users' dashboard widgets"
        )
    
    # Convert ObjectId to string for JSON serialization
    widget["_id"] = str(widget["_id"])
    widget["organizationId"] = str(widget["organizationId"])
    widget["userId"] = str(widget["userId"])
    
    return widget


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_dashboard_widget(
    widget: WidgetCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new dashboard widget."""
    # Check if user has permission to create widgets in this organization
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != widget.organizationId:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create widgets for this organization"
        )
    
    # If userId is not for current user, check permissions
    if widget.userId != str(current_user["_id"]) and current_user["role"] not in ["admin", "manager"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create widgets for other users"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(widget.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {widget.organizationId} not found"
        )
    
    # Check if user exists
    user = await app.mongodb.users.find_one({"_id": ObjectId(widget.userId)})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {widget.userId} not found"
        )
    
    # Validate widget type
    valid_widget_types = ["threatSummary", "vulnerabilityStatus", "securityScore", "activityTimeline", 
                        "deviceStatus", "networkTraffic", "topThreats", "complianceStatus"]
    if widget.widgetType not in valid_widget_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid widget type. Must be one of: {', '.join(valid_widget_types)}"
        )
    
    # Validate position coordinates
    if widget.position.x < 0 or widget.position.y < 0 or widget.position.width < 1 or widget.position.height < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid position coordinates. Must be non-negative and have positive dimensions."
        )
    
    # Prepare widget data
    widget_data = widget.dict()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    widget_data["organizationId"] = ObjectId(widget.organizationId)
    widget_data["userId"] = ObjectId(widget.userId)
    
    # Add additional fields
    widget_data.update({
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert widget
    result = await app.mongodb.dashboardWidgets.insert_one(widget_data)
    
    # Get the created widget
    created_widget = await app.mongodb.dashboardWidgets.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_widget["_id"] = str(created_widget["_id"])
    created_widget["organizationId"] = str(created_widget["organizationId"])
    created_widget["userId"] = str(created_widget["userId"])
    
    return created_widget


@router.put("/{widget_id}", response_model=Dict[str, Any])
async def update_dashboard_widget(
    widget_id: str,
    widget_update: WidgetUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a dashboard widget by ID."""
    # Check if widget exists
    existing_widget = await app.mongodb.dashboardWidgets.find_one({"_id": ObjectId(widget_id)})
    if not existing_widget:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dashboard widget with ID {widget_id} not found"
        )
    
    # Check if user has permission to update this widget
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_widget["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this dashboard widget"
        )
    
    # If not admin or manager, check if widget belongs to the user
    if current_user["role"] not in ["admin", "manager"] and str(current_user["_id"]) != str(existing_widget["userId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update other users' dashboard widgets"
        )
    
    # Validate widget type if provided
    if widget_update.widgetType:
        valid_widget_types = ["threatSummary", "vulnerabilityStatus", "securityScore", "activityTimeline", 
                            "deviceStatus", "networkTraffic", "topThreats", "complianceStatus"]
        if widget_update.widgetType not in valid_widget_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid widget type. Must be one of: {', '.join(valid_widget_types)}"
            )
    
    # Validate position coordinates if provided
    if widget_update.position:
        if widget_update.position.x < 0 or widget_update.position.y < 0 or widget_update.position.width < 1 or widget_update.position.height < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid position coordinates. Must be non-negative and have positive dimensions."
            )
    
    # Prepare update data
    update_data = {k: v for k, v in widget_update.dict().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Update widget
    await app.mongodb.dashboardWidgets.update_one(
        {"_id": ObjectId(widget_id)},
        {"$set": update_data}
    )
    
    # Get updated widget
    updated_widget = await app.mongodb.dashboardWidgets.find_one({"_id": ObjectId(widget_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_widget["_id"] = str(updated_widget["_id"])
    updated_widget["organizationId"] = str(updated_widget["organizationId"])
    updated_widget["userId"] = str(updated_widget["userId"])
    
    return updated_widget


@router.delete("/{widget_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dashboard_widget(
    widget_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a dashboard widget by ID."""
    # Check if widget exists
    existing_widget = await app.mongodb.dashboardWidgets.find_one({"_id": ObjectId(widget_id)})
    if not existing_widget:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dashboard widget with ID {widget_id} not found"
        )
    
    # Check if user has permission to delete this widget
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_widget["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this dashboard widget"
        )
    
    # If not admin or manager, check if widget belongs to the user
    if current_user["role"] not in ["admin", "manager"] and str(current_user["_id"]) != str(existing_widget["userId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete other users' dashboard widgets"
        )
    
    # Delete widget
    await app.mongodb.dashboardWidgets.delete_one({"_id": ObjectId(widget_id)})
    
    return None


@router.post("/layout", response_model=Dict[str, str], status_code=status.HTTP_200_OK)
async def update_user_dashboard_layout(
    layout: List[Dict[str, Any]],
    current_user: dict = Depends(get_current_user)
):
    """Update multiple dashboard widgets' positions at once (for drag-and-drop layouts)."""
    if not layout or len(layout) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Layout data is required"
        )
    
    # Process each widget in the layout
    for widget_data in layout:
        # Ensure required fields are present
        if "id" not in widget_data or "position" not in widget_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Each layout item must include 'id' and 'position'"
            )
        
        # Get widget
        widget_id = widget_data["id"]
        try:
            widget = await app.mongodb.dashboardWidgets.find_one({"_id": ObjectId(widget_id)})
        except:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid widget ID: {widget_id}"
            )
        
        if not widget:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Dashboard widget with ID {widget_id} not found"
            )
        
        # Check permissions
        if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(widget["organizationId"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not authorized to update widget with ID {widget_id}"
            )
        
        if current_user["role"] not in ["admin", "manager"] and str(current_user["_id"]) != str(widget["userId"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not authorized to update widget with ID {widget_id}"
            )
        
        # Validate position
        position = widget_data["position"]
        if not isinstance(position, dict) or not all(k in position for k in ["x", "y", "width", "height"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Position must include x, y, width, and height"
            )
        
        if any(v < 0 for v in [position["x"], position["y"]]) or any(v < 1 for v in [position["width"], position["height"]]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid position values"
            )
        
        # Update widget position
        await app.mongodb.dashboardWidgets.update_one(
            {"_id": ObjectId(widget_id)},
            {"$set": {
                "position": position,
                "updatedAt": datetime.now()
            }}
        )
    
    return {"message": f"Successfully updated layout for {len(layout)} widgets"}


@router.get("/defaults/{widget_type}", response_model=Dict[str, Any])
async def get_default_widget_configuration(
    widget_type: str,
    current_user: dict = Depends(get_current_user)
):
    """Get default configuration for a specific widget type."""
    # Validate widget type
    valid_widget_types = ["threatSummary", "vulnerabilityStatus", "securityScore", "activityTimeline", 
                        "deviceStatus", "networkTraffic", "topThreats", "complianceStatus"]
    if widget_type not in valid_widget_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid widget type. Must be one of: {', '.join(valid_widget_types)}"
        )
    
    # Default configurations for each widget type
    default_configs = {
        "threatSummary": {
            "title": "Threat Summary",
            "timeRange": "7d",
            "showResolved": True,
            "severityFilter": "all",
            "position": {"x": 0, "y": 0, "width": 6, "height": 4}
        },
        "vulnerabilityStatus": {
            "title": "Vulnerability Status",
            "timeRange": "30d",
            "showPatched": False,
            "severityFilter": "all",
            "position": {"x": 6, "y": 0, "width": 6, "height": 4}
        },
        "securityScore": {
            "title": "Security Score",
            "showHistory": True,
            "historyPeriod": "90d",
            "position": {"x": 0, "y": 4, "width": 4, "height": 4}
        },
        "activityTimeline": {
            "title": "Activity Timeline",
            "timeRange": "24h",
            "eventTypes": ["threat", "vulnerability", "login", "system"],
            "maxEvents": 10,
            "position": {"x": 4, "y": 4, "width": 8, "height": 4}
        },
        "deviceStatus": {
            "title": "Device Status",
            "deviceTypes": ["all"],
            "statusFilter": "all",
            "showOffline": True,
            "position": {"x": 0, "y": 8, "width": 6, "height": 4}
        },
        "networkTraffic": {
            "title": "Network Traffic",
            "timeRange": "24h",
            "showProtocols": True,
            "showAnomalies": True,
            "position": {"x": 6, "y": 8, "width": 6, "height": 4}
        },
        "topThreats": {
            "title": "Top Threats",
            "timeRange": "7d",
            "maxThreats": 5,
            "sortBy": "severity",
            "position": {"x": 0, "y": 12, "width": 6, "height": 4}
        },
        "complianceStatus": {
            "title": "Compliance Status",
            "frameworks": ["all"],
            "showDetails": True,
            "position": {"x": 6, "y": 12, "width": 6, "height": 4}
        }
    }
    
    return default_configs[widget_type]