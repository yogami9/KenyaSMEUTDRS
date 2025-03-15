"""
AI Models API Routes
This module contains API endpoints for managing AI models for threat detection.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/ai-models", tags=["AI Models"])

# Pydantic models
class AIModelBase(BaseModel):
    name: str
    type: str
    version: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    trainingMetrics: Optional[Dict[str, Any]] = None
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1Score: Optional[float] = None
    falsePositiveRate: Optional[float] = None
    trainedOn: Optional[datetime] = None
    status: str
    threatTypesDetected: Optional[List[str]] = None


class AIModelCreate(AIModelBase):
    pass


class AIModelUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    trainingMetrics: Optional[Dict[str, Any]] = None
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1Score: Optional[float] = None
    falsePositiveRate: Optional[float] = None
    trainedOn: Optional[datetime] = None
    status: Optional[str] = None
    threatTypesDetected: Optional[List[str]] = None


class AIModelDB(AIModelBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_ai_models(
    model_type: Optional[str] = None,
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    min_accuracy: Optional[float] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of AI models with optional filtering.
    """
    # Build query
    query = {}
    
    if model_type:
        query["type"] = model_type
    
    if status:
        query["status"] = status
    
    if threat_type:
        query["threatTypesDetected"] = threat_type
    
    if min_accuracy is not None:
        query["accuracy"] = {"$gte": min_accuracy}
    
    # Get AI models
    models = await app.mongodb.aiModels.find(query).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for model in models:
        model["_id"] = str(model["_id"])
    
    return models


@router.get("/{model_id}", response_model=Dict[str, Any])
async def get_ai_model(
    model_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single AI model by ID."""
    model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI model with ID {model_id} not found"
        )
    
    # Convert ObjectId to string for JSON serialization
    model["_id"] = str(model["_id"])
    
    return model


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_ai_model(
    model: AIModelCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new AI model (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can create AI models"
        )
    
    # Validate model type
    valid_model_types = ["FNN", "CNN", "RNN", "other"]
    if model.type not in valid_model_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid model type. Must be one of: {', '.join(valid_model_types)}"
        )
    
    # Validate status
    valid_statuses = ["training", "active", "deprecated"]
    if model.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Check for duplicate name and version
    existing_model = await app.mongodb.aiModels.find_one({"name": model.name, "version": model.version})
    if existing_model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AI model with name '{model.name}' and version '{model.version}' already exists"
        )
    
    # Prepare model data
    model_data = model.dict()
    timestamp = datetime.now()
    
    # Add additional fields
    model_data.update({
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert model
    result = await app.mongodb.aiModels.insert_one(model_data)
    
    # Get the created model
    created_model = await app.mongodb.aiModels.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_model["_id"] = str(created_model["_id"])
    
    return created_model


@router.put("/{model_id}", response_model=Dict[str, Any])
async def update_ai_model(
    model_id: str,
    model_update: AIModelUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update an AI model by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can update AI models"
        )
    
    # Check if model exists
    existing_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI model with ID {model_id} not found"
        )
    
    # Validate model type if provided
    if model_update.type:
        valid_model_types = ["FNN", "CNN", "RNN", "other"]
        if model_update.type not in valid_model_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid model type. Must be one of: {', '.join(valid_model_types)}"
            )
    
    # Validate status if provided
    if model_update.status:
        valid_statuses = ["training", "active", "deprecated"]
        if model_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in model_update.dict().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Update model
    await app.mongodb.aiModels.update_one(
        {"_id": ObjectId(model_id)},
        {"$set": update_data}
    )
    
    # Get updated model
    updated_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_model["_id"] = str(updated_model["_id"])
    
    return updated_model


@router.delete("/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ai_model(
    model_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete an AI model by ID (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete AI models"
        )
    
    # Check if model exists
    existing_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI model with ID {model_id} not found"
        )
    
    # Check if model is in use by any threats
    model_in_use = await app.mongodb.threats.find_one({"detectionModelId": ObjectId(model_id)})
    if model_in_use:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete model because it is referenced by existing threats"
        )
    
    # Delete model
    await app.mongodb.aiModels.delete_one({"_id": ObjectId(model_id)})
    
    return None


@router.get("/active/by-threat-type/{threat_type}", response_model=Dict[str, Any])
async def get_active_model_for_threat_type(
    threat_type: str,
    current_user: dict = Depends(get_current_user)
):
    """Get the best active AI model for a specific threat type."""
    # Validate threat type
    valid_threat_types = ["malware", "ransomware", "phishing", "ddos", "intrusion", "dataExfiltration", "anomaly", "other"]
    if threat_type not in valid_threat_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid threat type. Must be one of: {', '.join(valid_threat_types)}"
        )
    
    # Find active models for this threat type, sorted by accuracy
    query = {
        "status": "active",
        "threatTypesDetected": threat_type,
        "accuracy": {"$exists": True}
    }
    
    models = await app.mongodb.aiModels.find(query).sort("accuracy", -1).limit(1).to_list(1)
    
    if not models or len(models) == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active AI model found for threat type: {threat_type}"
        )
    
    # Convert ObjectId to string for JSON serialization
    models[0]["_id"] = str(models[0]["_id"])
    
    return models[0]


@router.patch("/{model_id}/deprecate", response_model=Dict[str, Any])
async def deprecate_ai_model(
    model_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark an AI model as deprecated (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can deprecate AI models"
        )
    
    # Check if model exists
    existing_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI model with ID {model_id} not found"
        )
    
    # Check if model is already deprecated
    if existing_model["status"] == "deprecated":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Model is already deprecated"
        )
    
    # Update model status
    await app.mongodb.aiModels.update_one(
        {"_id": ObjectId(model_id)},
        {"$set": {"status": "deprecated", "updatedAt": datetime.now()}}
    )
    
    # Get updated model
    updated_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_model["_id"] = str(updated_model["_id"])
    
    return updated_model


@router.patch("/{model_id}/activate", response_model=Dict[str, Any])
async def activate_ai_model(
    model_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark an AI model as active (admin only)."""
    # Check if user is admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can activate AI models"
        )
    
    # Check if model exists
    existing_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI model with ID {model_id} not found"
        )
    
    # Check if model is already active
    if existing_model["status"] == "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Model is already active"
        )
    
    # Update model status
    await app.mongodb.aiModels.update_one(
        {"_id": ObjectId(model_id)},
        {"$set": {"status": "active", "updatedAt": datetime.now()}}
    )
    
    # Get updated model
    updated_model = await app.mongodb.aiModels.find_one({"_id": ObjectId(model_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_model["_id"] = str(updated_model["_id"])
    
    return updated_model