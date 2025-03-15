"""
Training Data API Routes
This module contains API endpoints for managing training data for AI models.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, ConfigDict
from main import get_current_user, app, PyObjectId

router = APIRouter(prefix="/training-data", tags=["Training Data"])

# Pydantic models
class DataSplitsModel(BaseModel):
    training: float
    validation: float
    testing: float


class TrainingDataBase(BaseModel):
    dataType: str
    description: Optional[str] = None
    sourceOrganizations: Optional[List[str]] = None
    dataFormat: Optional[str] = None
    features: Optional[List[str]] = None
    samples: Optional[int] = None
    labelled: bool = False
    dataSplits: Optional[DataSplitsModel] = None
    preprocessingSteps: Optional[List[str]] = None
    status: str
    storageLocation: Optional[str] = None


class TrainingDataCreate(TrainingDataBase):
    pass


class TrainingDataUpdate(BaseModel):
    description: Optional[str] = None
    sourceOrganizations: Optional[List[str]] = None
    dataFormat: Optional[str] = None
    features: Optional[List[str]] = None
    samples: Optional[int] = None
    labelled: Optional[bool] = None
    dataSplits: Optional[DataSplitsModel] = None
    preprocessingSteps: Optional[List[str]] = None
    status: Optional[str] = None
    storageLocation: Optional[str] = None


class TrainingDataDB(TrainingDataBase):
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
async def get_training_data(
    data_type: Optional[str] = None,
    status: Optional[str] = None,
    labelled: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of training datasets with optional filtering.
    Admin or analyst role required.
    """
    # Check if user has permission
    if current_user["role"] not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin and analyst users can access training data"
        )
    
    # Build query
    query = {}
    
    if data_type:
        query["dataType"] = data_type
    
    if status:
        query["status"] = status
    
    if labelled is not None:
        query["labelled"] = labelled
    
    # Get training data
    training_data = await app.mongodb.trainingData.find(query).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for data in training_data:
        data["_id"] = str(data["_id"])
        if "sourceOrganizations" in data and data["sourceOrganizations"]:
            data["sourceOrganizations"] = [str(org_id) for org_id in data["sourceOrganizations"]]
    
    return training_data


@router.get("/{data_id}", response_model=Dict[str, Any])
async def get_training_data_by_id(
    data_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single training dataset by ID. Admin or analyst role required."""
    # Check if user has permission
    if current_user["role"] not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin and analyst users can access training data"
        )
    
    # Get training data
    training_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    if not training_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Training dataset with ID {data_id} not found"
        )
    
    # Convert ObjectId to string for JSON serialization
    training_data["_id"] = str(training_data["_id"])
    if "sourceOrganizations" in training_data and training_data["sourceOrganizations"]:
        training_data["sourceOrganizations"] = [str(org_id) for org_id in training_data["sourceOrganizations"]]
    
    return training_data


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_training_data(
    training_data: TrainingDataCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new training dataset. Admin role required."""
    # Check if user has permission
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can create training datasets"
        )
    
    # Validate data type
    valid_data_types = ["traffic", "logs", "threats", "behaviors"]
    if training_data.dataType not in valid_data_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid data type. Must be one of: {', '.join(valid_data_types)}"
        )
    
    # Validate status
    valid_statuses = ["collecting", "preprocessing", "ready", "in_use", "archived"]
    if training_data.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Validate data splits if provided
    if training_data.dataSplits:
        splits_sum = training_data.dataSplits.training + training_data.dataSplits.validation + training_data.dataSplits.testing
        if not 0.99 <= splits_sum <= 1.01:  # Allow some floating point error
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data splits must sum to 1.0"
            )
    
    # Prepare training data
    data_dict = training_data.model_dump()
    timestamp = datetime.now()
    
    # Convert source organizations to ObjectIds if provided
    if training_data.sourceOrganizations:
        source_orgs = []
        for org_id in training_data.sourceOrganizations:
            # Check if organization exists
            organization = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
            if not organization:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Organization with ID {org_id} not found"
                )
            source_orgs.append(ObjectId(org_id))
        data_dict["sourceOrganizations"] = source_orgs
    
    # Add additional fields
    data_dict.update({
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert training data
    result = await app.mongodb.trainingData.insert_one(data_dict)
    
    # Get the created training data
    created_data = await app.mongodb.trainingData.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_data["_id"] = str(created_data["_id"])
    if "sourceOrganizations" in created_data and created_data["sourceOrganizations"]:
        created_data["sourceOrganizations"] = [str(org_id) for org_id in created_data["sourceOrganizations"]]
    
    return created_data


@router.put("/{data_id}", response_model=Dict[str, Any])
async def update_training_data(
    data_id: str,
    training_data_update: TrainingDataUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a training dataset by ID. Admin role required."""
    # Check if user has permission
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can update training datasets"
        )
    
    # Check if training data exists
    existing_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    if not existing_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Training dataset with ID {data_id} not found"
        )
    
    # Validate status if provided
    if training_data_update.status:
        valid_statuses = ["collecting", "preprocessing", "ready", "in_use", "archived"]
        if training_data_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # Validate data splits if provided
    if training_data_update.dataSplits:
        splits_sum = training_data_update.dataSplits.training + training_data_update.dataSplits.validation + training_data_update.dataSplits.testing
        if not 0.99 <= splits_sum <= 1.01:  # Allow some floating point error
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data splits must sum to 1.0"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in training_data_update.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Convert source organizations to ObjectIds if provided
    if training_data_update.sourceOrganizations:
        source_orgs = []
        for org_id in training_data_update.sourceOrganizations:
            # Check if organization exists
            organization = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
            if not organization:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Organization with ID {org_id} not found"
                )
            source_orgs.append(ObjectId(org_id))
        update_data["sourceOrganizations"] = source_orgs
    
    # Update training data
    await app.mongodb.trainingData.update_one(
        {"_id": ObjectId(data_id)},
        {"$set": update_data}
    )
    
    # Get updated training data
    updated_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_data["_id"] = str(updated_data["_id"])
    if "sourceOrganizations" in updated_data and updated_data["sourceOrganizations"]:
        updated_data["sourceOrganizations"] = [str(org_id) for org_id in updated_data["sourceOrganizations"]]
    
    return updated_data


@router.delete("/{data_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_training_data(
    data_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a training dataset by ID. Admin role required."""
    # Check if user has permission
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can delete training datasets"
        )
    
    # Check if training data exists
    existing_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    if not existing_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Training dataset with ID {data_id} not found"
        )
    
    # Check if dataset is in use
    if existing_data["status"] == "in_use":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a dataset that is currently in use by AI models"
        )
    
    # Delete training data
    await app.mongodb.trainingData.delete_one({"_id": ObjectId(data_id)})
    
    return None


@router.patch("/{data_id}/status/{new_status}", response_model=Dict[str, Any])
async def update_training_data_status(
    data_id: str,
    new_status: str,
    current_user: dict = Depends(get_current_user)
):
    """Update a training dataset's status. Admin or analyst role required."""
    # Check if user has permission
    if current_user["role"] not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin and analyst users can update training dataset status"
        )
    
    # Check if training data exists
    existing_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    if not existing_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Training dataset with ID {data_id} not found"
        )
    
    # Validate status
    valid_statuses = ["collecting", "preprocessing", "ready", "in_use", "archived"]
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Validate status transitions
    current_status = existing_data["status"]
    valid_transitions = {
        "collecting": ["preprocessing", "archived"],
        "preprocessing": ["ready", "collecting", "archived"],
        "ready": ["in_use", "preprocessing", "archived"],
        "in_use": ["ready", "archived"],
        "archived": ["collecting"]
    }
    
    if new_status not in valid_transitions[current_status]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status transition from {current_status} to {new_status}"
        )
    
    # Update status
    await app.mongodb.trainingData.update_one(
        {"_id": ObjectId(data_id)},
        {"$set": {
            "status": new_status,
            "updatedAt": datetime.now()
        }}
    )
    
    # Get updated training data
    updated_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_data["_id"] = str(updated_data["_id"])
    if "sourceOrganizations" in updated_data and updated_data["sourceOrganizations"]:
        updated_data["sourceOrganizations"] = [str(org_id) for org_id in updated_data["sourceOrganizations"]]
    
    return updated_data


@router.get("/by-type/{data_type}", response_model=List[Dict[str, Any]])
async def get_training_data_by_type(
    data_type: str,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get training datasets by data type. Admin or analyst role required."""
    # Check if user has permission
    if current_user["role"] not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin and analyst users can access training data"
        )
    
    # Validate data type
    valid_data_types = ["traffic", "logs", "threats", "behaviors"]
    if data_type not in valid_data_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid data type. Must be one of: {', '.join(valid_data_types)}"
        )
    
    # Build query
    query = {"dataType": data_type}
    
    if status:
        valid_statuses = ["collecting", "preprocessing", "ready", "in_use", "archived"]
        if status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        query["status"] = status
    
    # Get training data
    training_data = await app.mongodb.trainingData.find(query).sort("updatedAt", -1).to_list(1000)
    
    # Convert ObjectId to string for JSON serialization
    for data in training_data:
        data["_id"] = str(data["_id"])
        if "sourceOrganizations" in data and data["sourceOrganizations"]:
            data["sourceOrganizations"] = [str(org_id) for org_id in data["sourceOrganizations"]]
    
    return training_data


@router.post("/{data_id}/add-sources", response_model=Dict[str, Any])
async def add_source_organizations(
    data_id: str,
    organization_ids: List[str],
    current_user: dict = Depends(get_current_user)
):
    """Add source organizations to a training dataset. Admin role required."""
    # Check if user has permission
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can modify training dataset sources"
        )
    
    # Check if training data exists
    existing_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    if not existing_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Training dataset with ID {data_id} not found"
        )
    
    # Validate organization IDs
    org_ids = []
    for org_id in organization_ids:
        # Check if organization exists
        organization = await app.mongodb.organizations.find_one({"_id": ObjectId(org_id)})
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization with ID {org_id} not found"
            )
        org_ids.append(ObjectId(org_id))
    
    # Get current source organizations
    current_sources = existing_data.get("sourceOrganizations", [])
    
    # Combine current and new sources without duplicates
    new_sources = list(set(current_sources + org_ids))
    
    # Update training data
    await app.mongodb.trainingData.update_one(
        {"_id": ObjectId(data_id)},
        {"$set": {
            "sourceOrganizations": new_sources,
            "updatedAt": datetime.now()
        }}
    )
    
    # Get updated training data
    updated_data = await app.mongodb.trainingData.find_one({"_id": ObjectId(data_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_data["_id"] = str(updated_data["_id"])
    if "sourceOrganizations" in updated_data and updated_data["sourceOrganizations"]:
        updated_data["sourceOrganizations"] = [str(org_id) for org_id in updated_data["sourceOrganizations"]]
    
    return updated_data