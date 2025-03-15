
"""
Reports API Routes
This module contains API endpoints for managing security reports.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from bson import ObjectId
from pydantic import BaseModel, Field
from main import get_current_user, app

router = APIRouter(prefix="/reports", tags=["Reports"])

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


class PeriodModel(BaseModel):
    startDate: datetime
    endDate: datetime


class ReportBase(BaseModel):
    reportType: str
    title: str
    description: Optional[str] = None
    period: PeriodModel
    threatsSummary: Optional[Dict[str, Any]] = None
    vulnerabilitiesSummary: Optional[Dict[str, Any]] = None
    complianceStatus: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    sentTo: Optional[List[str]] = None


class ReportCreate(ReportBase):
    organizationId: str


class ReportUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    threatsSummary: Optional[Dict[str, Any]] = None
    vulnerabilitiesSummary: Optional[Dict[str, Any]] = None
    complianceStatus: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    sentTo: Optional[List[str]] = None
    status: Optional[str] = None
    fileUrl: Optional[str] = None


class ReportDB(ReportBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organizationId: PyObjectId
    generatedBy: Optional[PyObjectId] = None
    generatedAt: Optional[datetime] = None
    sentAt: Optional[datetime] = None
    status: str
    fileUrl: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


# Routes
@router.get("/", response_model=List[Dict[str, Any]])
async def get_reports(
    org_id: Optional[str] = None,
    report_type: Optional[str] = None,
    status: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a list of reports with optional filtering.
    """
    # Determine organization ID based on user role
    if current_user["role"] != "admin" or not org_id:
        # Non-admin users can only see reports in their organization
        org_id = str(current_user["organizationId"])
    
    # Build query
    query = {"organizationId": ObjectId(org_id)}
    
    if report_type:
        query["reportType"] = report_type
    
    if status:
        query["status"] = status
    
    # Date range query for generated reports
    if from_date or to_date:
        date_query = {}
        if from_date:
            date_query["$gte"] = from_date
        if to_date:
            date_query["$lte"] = to_date
        
        if date_query:
            query["generatedAt"] = date_query
    
    # Get reports
    reports = await app.mongodb.reports.find(query).sort("createdAt", -1).skip(skip).limit(limit).to_list(limit)
    
    # Convert ObjectId to string for JSON serialization
    for report in reports:
        report["_id"] = str(report["_id"])
        report["organizationId"] = str(report["organizationId"])
        if "generatedBy" in report and report["generatedBy"]:
            report["generatedBy"] = str(report["generatedBy"])
    
    return reports


@router.get("/{report_id}", response_model=Dict[str, Any])
async def get_report(
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a single report by ID."""
    report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID {report_id} not found"
        )
    
    # Check if user has access to this report
    if current_user["role"] != "admin" and str(current_user["organizationId"]) != str(report["organizationId"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this report"
        )
    
    # Convert ObjectId to string for JSON serialization
    report["_id"] = str(report["_id"])
    report["organizationId"] = str(report["organizationId"])
    if "generatedBy" in report and report["generatedBy"]:
        report["generatedBy"] = str(report["generatedBy"])
    
    return report


@router.post("/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_report(
    report: ReportCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new report."""
    # Check if user has permission to create reports in this organization
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != report.organizationId):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create reports for this organization"
        )
    
    # Check if organization exists
    organization = await app.mongodb.organizations.find_one({"_id": ObjectId(report.organizationId)})
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ID {report.organizationId} not found"
        )
    
    # Validate report type
    valid_report_types = ["daily", "weekly", "monthly", "quarterly", "incident", "compliance"]
    if report.reportType not in valid_report_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid report type. Must be one of: {', '.join(valid_report_types)}"
        )
    
    # Prepare report data
    report_data = report.dict()
    timestamp = datetime.now()
    
    # Convert string IDs to ObjectIds
    report_data["organizationId"] = ObjectId(report.organizationId)
    
    # Add additional fields
    report_data.update({
        "generatedBy": current_user["_id"],
        "generatedAt": timestamp,
        "status": "draft",
        "createdAt": timestamp,
        "updatedAt": timestamp
    })
    
    # Insert report
    result = await app.mongodb.reports.insert_one(report_data)
    
    # Get the created report
    created_report = await app.mongodb.reports.find_one({"_id": result.inserted_id})
    
    # Convert ObjectId to string for JSON serialization
    created_report["_id"] = str(created_report["_id"])
    created_report["organizationId"] = str(created_report["organizationId"])
    if "generatedBy" in created_report and created_report["generatedBy"]:
        created_report["generatedBy"] = str(created_report["generatedBy"])
    
    return created_report


@router.put("/{report_id}", response_model=Dict[str, Any])
async def update_report(
    report_id: str,
    report_update: ReportUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a report by ID."""
    # Check if report exists
    existing_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    if not existing_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID {report_id} not found"
        )
    
    # Check if user has permission to update this report
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_report["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this report"
        )
    
    # Validate status if provided
    if report_update.status:
        valid_statuses = ["draft", "generated", "sent", "viewed"]
        if report_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
    
    # Prepare update data
    update_data = {k: v for k, v in report_update.dict().items() if v is not None}
    update_data["updatedAt"] = datetime.now()
    
    # Special handling for status changes
    if report_update.status == "generated" and existing_report["status"] == "draft":
        update_data["generatedAt"] = datetime.now()
    
    if report_update.status == "sent" and existing_report["status"] in ["draft", "generated"]:
        update_data["sentAt"] = datetime.now()
    
    # Update report
    await app.mongodb.reports.update_one(
        {"_id": ObjectId(report_id)},
        {"$set": update_data}
    )
    
    # Get updated report
    updated_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_report["_id"] = str(updated_report["_id"])
    updated_report["organizationId"] = str(updated_report["organizationId"])
    if "generatedBy" in updated_report and updated_report["generatedBy"]:
        updated_report["generatedBy"] = str(updated_report["generatedBy"])
    
    return updated_report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a report by ID."""
    # Check if report exists
    existing_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    if not existing_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID {report_id} not found"
        )
    
    # Check if user has permission to delete this report
    if current_user["role"] not in ["admin", "manager"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_report["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this report"
        )
    
    # Delete report
    await app.mongodb.reports.delete_one({"_id": ObjectId(report_id)})
    
    return None


@router.post("/{report_id}/generate", response_model=Dict[str, Any])
async def generate_report(
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Generate a report by ID (calculate statistics and create report document)."""
    # Check if report exists
    existing_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    if not existing_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID {report_id} not found"
        )
    
    # Check if user has permission to generate this report
    if current_user["role"] not in ["admin", "manager", "analyst"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_report["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to generate this report"
        )
    
    # Check if report is in draft status
    if existing_report["status"] != "draft":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only reports in draft status can be generated"
        )
    
    # Get report period
    start_date = existing_report["period"]["startDate"]
    end_date = existing_report["period"]["endDate"]
    org_id = existing_report["organizationId"]
    
    # Generate threats summary
    threats_summary = await generate_threats_summary(org_id, start_date, end_date)
    
    # Generate vulnerabilities summary
    vulnerabilities_summary = await generate_vulnerabilities_summary(org_id, start_date, end_date)
    
    # Generate compliance status (simplified example)
    compliance_status = {
        "overall_score": 75,
        "last_assessment": datetime.now() - timedelta(days=15),
        "compliant_controls": 32,
        "non_compliant_controls": 8,
        "risk_areas": [
            {"name": "Access Control", "score": 85},
            {"name": "Data Protection", "score": 70},
            {"name": "Incident Response", "score": 90},
            {"name": "Network Security", "score": 65}
        ]
    }
    
    # Generate recommendations based on threats and vulnerabilities
    recommendations = generate_recommendations(threats_summary, vulnerabilities_summary)
    
    # Update the report
    update_data = {
        "threatsSummary": threats_summary,
        "vulnerabilitiesSummary": vulnerabilities_summary,
        "complianceStatus": compliance_status,
        "recommendations": recommendations,
        "status": "generated",
        "generatedAt": datetime.now(),
        "generatedBy": current_user["_id"],
        "updatedAt": datetime.now()
    }
    
    # Update report
    await app.mongodb.reports.update_one(
        {"_id": ObjectId(report_id)},
        {"$set": update_data}
    )
    
    # Get updated report
    updated_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_report["_id"] = str(updated_report["_id"])
    updated_report["organizationId"] = str(updated_report["organizationId"])
    if "generatedBy" in updated_report and updated_report["generatedBy"]:
        updated_report["generatedBy"] = str(updated_report["generatedBy"])
    
    return updated_report


@router.post("/{report_id}/send", response_model=Dict[str, Any])
async def send_report(
    report_id: str,
    recipients: List[str],
    current_user: dict = Depends(get_current_user)
):
    """Mark a report as sent and record the recipients."""
    # Check if report exists
    existing_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    if not existing_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID {report_id} not found"
        )
    
    # Check if user has permission to send this report
    if current_user["role"] not in ["admin", "manager"] or \
       (current_user["role"] != "admin" and str(current_user["organizationId"]) != str(existing_report["organizationId"])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to send this report"
        )
    
    # Check if report is in generated status
    if existing_report["status"] not in ["generated", "draft"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only reports in draft or generated status can be sent"
        )
    
    # Update the report
    timestamp = datetime.now()
    update_data = {
        "status": "sent",
        "sentTo": recipients,
        "sentAt": timestamp,
        "updatedAt": timestamp
    }
    
    # If report was in draft status, also mark it as generated
    if existing_report["status"] == "draft":
        update_data["status"] = "generated"
        update_data["generatedAt"] = timestamp
        update_data["generatedBy"] = current_user["_id"]
    
    # Update report
    await app.mongodb.reports.update_one(
        {"_id": ObjectId(report_id)},
        {"$set": update_data}
    )
    
    # Get updated report
    updated_report = await app.mongodb.reports.find_one({"_id": ObjectId(report_id)})
    
    # Convert ObjectId to string for JSON serialization
    updated_report["_id"] = str(updated_report["_id"])
    updated_report["organizationId"] = str(updated_report["organizationId"])
    if "generatedBy" in updated_report and updated_report["generatedBy"]:
        updated_report["generatedBy"] = str(updated_report["generatedBy"])
    
    return updated_report


# Helper functions
async def generate_threats_summary(org_id, start_date, end_date):
    """Generate a summary of threats for a specific time period."""
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {
            "organizationId": org_id,
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
        {"$sort": {"_id.severity": 1}}
    ]
    
    # Run aggregation
    threat_counts = await app.mongodb.threats.aggregate(pipeline).to_list(1000)
    
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
    for group in threat_counts:
        severity = group["_id"]["severity"]
        status = group["_id"]["status"]
        threat_type = group["_id"]["threatType"]
        count = group["count"]
        
        summary["total"] += count
        
        # Update by_severity counts
        if severity not in summary["by_severity"]:
            summary["by_severity"][severity] = 0
        summary["by_severity"][severity] += count
        
        # Update by_status counts
        summary["by_status"][status] += count
        
        # Update by_type counts
        summary["by_type"][threat_type] += count
    
    # Get time to resolution metrics
    resolution_pipeline = [
        {"$match": {
            "organizationId": org_id,
            "status": "resolved",
            "resolvedAt": {"$exists": True},
            "timestamp": {"$exists": True},
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }},
        {"$project": {
            "resolutionTime": {"$subtract": ["$resolvedAt", "$timestamp"]}
        }},
        {"$group": {
            "_id": None,
            "avgResolutionTime": {"$avg": "$resolutionTime"},
            "maxResolutionTime": {"$max": "$resolutionTime"},
            "minResolutionTime": {"$min": "$resolutionTime"},
            "count": {"$sum": 1}
        }}
    ]
    
    resolution_metrics = await app.mongodb.threats.aggregate(resolution_pipeline).to_list(1)
    
    if resolution_metrics and len(resolution_metrics) > 0:
        # Convert milliseconds to hours
        avg_time_ms = resolution_metrics[0]["avgResolutionTime"]
        max_time_ms = resolution_metrics[0]["maxResolutionTime"]
        min_time_ms = resolution_metrics[0]["minResolutionTime"]
        
        summary["resolution_metrics"] = {
            "avg_hours": round(avg_time_ms / (1000 * 60 * 60), 1),
            "max_hours": round(max_time_ms / (1000 * 60 * 60), 1),
            "min_hours": round(min_time_ms / (1000 * 60 * 60), 1),
            "resolved_count": resolution_metrics[0]["count"]
        }
    else:
        summary["resolution_metrics"] = {
            "avg_hours": 0,
            "max_hours": 0,
            "min_hours": 0,
            "resolved_count": 0
        }
    
    # Add time range info
    summary["time_range"] = {
        "start_date": start_date,
        "end_date": end_date,
        "days": (end_date - start_date).days + 1
    }
    
    return summary


async def generate_vulnerabilities_summary(org_id, start_date, end_date):
    """Generate a summary of vulnerabilities for a specific time period."""
    # Build pipeline for aggregation
    pipeline = [
        {"$match": {
            "organizationId": org_id,
            "discoveredAt": {"$gte": start_date, "$lte": end_date}
        }},
        {"$group": {
            "_id": {
                "severity": "$severity",
                "status": "$status"
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.severity": 1}}
    ]
    
    # Run aggregation
    vuln_counts = await app.mongodb.vulnerabilities.aggregate(pipeline).to_list(1000)
    
    # Process results
    summary = {
        "total": 0,
        "by_severity": {},
        "by_status": {},
        "patch_available": 0,
        "exploit_available": 0
    }
    
    # Initialize by_status counters
    for status in ["open", "in_progress", "patched", "mitigated", "accepted"]:
        summary["by_status"][status] = 0
    
    # Process aggregation results
    for group in vuln_counts:
        severity = group["_id"]["severity"]
        status = group["_id"]["status"]
        count = group["count"]
        
        summary["total"] += count
        
        # Update by_severity counts
        if severity not in summary["by_severity"]:
            summary["by_severity"][severity] = 0
        summary["by_severity"][severity] += count
        
        # Update by_status counts
        summary["by_status"][status] += count
    
    # Get patch and exploit availability counts
    patch_pipeline = [
        {"$match": {
            "organizationId": org_id,
            "discoveredAt": {"$gte": start_date, "$lte": end_date},
            "patchAvailable": True
        }},
        {"$count": "count"}
    ]
    
    exploit_pipeline = [
        {"$match": {
            "organizationId": org_id,
            "discoveredAt": {"$gte": start_date, "$lte": end_date},
            "exploitAvailable": True
        }},
        {"$count": "count"}
    ]
    
    patch_result = await app.mongodb.vulnerabilities.aggregate(patch_pipeline).to_list(1)
    exploit_result = await app.mongodb.vulnerabilities.aggregate(exploit_pipeline).to_list(1)
    
    summary["patch_available"] = patch_result[0]["count"] if patch_result and len(patch_result) > 0 else 0
    summary["exploit_available"] = exploit_result[0]["count"] if exploit_result and len(exploit_result) > 0 else 0
    
    # Calculate average time to fix
    fix_pipeline = [
        {"$match": {
            "organizationId": org_id,
            "status": {"$in": ["patched", "mitigated"]},
            "fixedAt": {"$exists": True},
            "discoveredAt": {"$exists": True},
            "discoveredAt": {"$gte": start_date, "$lte": end_date}
        }},
        {"$project": {
            "fixTime": {"$subtract": ["$fixedAt", "$discoveredAt"]}
        }},
        {"$group": {
            "_id": None,
            "avgFixTime": {"$avg": "$fixTime"},
            "maxFixTime": {"$max": "$fixTime"},
            "minFixTime": {"$min": "$fixTime"},
            "count": {"$sum": 1}
        }}
    ]
    
    fix_metrics = await app.mongodb.vulnerabilities.aggregate(fix_pipeline).to_list(1)
    
    if fix_metrics and len(fix_metrics) > 0:
        # Convert milliseconds to days
        avg_time_ms = fix_metrics[0]["avgFixTime"]
        max_time_ms = fix_metrics[0]["maxFixTime"]
        min_time_ms = fix_metrics[0]["minFixTime"]
        
        summary["fix_metrics"] = {
            "avg_days": round(avg_time_ms / (1000 * 60 * 60 * 24), 1),
            "max_days": round(max_time_ms / (1000 * 60 * 60 * 24), 1),
            "min_days": round(min_time_ms / (1000 * 60 * 60 * 24), 1),
            "fixed_count": fix_metrics[0]["count"]
        }
    else:
        summary["fix_metrics"] = {
            "avg_days": 0,
            "max_days": 0,
            "min_days": 0,
            "fixed_count": 0
        }
    
    # Add time range info
    summary["time_range"] = {
        "start_date": start_date,
        "end_date": end_date,
        "days": (end_date - start_date).days + 1
    }
    
    return summary


def generate_recommendations(threats_summary, vulnerabilities_summary):
    """Generate security recommendations based on threat and vulnerability data."""
    recommendations = []
    
    # Check for critical and high severity vulnerabilities
    critical_vulns = vulnerabilities_summary.get("by_severity", {}).get("critical", 0)
    high_vulns = vulnerabilities_summary.get("by_severity", {}).get("high", 0)
    
    if critical_vulns > 0:
        recommendations.append(
            "URGENT: Address all critical vulnerabilities immediately. "
            f"There are {critical_vulns} critical vulnerabilities that require attention."
        )
    
    if high_vulns > 0:
        recommendations.append(
            f"Prioritize remediation of {high_vulns} high severity vulnerabilities "
            "to reduce security risk exposure."
        )
    
    # Check for vulnerabilities with available patches
    patch_available = vulnerabilities_summary.get("patch_available", 0)
    if patch_available > 0:
        recommendations.append(
            f"Apply available security patches for {patch_available} vulnerabilities "
            "to improve security posture."
        )
    
    # Check for vulnerabilities with known exploits
    exploit_available = vulnerabilities_summary.get("exploit_available", 0)
    if exploit_available > 0:
        recommendations.append(
            f"URGENT: Mitigate {exploit_available} vulnerabilities with known exploits "
            "to prevent potential attacks."
        )
    
    # Check for different types of threats
    ransomware_threats = threats_summary.get("by_type", {}).get("ransomware", 0)
    if ransomware_threats > 0:
        recommendations.append(
            "Enhance backup strategy and implement ransomware protection measures "
            "due to detected ransomware activity."
        )
    
    phishing_threats = threats_summary.get("by_type", {}).get("phishing", 0)
    if phishing_threats > 0:
        recommendations.append(
            "Conduct employee security awareness training focusing on phishing recognition "
            "to reduce risk of social engineering attacks."
        )
    
    # Add general recommendations
    if threats_summary.get("total", 0) > 0 or vulnerabilities_summary.get("total", 0) > 0:
        recommendations.append(
            "Review and update incident response procedures to ensure timely "
            "and effective handling of security incidents."
        )
    
    # If few or no specific recommendations, add general best practices
    if len(recommendations) < 3:
        recommendations.append(
            "Implement regular vulnerability scanning to proactively identify and "
            "address security weaknesses before they can be exploited."
        )
        
        recommendations.append(
            "Ensure all systems are configured according to security best practices "
            "and maintain regular security patching schedules."
        )
        
        recommendations.append(
            "Establish or review access control policies to enforce the principle "
            "of least privilege across all systems and applications."
        )
    
    return recommendations
