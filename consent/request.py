"""
Consent Request API
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List

from database import get_db

router = APIRouter()


class ConsentRequestCreate(BaseModel):
    token_id: str
    requester_name: str
    requested_fields: List[str]


# Valid fields that can be requested (including document types)
VALID_FIELDS = [
    # Data fields
    "name", "pan", "dob", "address", "phone", "id",
    # Document types
    "aadhaar_front", "aadhaar_back", "pan_card", 
    "passport", "driving_license", "voter_id", "selfie"
]


class ConsentRequestResponse(BaseModel):
    consent_id: str
    token_id: str
    requester: str
    requested_fields: List[str]
    status: str
    message: str


@router.post("/request", response_model=ConsentRequestResponse)
async def create_consent_request(request: ConsentRequestCreate):
    """
    Create a consent request for KYC data
    
    - Validates requested fields
    - Creates consent request with status = pending
    - Returns consent_id for tracking
    """
    db = get_db()
    
    # Validate token exists
    token_result = db.table("kyc_tokens").select("id, status, user_id").eq(
        "id", request.token_id
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="KYC token not found"
        )
    
    token = token_result.data[0]
    
    if token["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="KYC token is not active"
        )
    
    # Validate requested fields
    invalid_fields = [f for f in request.requested_fields if f not in VALID_FIELDS]
    if invalid_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid fields requested: {invalid_fields}. Valid fields are: {VALID_FIELDS}"
        )
    
    # Create consent request
    result = db.table("consent_requests").insert({
        "token_id": request.token_id,
        "requester": request.requester_name,
        "requested_fields": request.requested_fields,
        "status": "pending"
    }).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create consent request"
        )
    
    consent = result.data[0]
    
    # Log the consent request
    db.table("audit_logs").insert({
        "token_id": request.token_id,
        "action": "CONSENT_REQUESTED",
        "performed_by": request.requester_name,
        "details": {
            "consent_id": consent["id"],
            "requested_fields": request.requested_fields
        }
    }).execute()
    
    return ConsentRequestResponse(
        consent_id=consent["id"],
        token_id=consent["token_id"],
        requester=consent["requester"],
        requested_fields=consent["requested_fields"],
        status=consent["status"],
        message="Consent request created. Awaiting user approval."
    )


@router.get("/requests/{token_id}")
async def get_consent_requests(token_id: str):
    """Get all consent requests for a token"""
    db = get_db()
    
    result = db.table("consent_requests").select("*").eq(
        "token_id", token_id
    ).order("created_at", desc=True).execute()
    
    return {
        "consent_requests": result.data,
        "count": len(result.data)
    }


@router.get("/request/{consent_id}")
async def get_consent_request(consent_id: str):
    """Get details of a specific consent request"""
    db = get_db()
    
    result = db.table("consent_requests").select("*").eq(
        "id", consent_id
    ).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    return result.data[0]
