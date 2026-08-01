"""
Consent Approval API
"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Literal

from database import get_db
from auth import get_current_user

router = APIRouter()


class ApproveRequest(BaseModel):
    consent_id: str


class RejectRequest(BaseModel):
    consent_id: str
    reason: str = "User rejected the request"


class ConsentActionResponse(BaseModel):
    consent_id: str
    status: str
    message: str


@router.post("/approve", response_model=ConsentActionResponse)
async def approve_consent(
    request: ApproveRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Approve a consent request
    
    - Validates consent exists and is pending
    - Verifies user owns the associated token
    - Updates consent status to approved
    - Logs action in audit_logs
    """
    db = get_db()
    
    # Get consent request
    consent_result = db.table("consent_requests").select("*").eq(
        "id", request.consent_id
    ).execute()
    
    if not consent_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    consent = consent_result.data[0]
    
    if consent["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Consent request is already {consent['status']}"
        )
    
    # Verify user owns the token
    token_result = db.table("kyc_tokens").select("user_id").eq(
        "id", consent["token_id"]
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated KYC token not found"
        )
    
    if token_result.data[0]["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to approve this consent request"
        )
    
    # Update consent status
    update_result = db.table("consent_requests").update({
        "status": "approved"
    }).eq("id", request.consent_id).execute()
    
    if not update_result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update consent status"
        )
    
    # Log the approval
    db.table("audit_logs").insert({
        "token_id": consent["token_id"],
        "action": "CONSENT_APPROVED",
        "performed_by": current_user["email"],
        "details": {
            "consent_id": request.consent_id,
            "requester": consent["requester"],
            "fields_approved": consent["requested_fields"]
        }
    }).execute()
    
    return ConsentActionResponse(
        consent_id=request.consent_id,
        status="approved",
        message="Consent approved successfully"
    )


@router.post("/reject", response_model=ConsentActionResponse)
async def reject_consent(
    request: RejectRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Reject a consent request
    
    - Validates consent exists and is pending
    - Verifies user owns the associated token
    - Updates consent status to rejected
    - Logs action in audit_logs
    """
    db = get_db()
    
    # Get consent request
    consent_result = db.table("consent_requests").select("*").eq(
        "id", request.consent_id
    ).execute()
    
    if not consent_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    consent = consent_result.data[0]
    
    if consent["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Consent request is already {consent['status']}"
        )
    
    # Verify user owns the token
    token_result = db.table("kyc_tokens").select("user_id").eq(
        "id", consent["token_id"]
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated KYC token not found"
        )
    
    if token_result.data[0]["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to reject this consent request"
        )
    
    # Update consent status
    update_result = db.table("consent_requests").update({
        "status": "rejected"
    }).eq("id", request.consent_id).execute()
    
    if not update_result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update consent status"
        )
    
    # Log the rejection
    db.table("audit_logs").insert({
        "token_id": consent["token_id"],
        "action": "CONSENT_REJECTED",
        "performed_by": current_user["email"],
        "details": {
            "consent_id": request.consent_id,
            "requester": consent["requester"],
            "reason": request.reason
        }
    }).execute()
    
    return ConsentActionResponse(
        consent_id=request.consent_id,
        status="rejected",
        message="Consent rejected"
    )


@router.get("/pending")
async def get_pending_consents(current_user: dict = Depends(get_current_user)):
    """Get all pending consent requests for current user's tokens"""
    db = get_db()
    
    # Get user's tokens
    tokens_result = db.table("kyc_tokens").select("id").eq(
        "user_id", current_user["id"]
    ).execute()
    
    if not tokens_result.data:
        return {"consent_requests": [], "count": 0}
    
    token_ids = [t["id"] for t in tokens_result.data]
    
    # Get pending consents for those tokens
    consents_result = db.table("consent_requests").select("*").in_(
        "token_id", token_ids
    ).eq("status", "pending").order("created_at", desc=True).execute()
    
    return {
        "consent_requests": consents_result.data,
        "count": len(consents_result.data)
    }


@router.get("/approved")
async def get_approved_consents(current_user: dict = Depends(get_current_user)):
    """Get all approved consent requests for current user's tokens"""
    db = get_db()
    
    # Get user's tokens
    tokens_result = db.table("kyc_tokens").select("id").eq(
        "user_id", current_user["id"]
    ).execute()
    
    if not tokens_result.data:
        return {"consent_requests": [], "count": 0}
    
    token_ids = [t["id"] for t in tokens_result.data]
    
    # Get approved consents for those tokens
    consents_result = db.table("consent_requests").select("*").in_(
        "token_id", token_ids
    ).eq("status", "approved").order("created_at", desc=True).execute()
    
    return {
        "consent_requests": consents_result.data,
        "count": len(consents_result.data)
    }


@router.post("/revoke")
async def revoke_consent(
    request: ApproveRequest,  # Reusing same model as it only needs consent_id
    current_user: dict = Depends(get_current_user)
):
    """
    Revoke an approved consent
    
    - Validates consent exists and is approved
    - Verifies user owns the associated token
    - Updates consent status to revoked
    - Logs action in audit_logs
    """
    db = get_db()
    
    # Get consent request
    consent_result = db.table("consent_requests").select("*").eq(
        "id", request.consent_id
    ).execute()
    
    if not consent_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    consent = consent_result.data[0]
    
    if consent["status"] != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Can only revoke approved consents. Current status: {consent['status']}"
        )
    
    # Verify user owns the token
    token_result = db.table("kyc_tokens").select("user_id").eq(
        "id", consent["token_id"]
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated KYC token not found"
        )
    
    if token_result.data[0]["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this consent"
        )
    
    # Update consent status
    update_result = db.table("consent_requests").update({
        "status": "revoked"
    }).eq("id", request.consent_id).execute()
    
    if not update_result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke consent"
        )
    
    # Log the revocation
    db.table("audit_logs").insert({
        "token_id": consent["token_id"],
        "action": "CONSENT_REVOKED",
        "performed_by": current_user["email"],
        "details": {
            "consent_id": request.consent_id,
            "requester": consent["requester"]
        }
    }).execute()
    
    return ConsentActionResponse(
        consent_id=request.consent_id,
        status="revoked",
        message="Consent revoked successfully"
    )
