"""
KYC Token Revocation API
"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional

from database import get_db
from auth import get_current_user

router = APIRouter()


class RevokeRequest(BaseModel):
    token_id: str
    reason: Optional[str] = "User requested revocation"


class RevokeResponse(BaseModel):
    token_id: str
    status: str
    message: str


@router.post("/revoke", response_model=RevokeResponse)
async def revoke_kyc_token(
    request: RevokeRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Revoke a KYC token
    
    - Updates token status to 'revoked'
    - Logs revocation in audit_logs
    - Blocks future verification attempts
    """
    db = get_db()
    
    # Get the token
    token_result = db.table("kyc_tokens").select("*").eq(
        "id", request.token_id
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="KYC token not found"
        )
    
    token = token_result.data[0]
    
    # Verify user owns this token
    if token["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this token"
        )
    
    if token["status"] == "revoked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked"
        )
    
    # Update token status
    update_result = db.table("kyc_tokens").update({
        "status": "revoked"
    }).eq("id", request.token_id).execute()
    
    if not update_result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke token"
        )
    
    # Log the revocation
    db.table("audit_logs").insert({
        "token_id": request.token_id,
        "action": "TOKEN_REVOKED",
        "performed_by": current_user["email"],
        "details": {
            "reason": request.reason
        }
    }).execute()
    
    # Reject all pending consent requests for this token
    db.table("consent_requests").update({
        "status": "rejected"
    }).eq("token_id", request.token_id).eq("status", "pending").execute()
    
    return RevokeResponse(
        token_id=request.token_id,
        status="revoked",
        message="KYC token has been revoked successfully"
    )
