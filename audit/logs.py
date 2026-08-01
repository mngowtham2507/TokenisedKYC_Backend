"""
Audit Logs API
"""
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from database import get_db
from auth import get_current_user

router = APIRouter()


class AuditLogResponse(BaseModel):
    id: str
    token_id: Optional[str]
    action: str
    performed_by: str
    details: Optional[dict]
    timestamp: str


class AuditLogsListResponse(BaseModel):
    logs: List[dict]
    count: int
    total: int


@router.get("/logs", response_model=AuditLogsListResponse)
async def get_audit_logs(
    token_id: Optional[str] = Query(None, description="Filter by token ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    limit: int = Query(50, ge=1, le=100, description="Number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get audit logs with optional filtering
    
    Filters:
    - token_id: Filter by specific token
    - action: Filter by action type (TOKEN_ISSUED, TOKEN_VERIFIED, etc.)
    - limit/offset: Pagination
    """
    db = get_db()
    
    # Get user's tokens to filter logs
    tokens_result = db.table("kyc_tokens").select("id").eq(
        "user_id", current_user["id"]
    ).execute()
    
    user_token_ids = [t["id"] for t in tokens_result.data] if tokens_result.data else []
    
    # Build query
    query = db.table("audit_logs").select("*", count="exact")
    
    if token_id:
        # Verify user owns this token
        if token_id not in user_token_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view logs for this token"
            )
        query = query.eq("token_id", token_id)
    else:
        # Only show logs for user's tokens
        if user_token_ids:
            query = query.in_("token_id", user_token_ids)
        else:
            return AuditLogsListResponse(logs=[], count=0, total=0)
    
    if action:
        query = query.eq("action", action)
    
    # Execute with pagination
    result = query.order("timestamp", desc=True).range(offset, offset + limit - 1).execute()
    
    return AuditLogsListResponse(
        logs=result.data,
        count=len(result.data),
        total=result.count if result.count else len(result.data)
    )


@router.get("/logs/actions")
async def get_action_types():
    """Get list of possible audit action types"""
    return {
        "actions": [
            "TOKEN_ISSUED",
            "TOKEN_VERIFIED",
            "TOKEN_REVOKED",
            "CONSENT_REQUESTED",
            "CONSENT_APPROVED",
            "CONSENT_REJECTED"
        ]
    }


@router.get("/logs/token/{token_id}")
async def get_token_audit_trail(
    token_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get complete audit trail for a specific token"""
    db = get_db()
    
    # Verify token exists and user owns it
    token_result = db.table("kyc_tokens").select("user_id").eq(
        "id", token_id
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    if token_result.data[0]["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this token's audit trail"
        )
    
    # Get all logs for this token
    logs_result = db.table("audit_logs").select("*").eq(
        "token_id", token_id
    ).order("timestamp", desc=True).execute()
    
    return {
        "token_id": token_id,
        "audit_trail": logs_result.data,
        "total_events": len(logs_result.data)
    }


@router.get("/logs/summary")
async def get_audit_summary(current_user: dict = Depends(get_current_user)):
    """Get summary of audit activity for current user"""
    db = get_db()
    
    # Get user's tokens
    tokens_result = db.table("kyc_tokens").select("id").eq(
        "user_id", current_user["id"]
    ).execute()
    
    if not tokens_result.data:
        return {
            "total_tokens": 0,
            "total_events": 0,
            "events_by_action": {}
        }
    
    token_ids = [t["id"] for t in tokens_result.data]
    
    # Get all logs for user's tokens
    logs_result = db.table("audit_logs").select("action").in_(
        "token_id", token_ids
    ).execute()
    
    # Count by action type
    action_counts = {}
    for log in logs_result.data:
        action = log["action"]
        action_counts[action] = action_counts.get(action, 0) + 1
    
    return {
        "total_tokens": len(token_ids),
        "total_events": len(logs_result.data),
        "events_by_action": action_counts
    }
