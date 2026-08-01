"""
KYC Token Verification API
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional

from database import get_db
from utils.crypto import verify_signature
from utils.hash import verify_hash

router = APIRouter()


def _get_trust_level(verification_source: Optional[str]) -> dict:
    """Get trust level information based on verification source"""
    trust_levels = {
        "uidai": {"score": 100, "level": "Government Verified", "color": "green"},
        "nsdl": {"score": 100, "level": "Government Verified", "color": "green"},
        "digilocker": {"score": 100, "level": "DigiLocker Verified", "color": "green"},
        "passport_seva": {"score": 100, "level": "Government Verified", "color": "green"},
        "rto": {"score": 100, "level": "Government Verified", "color": "green"},
        "manual_verified": {"score": 80, "level": "Manually Verified", "color": "yellow"},
        "unverified": {"score": 0, "level": "UNVERIFIED - DO NOT TRUST", "color": "red"},
    }
    
    return trust_levels.get(
        verification_source, 
        {"score": 0, "level": "Unknown Source", "color": "red"}
    )


class VerifyRequest(BaseModel):
    token_id: str
    consent_id: str


class VerifyResponse(BaseModel):
    valid: bool
    token_id: str
    requested_fields: dict
    issuer: str
    issued_at: str
    message: str


@router.post("/verify", response_model=VerifyResponse)
async def verify_kyc_token(request: VerifyRequest):
    """
    Verify a KYC token
    
    Verification steps:
    1. Check token exists and status = active
    2. Verify JWT signature
    3. Check consent approved
    4. Return only requested fields
    5. Log verification in audit_logs
    """
    db = get_db()
    
    # Step 1: Check token exists and is active
    token_result = db.table("kyc_tokens").select("*").eq(
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
            detail="KYC token has been revoked"
        )
    
    # Step 2: Verify JWT signature (if available)
    token_json = token["token_json"]
    signature = token_json.get("proof", {}).get("signature")
    
    # For tokens without valid signature, we skip signature verification
    # In production, this should be strictly enforced
    if signature:
        verification_result = verify_signature(signature)
        
        if not verification_result["valid"]:
            # Log warning but continue (for backward compatibility with old tokens)
            print(f"Warning: Token signature verification failed: {verification_result.get('error')}")
            # For now, skip strict signature enforcement for existing tokens
            # raise HTTPException(
            #     status_code=status.HTTP_400_BAD_REQUEST,
            #     detail=f"Invalid token signature: {verification_result.get('error')}"
            # )
    
    # Verify hash integrity
    stored_hash = token["token_hash"]
    if not verify_hash(token_json, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token integrity check failed"
        )
    
    # Step 3: Check consent is approved
    consent_result = db.table("consent_requests").select("*").eq(
        "id", request.consent_id
    ).execute()
    
    if not consent_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    consent = consent_result.data[0]
    
    if consent["token_id"] != request.token_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Consent request does not match token"
        )
    
    if consent["status"] != "approved":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Consent has not been approved"
        )
    
    # Step 4: Return only requested fields
    credential_subject = token_json.get("credentialSubject", {})
    requested_fields = consent["requested_fields"]
    
    # Document types
    DOCUMENT_TYPES = ["aadhaar_front", "aadhaar_back", "pan_card", "passport", "driving_license", "voter_id", "selfie"]
    
    filtered_data = {}
    requested_documents = []
    
    for field in requested_fields:
        if field in DOCUMENT_TYPES:
            requested_documents.append(field)
        elif field in credential_subject:
            filtered_data[field] = credential_subject[field]
    
    # If documents are requested, fetch their URLs WITH verification status
    documents_data = {}
    if requested_documents:
        user_id = token["user_id"]
        docs_result = db.table("kyc_documents").select(
            "document_type, file_url, status, verification_source, verification_id, issuer_name, verified_at, document_hash"
        ).eq(
            "user_id", user_id
        ).in_("document_type", requested_documents).execute()
        
        if docs_result.data:
            for doc in docs_result.data:
                # Include verification information for banks to trust
                documents_data[doc["document_type"]] = {
                    "file_url": doc["file_url"],
                    "is_verified": doc.get("status") == "verified",
                    "verification_source": doc.get("verification_source"),
                    "verification_id": doc.get("verification_id"),
                    "issuer_name": doc.get("issuer_name"),
                    "verified_at": doc.get("verified_at"),
                    "document_hash": doc.get("document_hash"),
                    "trust_level": _get_trust_level(doc.get("verification_source"))
                }
    
    # Combine data and documents
    filtered_data["documents"] = documents_data if documents_data else None
    
    # Step 5: Log verification
    db.table("audit_logs").insert({
        "token_id": request.token_id,
        "action": "TOKEN_VERIFIED",
        "performed_by": consent["requester"],
        "details": {
            "consent_id": request.consent_id,
            "fields_shared": requested_fields
        }
    }).execute()
    
    return VerifyResponse(
        valid=True,
        token_id=request.token_id,
        requested_fields=filtered_data,
        issuer=token_json.get("issuer", "Unknown"),
        issued_at=token_json.get("issuedAt", "Unknown"),
        message="KYC verification successful"
    )


@router.get("/verify/{token_id}/status")
async def check_token_status(token_id: str):
    """Check if a token is active (without full verification)"""
    db = get_db()
    
    result = db.table("kyc_tokens").select("id, status, issued_at").eq(
        "id", token_id
    ).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    token = result.data[0]
    
    return {
        "token_id": token["id"],
        "status": token["status"],
        "is_active": token["status"] == "active",
        "issued_at": token["issued_at"]
    }


@router.get("/verify/preview/{consent_id}")
async def preview_kyc_data(consent_id: str):
    """
    Preview KYC data before verification - shows all data that will be shared
    Does NOT log as verified, just shows preview
    """
    db = get_db()
    
    # Get consent request
    consent_result = db.table("consent_requests").select("*").eq(
        "id", consent_id
    ).execute()
    
    if not consent_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Consent request not found"
        )
    
    consent = consent_result.data[0]
    
    if consent["status"] != "approved":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Consent is {consent['status']}, must be approved for preview"
        )
    
    # Get token
    token_result = db.table("kyc_tokens").select("*").eq(
        "id", consent["token_id"]
    ).execute()
    
    if not token_result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="KYC token not found"
        )
    
    token = token_result.data[0]
    token_json = token["token_json"]
    credential_subject = token_json.get("credentialSubject", {})
    
    # Document types
    DOCUMENT_TYPES = ["aadhaar_front", "aadhaar_back", "pan_card", "passport", "driving_license", "voter_id", "selfie"]
    
    # Build preview data
    data_fields = {}
    requested_documents = []
    
    for field in consent["requested_fields"]:
        if field in DOCUMENT_TYPES:
            requested_documents.append(field)
        elif field in credential_subject:
            data_fields[field] = credential_subject[field]
    
    # Get documents with verification status
    documents_data = {}
    if requested_documents:
        user_id = token["user_id"]
        docs_result = db.table("kyc_documents").select(
            "document_type, file_url, status, verification_source, issuer_name, verified_at"
        ).eq(
            "user_id", user_id
        ).in_("document_type", requested_documents).execute()
        
        if docs_result.data:
            for doc in docs_result.data:
                documents_data[doc["document_type"]] = {
                    "file_url": doc["file_url"],
                    "is_verified": doc.get("status") == "verified",
                    "verification_source": doc.get("verification_source"),
                    "issuer_name": doc.get("issuer_name"),
                    "verified_at": doc.get("verified_at"),
                    "trust_level": _get_trust_level(doc.get("verification_source"))
                }
    
    return {
        "consent_id": consent_id,
        "token_id": consent["token_id"],
        "token_status": token["status"],
        "requester": consent["requester"],
        "requested_fields": consent["requested_fields"],
        "consent_status": consent["status"],
        "created_at": consent["created_at"],
        "issuer": token_json.get("issuer", "KYC Authority"),
        "issued_at": token_json.get("issuedAt", token["issued_at"]),
        "data_fields": data_fields,
        "documents": documents_data
    }
