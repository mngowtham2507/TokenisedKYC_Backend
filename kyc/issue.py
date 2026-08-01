"""
KYC Token Issuance API
"""
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional, List

from database import get_db
from auth import get_current_user
from utils.crypto import sign_credential
from utils.hash import hash_json

router = APIRouter()


class KYCData(BaseModel):
    name: str
    pan: str
    dob: str  # Format: YYYY-MM-DD
    address: Optional[str] = None
    phone: Optional[str] = None
    aadhaar_last_four: Optional[str] = None


class IssueRequest(BaseModel):
    kyc_data: KYCData


class VerifiableCredential(BaseModel):
    id: str
    type: List[str]
    issuer: str
    issuedAt: str
    credentialSubject: dict
    proof: dict


class IssueResponse(BaseModel):
    token_id: str
    credential: VerifiableCredential
    token_hash: str
    message: str


class KYCStatusResponse(BaseModel):
    status: str
    documents_uploaded: int
    documents_required: int
    documents_verified: int
    can_issue_token: bool
    has_active_token: bool
    message: str


@router.get("/status", response_model=KYCStatusResponse)
async def get_kyc_status(current_user: dict = Depends(get_current_user)):
    """
    Get KYC status for current user
    - Check what documents are uploaded
    - Check if documents are verified
    - Check if token can be issued
    """
    db = get_db()
    
    # Check documents
    docs = db.table("kyc_documents").select("*").eq(
        "user_id", current_user["id"]
    ).execute()
    
    required_types = ["aadhaar_front", "aadhaar_back", "pan_card", "selfie"]
    uploaded_docs = docs.data if docs.data else []
    verified_docs = [d for d in uploaded_docs if d["status"] == "verified"]
    
    # Check existing token
    existing_token = db.table("kyc_tokens").select("*").eq(
        "user_id", current_user["id"]
    ).eq("status", "active").execute()
    
    has_active_token = bool(existing_token.data)
    all_verified = len(verified_docs) >= len(required_types)
    
    if has_active_token:
        status_msg = "You already have an active KYC token"
        kyc_status = "verified"
    elif all_verified:
        status_msg = "Documents verified! You can now receive your KYC token"
        kyc_status = "verified"
    elif len(uploaded_docs) >= len(required_types):
        status_msg = "Documents uploaded, pending verification"
        kyc_status = "pending_verification"
    elif len(uploaded_docs) > 0:
        status_msg = f"Please upload remaining documents ({len(required_types) - len(uploaded_docs)} more needed)"
        kyc_status = "documents_partial"
    else:
        status_msg = "Please upload required documents to begin KYC"
        kyc_status = "pending"
    
    return KYCStatusResponse(
        status=kyc_status,
        documents_uploaded=len(uploaded_docs),
        documents_required=len(required_types),
        documents_verified=len(verified_docs),
        can_issue_token=all_verified and not has_active_token,
        has_active_token=has_active_token,
        message=status_msg
    )


@router.post("/submit")
async def submit_kyc_for_verification(current_user: dict = Depends(get_current_user)):
    """
    Submit uploaded documents for KYC verification
    """
    db = get_db()
    
    # Check documents
    required_types = ["aadhaar_front", "aadhaar_back", "pan_card", "selfie"]
    docs = db.table("kyc_documents").select("*").eq(
        "user_id", current_user["id"]
    ).execute()
    
    uploaded_types = [d["document_type"] for d in (docs.data or [])]
    missing = [t for t in required_types if t not in uploaded_types]
    
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required documents: {', '.join(missing)}"
        )
    
    # Update user KYC status
    db.table("users").update({
        "kyc_status": "documents_uploaded"
    }).eq("id", current_user["id"]).execute()
    
    # Log submission
    db.table("audit_logs").insert({
        "action": "KYC_DOCUMENTS_SUBMITTED",
        "performed_by": current_user["email"],
        "details": {
            "user_id": current_user["id"],
            "documents_count": len(docs.data)
        }
    }).execute()
    
    return {
        "message": "KYC documents submitted for verification",
        "status": "pending_verification",
        "documents_submitted": len(docs.data)
    }


@router.post("/issue", response_model=IssueResponse)
async def issue_kyc_token(
    request: IssueRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Issue a new KYC token (Verifiable Credential)
    
    - Creates a Verifiable Credential JSON
    - Digitally signs it using JWT
    - Hashes the VC using SHA-256
    - Stores in Supabase with status=active
    """
    db = get_db()
    
    # Check if user already has an active KYC token
    existing = db.table("kyc_tokens").select("*").eq(
        "user_id", current_user["id"]
    ).eq("status", "active").execute()
    
    if existing.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has an active KYC token. Revoke existing token first."
        )
    
    # Create Verifiable Credential
    vc_id = str(uuid.uuid4())
    issued_at = datetime.utcnow().isoformat() + "Z"
    
    credential_data = {
        "id": f"vc:{vc_id}",
        "type": ["VerifiableCredential", "KYCCredential"],
        "issuer": "Tokenised-KYC-Authority",
        "issuedAt": issued_at,
        "credentialSubject": {
            "id": f"did:user:{current_user['id']}",
            "name": request.kyc_data.name,
            "pan": request.kyc_data.pan,
            "dob": request.kyc_data.dob,
            "address": request.kyc_data.address,
            "phone": request.kyc_data.phone
        }
    }
    
    # Sign the credential
    signature = sign_credential(credential_data)
    
    # Add proof to credential
    credential_with_proof = {
        **credential_data,
        "proof": {
            "type": "JwtProof2020",
            "created": issued_at,
            "proofPurpose": "assertionMethod",
            "verificationMethod": "Tokenised-KYC-Authority#key-1",
            "signature": signature
        }
    }
    
    # Hash the complete credential
    token_hash = hash_json(credential_with_proof)
    
    # Store in database
    result = db.table("kyc_tokens").insert({
        "user_id": current_user["id"],
        "token_json": credential_with_proof,
        "token_hash": token_hash,
        "status": "active"
    }).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store KYC token"
        )
    
    token_record = result.data[0]
    
    # Log the issuance
    db.table("audit_logs").insert({
        "token_id": token_record["id"],
        "action": "TOKEN_ISSUED",
        "performed_by": "system",
        "details": {
            "user_id": current_user["id"],
            "user_email": current_user["email"]
        }
    }).execute()
    
    return IssueResponse(
        token_id=token_record["id"],
        credential=VerifiableCredential(
            id=credential_with_proof["id"],
            type=credential_with_proof["type"],
            issuer=credential_with_proof["issuer"],
            issuedAt=credential_with_proof["issuedAt"],
            credentialSubject=credential_with_proof["credentialSubject"],
            proof=credential_with_proof["proof"]
        ),
        token_hash=token_hash,
        message="KYC token issued successfully"
    )


@router.get("/tokens")
async def get_user_tokens(current_user: dict = Depends(get_current_user)):
    """Get all KYC tokens for current user"""
    db = get_db()
    
    result = db.table("kyc_tokens").select("*").eq(
        "user_id", current_user["id"]
    ).order("issued_at", desc=True).execute()
    
    return {
        "tokens": result.data,
        "count": len(result.data)
    }


@router.get("/token/{token_id}")
async def get_token_details(
    token_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get details of a specific KYC token"""
    db = get_db()
    
    result = db.table("kyc_tokens").select("*").eq("id", token_id).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    token = result.data[0]
    
    # Verify user owns this token
    if token["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this token"
        )
    
    return token
