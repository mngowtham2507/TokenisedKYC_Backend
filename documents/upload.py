"""
Document Upload API for KYC verification
"""
import os
import uuid
import base64
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

from database import get_db
from auth import get_current_user
from documents.verification import verify_document, format_verification_badge, VerificationSource

router = APIRouter()


class DocumentType(str, Enum):
    AADHAAR_FRONT = "aadhaar_front"
    AADHAAR_BACK = "aadhaar_back"
    PAN_CARD = "pan_card"
    PASSPORT = "passport"
    DRIVING_LICENSE = "driving_license"
    VOTER_ID = "voter_id"
    SELFIE = "selfie"


class VerificationInfo(BaseModel):
    is_verified: bool
    verification_source: Optional[str] = None
    verification_source_display: Optional[str] = None
    issuer_name: Optional[str] = None
    verified_at: Optional[str] = None
    trust_score: int = 0
    trust_level: Optional[str] = None
    trust_description: Optional[str] = None
    badge_color: str = "red"


class DocumentResponse(BaseModel):
    id: str
    user_id: str
    document_type: str
    file_name: str
    file_url: str
    status: str
    uploaded_at: str
    verification: Optional[VerificationInfo] = None


class DocumentListResponse(BaseModel):
    documents: List[DocumentResponse]
    total: int


@router.post("/upload", response_model=DocumentResponse)
async def upload_document(
    document_type: DocumentType = Form(...),
    file: UploadFile = File(...),
    document_number: Optional[str] = Form(None),  # e.g., Aadhaar number, PAN number
    current_user: dict = Depends(get_current_user)
):
    """
    Upload a KYC document with automatic verification
    
    Supported document types:
    - aadhaar_front: Aadhaar Card (Front) - verified via UIDAI
    - aadhaar_back: Aadhaar Card (Back) - verified via UIDAI  
    - pan_card: PAN Card - verified via NSDL
    - passport: Passport - verified via DigiLocker
    - driving_license: Driving License - verified via RTO/DigiLocker
    - voter_id: Voter ID - verified via DigiLocker
    - selfie: Live Selfie for verification
    
    Provide document_number for enhanced verification (e.g., 12-digit Aadhaar, 10-char PAN)
    """
    db = get_db()
    
    # Validate file type
    allowed_types = ["image/jpeg", "image/png", "image/jpg", "application/pdf"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_types)}"
        )
    
    # Validate file size (max 5MB)
    file_content = await file.read()
    if len(file_content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="File size exceeds 5MB limit"
        )
    
    # Verify document with official sources
    verification_result = await verify_document(
        document_type=document_type.value,
        file_content=file_content,
        document_number=document_number,
        additional_info={"user_id": current_user["id"]}
    )
    
    verification_badge = format_verification_badge(verification_result)
    
    # Determine status based on verification
    doc_status = "verified" if verification_result.get("success") else "pending"
    
    # Check if document type already exists for user
    existing = db.table("kyc_documents").select("*").eq(
        "user_id", current_user["id"]
    ).eq("document_type", document_type.value).execute()
    
    # Prepare verification data for database
    verification_db_data = {
        "verification_source": verification_result.get("verification_source"),
        "verification_id": verification_result.get("verification_id"),
        "issuer_signature": verification_result.get("issuer_signature"),
        "issuer_name": verification_result.get("issuer_name"),
        "verified_at": verification_result.get("verified_at"),
        "document_hash": verification_result.get("document_hash"),
        "extracted_data": verification_result.get("extracted_data")
    }
    
    if existing.data:
        # Update existing document
        doc_id = existing.data[0]["id"]
        
        # Upload to Supabase Storage
        file_ext = file.filename.split(".")[-1] if file.filename else "jpg"
        file_path = f"kyc/{current_user['id']}/{document_type.value}.{file_ext}"
        
        try:
            # Delete old file if exists
            db.storage.from_("documents").remove([file_path])
        except:
            pass
        
        # Upload new file
        result = db.storage.from_("documents").upload(
            file_path,
            file_content,
            {"content-type": file.content_type}
        )
        
        file_url = db.storage.from_("documents").get_public_url(file_path)
        
        # Update database record with verification info
        update_data = {
            "file_name": file.filename,
            "file_url": file_url,
            "status": doc_status,
            "updated_at": datetime.utcnow().isoformat(),
            **verification_db_data
        }
        updated = db.table("kyc_documents").update(update_data).eq("id", doc_id).execute()
        
        doc_record = updated.data[0]
    else:
        # Create new document record
        doc_id = str(uuid.uuid4())
        
        # Upload to Supabase Storage
        file_ext = file.filename.split(".")[-1] if file.filename else "jpg"
        file_path = f"kyc/{current_user['id']}/{document_type.value}.{file_ext}"
        
        result = db.storage.from_("documents").upload(
            file_path,
            file_content,
            {"content-type": file.content_type}
        )
        
        file_url = db.storage.from_("documents").get_public_url(file_path)
        
        # Save to database with verification info
        insert_data = {
            "id": doc_id,
            "user_id": current_user["id"],
            "document_type": document_type.value,
            "file_name": file.filename,
            "file_url": file_url,
            "status": doc_status,
            **verification_db_data
        }
        doc_record = db.table("kyc_documents").insert(insert_data).execute().data[0]
    
    return DocumentResponse(
        id=doc_record["id"],
        user_id=doc_record["user_id"],
        document_type=doc_record["document_type"],
        file_name=doc_record["file_name"],
        file_url=doc_record["file_url"],
        status=doc_record["status"],
        uploaded_at=doc_record.get("created_at", datetime.utcnow().isoformat()),
        verification=VerificationInfo(
            is_verified=verification_badge["is_verified"],
            verification_source=verification_badge["verification_source"],
            verification_source_display=verification_badge["verification_source_display"],
            issuer_name=verification_badge["issuer_name"],
            verified_at=verification_badge["verified_at"],
            trust_score=verification_badge["trust_score"],
            trust_level=verification_badge["trust_level"],
            trust_description=verification_badge["trust_description"],
            badge_color=verification_badge["badge_color"]
        )
    )


@router.get("/list", response_model=DocumentListResponse)
async def list_documents(current_user: dict = Depends(get_current_user)):
    """List all documents uploaded by the user"""
    db = get_db()
    
    result = db.table("kyc_documents").select("*").eq(
        "user_id", current_user["id"]
    ).order("created_at", desc=True).execute()
    
    documents = [
        DocumentResponse(
            id=doc["id"],
            user_id=doc["user_id"],
            document_type=doc["document_type"],
            file_name=doc["file_name"],
            file_url=doc["file_url"],
            status=doc["status"],
            uploaded_at=doc.get("created_at", "")
        )
        for doc in result.data
    ]
    
    return DocumentListResponse(documents=documents, total=len(documents))


@router.delete("/{document_id}")
async def delete_document(
    document_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a document"""
    db = get_db()
    
    # Verify ownership
    doc = db.table("kyc_documents").select("*").eq(
        "id", document_id
    ).eq("user_id", current_user["id"]).execute()
    
    if not doc.data:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Delete from storage
    try:
        file_path = f"kyc/{current_user['id']}/{doc.data[0]['document_type']}"
        db.storage.from_("documents").remove([file_path])
    except:
        pass
    
    # Delete from database
    db.table("kyc_documents").delete().eq("id", document_id).execute()
    
    return {"message": "Document deleted successfully"}


@router.get("/required")
async def get_required_documents():
    """Get list of required documents for KYC"""
    return {
        "required_documents": [
            {
                "type": "aadhaar_front",
                "name": "Aadhaar Card (Front)",
                "description": "Clear photo of the front side of your Aadhaar card",
                "required": True
            },
            {
                "type": "aadhaar_back",
                "name": "Aadhaar Card (Back)",
                "description": "Clear photo of the back side of your Aadhaar card",
                "required": True
            },
            {
                "type": "pan_card",
                "name": "PAN Card",
                "description": "Clear photo of your PAN card",
                "required": True
            },
            {
                "type": "selfie",
                "name": "Live Selfie",
                "description": "Take a clear selfie for identity verification",
                "required": True
            }
        ],
        "optional_documents": [
            {
                "type": "passport",
                "name": "Passport",
                "description": "First and last page of your passport"
            },
            {
                "type": "driving_license",
                "name": "Driving License",
                "description": "Clear photo of your driving license"
            },
            {
                "type": "voter_id",
                "name": "Voter ID",
                "description": "Clear photo of your voter ID card"
            }
        ]
    }
