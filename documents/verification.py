"""
Document Verification Service

This module provides integration with official document verification sources:
- DigiLocker API (Government of India)
- UIDAI e-KYC (Aadhaar verification)
- NSDL (PAN verification)
- Other government sources

For production:
- Register at https://partners.digilocker.gov.in for DigiLocker API access
- Get UIDAI e-KYC license from UIDAI
- Register with NSDL for PAN verification API
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Optional, Tuple
from enum import Enum

# In production, these would be API calls to actual services
# For now, we simulate the verification process

class VerificationSource(str, Enum):
    DIGILOCKER = "digilocker"
    UIDAI = "uidai"
    NSDL = "nsdl"
    PASSPORT_SEVA = "passport_seva"
    RTO = "rto"
    MANUAL_VERIFIED = "manual_verified"
    UNVERIFIED = "unverified"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    PENDING = "pending"
    REJECTED = "rejected"
    FAILED = "failed"


# Document type to verification source mapping
DOCUMENT_VERIFICATION_SOURCES = {
    "aadhaar_front": VerificationSource.UIDAI,
    "aadhaar_back": VerificationSource.UIDAI,
    "pan_card": VerificationSource.NSDL,
    "passport": VerificationSource.PASSPORT_SEVA,
    "driving_license": VerificationSource.RTO,
    "voter_id": VerificationSource.DIGILOCKER,
    "selfie": VerificationSource.MANUAL_VERIFIED,
}


def calculate_document_hash(file_content: bytes) -> str:
    """Calculate SHA-256 hash of document for integrity verification"""
    return hashlib.sha256(file_content).hexdigest()


def sign_document_verification(document_data: Dict) -> str:
    """
    Create a cryptographic signature for the verification result.
    In production, this would use the issuer's private key.
    """
    from utils.crypto import sign_data
    
    # Sign the verification data
    data_to_sign = json.dumps(document_data, sort_keys=True)
    signature = sign_data(data_to_sign)
    return signature


async def verify_aadhaar(aadhaar_number: str, otp: Optional[str] = None) -> Dict:
    """
    Verify Aadhaar via UIDAI e-KYC API
    
    In production:
    - Call UIDAI e-KYC API with ASA (Authentication Service Agency) license
    - Requires user consent and OTP from registered mobile
    - Returns digitally signed e-KYC XML/JSON
    
    Reference: https://uidai.gov.in/ecosystem/authentication-devices-documents/about-aua-kua.html
    """
    # Simulated verification for demo
    # In production, this calls the actual UIDAI API
    
    if not aadhaar_number or len(aadhaar_number) != 12:
        return {
            "success": False,
            "error": "Invalid Aadhaar number format",
            "status": VerificationStatus.FAILED
        }
    
    # Simulate successful UIDAI verification
    return {
        "success": True,
        "verification_source": VerificationSource.UIDAI,
        "verification_id": f"UIDAI-EKYC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "issuer_name": "Unique Identification Authority of India (UIDAI)",
        "verified_at": datetime.now().isoformat(),
        "status": VerificationStatus.VERIFIED,
        "extracted_data": {
            "aadhaar_masked": f"XXXX-XXXX-{aadhaar_number[-4:]}",
            "name_verified": True,
            "address_verified": True,
            "photo_verified": True,
            "dob_verified": True
        },
        "trust_score": 100,  # Government verified = highest trust
        "message": "Document verified via UIDAI e-KYC"
    }


async def verify_pan(pan_number: str, name: Optional[str] = None, dob: Optional[str] = None) -> Dict:
    """
    Verify PAN via NSDL/Income Tax Department API
    
    In production:
    - Call NSDL PAN verification API
    - Requires registration with Income Tax Department
    - Returns PAN status and holder details
    
    Reference: https://www.tin-nsdl.com/services/pan/pan-verification.html
    """
    # Validate PAN format: AAAAA1234A
    if not pan_number or len(pan_number) != 10:
        return {
            "success": False,
            "error": "Invalid PAN format",
            "status": VerificationStatus.FAILED
        }
    
    # Simulate successful NSDL verification
    return {
        "success": True,
        "verification_source": VerificationSource.NSDL,
        "verification_id": f"NSDL-PAN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "issuer_name": "Income Tax Department / NSDL",
        "verified_at": datetime.now().isoformat(),
        "status": VerificationStatus.VERIFIED,
        "extracted_data": {
            "pan_number": pan_number,
            "name_match": True if name else None,
            "pan_status": "ACTIVE",
            "pan_type": "Individual" if pan_number[3] == 'P' else "Other"
        },
        "trust_score": 100,
        "message": "PAN verified via NSDL"
    }


async def verify_via_digilocker(
    document_type: str, 
    digilocker_code: Optional[str] = None,
    document_uri: Optional[str] = None
) -> Dict:
    """
    Verify document via DigiLocker API
    
    DigiLocker provides access to authentic documents issued by various government bodies.
    Documents from DigiLocker are digitally signed by the issuing authority.
    
    In production:
    - Register as DigiLocker Partner at https://partners.digilocker.gov.in
    - Use OAuth 2.0 for user authorization
    - Fetch documents using DigiLocker API
    - Documents come with digital signature from issuer
    
    Supported documents:
    - Aadhaar, PAN, Driving License, Vehicle Registration
    - Class X, XII Marksheets, Degree Certificates
    - Insurance policies, Property documents
    """
    
    # Simulate DigiLocker verification
    issuer_map = {
        "aadhaar_front": "Unique Identification Authority of India",
        "aadhaar_back": "Unique Identification Authority of India", 
        "pan_card": "Income Tax Department",
        "driving_license": "Ministry of Road Transport & Highways",
        "voter_id": "Election Commission of India",
        "passport": "Ministry of External Affairs"
    }
    
    return {
        "success": True,
        "verification_source": VerificationSource.DIGILOCKER,
        "verification_id": f"DIGI-{document_type.upper()}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "issuer_name": issuer_map.get(document_type, "Government of India"),
        "verified_at": datetime.now().isoformat(),
        "status": VerificationStatus.VERIFIED,
        "extracted_data": {
            "document_type": document_type,
            "digilocker_verified": True,
            "digitally_signed": True,
            "issuer_certificate": "Valid"
        },
        "trust_score": 100,
        "message": f"Document fetched and verified via DigiLocker"
    }


async def verify_document(
    document_type: str,
    file_content: Optional[bytes] = None,
    document_number: Optional[str] = None,
    additional_info: Optional[Dict] = None
) -> Dict:
    """
    Main document verification function.
    Routes to appropriate verification source based on document type.
    
    Args:
        document_type: Type of document (aadhaar_front, pan_card, etc.)
        file_content: Raw file bytes for hash calculation
        document_number: Document number for API verification
        additional_info: Additional info like name, DOB for matching
    
    Returns:
        Verification result with status, source, and signature
    """
    
    # Calculate document hash for integrity
    document_hash = None
    if file_content:
        document_hash = calculate_document_hash(file_content)
    
    verification_source = DOCUMENT_VERIFICATION_SOURCES.get(
        document_type, 
        VerificationSource.UNVERIFIED
    )
    
    result = None
    
    # Route to appropriate verification API
    if document_type in ["aadhaar_front", "aadhaar_back"]:
        if document_number:
            result = await verify_aadhaar(document_number)
        else:
            # Try DigiLocker if no Aadhaar number provided
            result = await verify_via_digilocker(document_type)
            
    elif document_type == "pan_card":
        if document_number:
            result = await verify_pan(
                document_number,
                name=additional_info.get("name") if additional_info else None
            )
        else:
            result = await verify_via_digilocker(document_type)
            
    elif document_type in ["driving_license", "voter_id", "passport"]:
        # Use DigiLocker for these documents
        result = await verify_via_digilocker(document_type)
        
    elif document_type == "selfie":
        # Selfie requires face matching with ID document
        result = {
            "success": True,
            "verification_source": VerificationSource.MANUAL_VERIFIED,
            "verification_id": f"SELFIE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "issuer_name": "KYC System",
            "verified_at": datetime.now().isoformat(),
            "status": VerificationStatus.VERIFIED,
            "extracted_data": {
                "face_match_pending": True,
                "liveness_check": "passed"
            },
            "trust_score": 80,  # Lower trust for selfie
            "message": "Selfie captured, face matching with ID pending"
        }
    else:
        result = {
            "success": False,
            "verification_source": VerificationSource.UNVERIFIED,
            "status": VerificationStatus.PENDING,
            "message": "Document type not supported for automatic verification"
        }
    
    # Add document hash to result
    if document_hash:
        result["document_hash"] = document_hash
    
    # Sign the verification result if successful
    if result.get("success"):
        try:
            result["issuer_signature"] = sign_document_verification({
                "document_type": document_type,
                "verification_source": result.get("verification_source"),
                "verification_id": result.get("verification_id"),
                "verified_at": result.get("verified_at"),
                "document_hash": document_hash
            })
        except Exception as e:
            # Don't fail verification if signing fails
            result["issuer_signature"] = None
            result["signature_error"] = str(e)
    
    return result


def get_trust_level(verification_source: str) -> Tuple[int, str, str]:
    """
    Get trust level information based on verification source.
    
    Returns:
        Tuple of (trust_score, trust_level_name, description)
    """
    trust_levels = {
        VerificationSource.UIDAI: (100, "Government Verified", "Verified directly with UIDAI"),
        VerificationSource.NSDL: (100, "Government Verified", "Verified with Income Tax Department"),
        VerificationSource.DIGILOCKER: (100, "DigiLocker Verified", "Fetched from DigiLocker with issuer signature"),
        VerificationSource.PASSPORT_SEVA: (100, "Government Verified", "Verified with Passport Seva"),
        VerificationSource.RTO: (100, "Government Verified", "Verified with Regional Transport Office"),
        VerificationSource.MANUAL_VERIFIED: (80, "Manually Verified", "Verified by authorized agent"),
        VerificationSource.UNVERIFIED: (0, "Unverified", "Document not verified - DO NOT TRUST"),
    }
    
    return trust_levels.get(
        verification_source, 
        (0, "Unknown", "Verification source unknown")
    )


def format_verification_badge(verification_result: Dict) -> Dict:
    """
    Format verification result for display in UI
    """
    source = verification_result.get("verification_source", "unverified")
    trust_score, trust_level, description = get_trust_level(source)
    
    return {
        "is_verified": verification_result.get("success", False),
        "verification_source": source,
        "verification_source_display": source.replace("_", " ").title() if source else "Unknown",
        "issuer_name": verification_result.get("issuer_name", "Unknown"),
        "verified_at": verification_result.get("verified_at"),
        "trust_score": trust_score,
        "trust_level": trust_level,
        "trust_description": description,
        "verification_id": verification_result.get("verification_id"),
        "has_signature": bool(verification_result.get("issuer_signature")),
        "badge_color": "green" if trust_score >= 80 else ("yellow" if trust_score >= 50 else "red"),
        "badge_icon": "shield-check" if trust_score >= 80 else ("alert" if trust_score >= 50 else "x-circle")
    }
