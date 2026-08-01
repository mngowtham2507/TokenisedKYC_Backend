"""
Tokenised KYC System - FastAPI Backend
Main application entry point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database import init_db
from auth import router as auth_router
from kyc.issue import router as kyc_issue_router
from kyc.verify import router as kyc_verify_router
from kyc.revoke import router as kyc_revoke_router
from consent.request import router as consent_request_router
from consent.approve import router as consent_approve_router
from audit.logs import router as audit_router
from documents.upload import router as documents_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database connection on startup"""
    await init_db()
    yield


app = FastAPI(
    title="Tokenised KYC API",
    description="A decentralized KYC system with verifiable credentials",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(kyc_issue_router, prefix="/kyc", tags=["KYC"])
app.include_router(kyc_verify_router, prefix="/kyc", tags=["KYC"])
app.include_router(kyc_revoke_router, prefix="/kyc", tags=["KYC"])
app.include_router(consent_request_router, prefix="/consent", tags=["Consent"])
app.include_router(consent_approve_router, prefix="/consent", tags=["Consent"])
app.include_router(audit_router, prefix="/audit", tags=["Audit"])
app.include_router(documents_router, prefix="/documents", tags=["Documents"])


@app.get("/")
async def root():
    return {
        "message": "Tokenised KYC API",
        "version": "1.0.0",
        "endpoints": {
            "auth": "/auth",
            "kyc": "/kyc",
            "consent": "/consent",
            "audit": "/audit",
            "documents": "/documents"
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
