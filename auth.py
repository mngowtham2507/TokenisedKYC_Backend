"""
Authentication module with Supabase Auth support
"""
import os
import requests
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt
from jwt import PyJWKClient
from dotenv import load_dotenv

from database import get_db
from utils.crypto import generate_key_pair

load_dotenv()

router = APIRouter()
security = HTTPBearer()

# Supabase settings
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")

# JWKS client for ECC key verification (cached)
_jwks_client = None

def get_jwks_client():
    """Get or create JWKS client for Supabase"""
    global _jwks_client
    if _jwks_client is None and SUPABASE_URL:
        jwks_url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
        _jwks_client = PyJWKClient(jwks_url)
    return _jwks_client


# Pydantic Models
class UserRegister(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserCreate(BaseModel):
    email: EmailStr
    name: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    public_key: Optional[str] = None
    kyc_status: Optional[str] = None
    created_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify Supabase JWT token and return payload"""
    token = credentials.credentials
    
    try:
        # First, try to get the signing key from JWKS (ECC keys)
        jwks_client = get_jwks_client()
        if jwks_client:
            try:
                signing_key = jwks_client.get_signing_key_from_jwt(token)
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["ES256", "RS256"],
                    audience="authenticated"
                )
                return payload
            except Exception:
                pass  # Fall through to try HS256
        
        # Fallback: Try HS256 with legacy JWT secret
        if SUPABASE_JWT_SECRET:
            payload = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated"
            )
            return payload
        
        raise jwt.InvalidTokenError("No valid signing key found")
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


async def get_current_user(token_payload: dict = Depends(verify_token)) -> dict:
    """Get current user from Supabase token"""
    db = get_db()
    user_id = token_payload.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    result = db.table("users").select("*").eq("id", user_id).execute()
    
    if not result.data:
        # User authenticated with Supabase but not in our users table yet
        # This can happen with new users - create profile from token info
        email = token_payload.get("email", "")
        user_metadata = token_payload.get("user_metadata", {})
        name = user_metadata.get("name", email.split("@")[0])
        
        # Generate key pair for user
        from utils.crypto import generate_key_pair
        private_key, public_key = generate_key_pair()
        
        new_user = db.table("users").insert({
            "id": user_id,
            "email": email,
            "name": name,
            "public_key": public_key,
            "kyc_status": "pending"
        }).execute()
        
        if not new_user.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user profile"
            )
        
        return new_user.data[0]
    
    return result.data[0]


@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    """Register a new user with Supabase Auth"""
    db = get_db()
    
    try:
        # Sign up user with Supabase Auth
        auth_response = db.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password,
            "options": {
                "data": {
                    "name": user_data.name
                }
            }
        })
        
        if not auth_response.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user account"
            )
        
        user_id = auth_response.user.id
        
        # Generate key pair for user
        private_key, public_key = generate_key_pair()
        
        # Create user profile in users table
        try:
            user_profile = db.table("users").insert({
                "id": user_id,
                "email": user_data.email,
                "name": user_data.name,
                "public_key": public_key,
                "kyc_status": "pending"
            }).execute()
            
            if not user_profile.data:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user profile"
                )
        except Exception as e:
            # If profile creation fails, user might already exist
            # Try to get existing profile
            existing = db.table("users").select("*").eq("id", user_id).execute()
            if existing.data:
                user_profile = existing
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Database error: {str(e)}"
                )
        
        profile = user_profile.data[0]
        
        return TokenResponse(
            access_token=auth_response.session.access_token,
            user=UserResponse(
                id=profile["id"],
                email=profile["email"],
                name=profile["name"],
                public_key=profile.get("public_key"),
                kyc_status=profile.get("kyc_status", "pending"),
                created_at=profile["created_at"]
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login user with Supabase Auth"""
    db = get_db()
    
    try:
        # Sign in with Supabase Auth
        auth_response = db.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if not auth_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        user_id = auth_response.user.id
        
        # Get user profile from users table
        try:
            user_profile = db.table("users").select("*").eq("id", user_id).execute()
            
            if not user_profile.data:
                # Create profile if it doesn't exist (shouldn't happen but handle it)
                user_metadata = auth_response.user.user_metadata or {}
                name = user_metadata.get("name", credentials.email.split("@")[0])
                
                private_key, public_key = generate_key_pair()
                
                user_profile = db.table("users").insert({
                    "id": user_id,
                    "email": credentials.email,
                    "name": name,
                    "public_key": public_key,
                    "kyc_status": "pending"
                }).execute()
                
                if not user_profile.data:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to retrieve user profile"
                    )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error querying schema: {str(e)}"
            )
        
        profile = user_profile.data[0]
        
        return TokenResponse(
            access_token=auth_response.session.access_token,
            user=UserResponse(
                id=profile["id"],
                email=profile["email"],
                name=profile["name"],
                public_key=profile.get("public_key"),
                kyc_status=profile.get("kyc_status", "pending"),
                created_at=profile["created_at"]
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Login failed: {str(e)}"
        )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"],
        public_key=current_user.get("public_key"),
        kyc_status=current_user.get("kyc_status", "pending"),
        created_at=current_user["created_at"]
    )
