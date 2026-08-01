"""
Database configuration and Supabase connection
"""
import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = None


async def init_db():
    """Initialize Supabase client"""
    global supabase
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return supabase


def get_db() -> Client:
    """Get Supabase client instance"""
    global supabase
    if supabase is None:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return supabase


# SQL to create tables in Supabase (run this in Supabase SQL editor)
CREATE_TABLES_SQL = """
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    public_key TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- KYC Tokens table
CREATE TABLE IF NOT EXISTS kyc_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_json JSONB NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Consent Requests table
CREATE TABLE IF NOT EXISTS consent_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES kyc_tokens(id) ON DELETE CASCADE,
    requester VARCHAR(255) NOT NULL,
    requested_fields TEXT[] NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES kyc_tokens(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    performed_by VARCHAR(255) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_kyc_tokens_user_id ON kyc_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_tokens_status ON kyc_tokens(status);
CREATE INDEX IF NOT EXISTS idx_consent_requests_token_id ON consent_requests(token_id);
CREATE INDEX IF NOT EXISTS idx_consent_requests_status ON consent_requests(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_token_id ON audit_logs(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
"""
