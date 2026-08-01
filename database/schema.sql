-- Tokenised KYC System Database Schema
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (uses Supabase Auth user IDs)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,  -- References auth.users(id) from Supabase Auth
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    public_key TEXT,
    kyc_status VARCHAR(20) DEFAULT 'pending' CHECK (kyc_status IN ('pending', 'documents_uploaded', 'verified', 'rejected')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- KYC Documents table (for document uploads)
CREATE TABLE IF NOT EXISTS kyc_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    document_type VARCHAR(50) NOT NULL CHECK (document_type IN ('aadhaar_front', 'aadhaar_back', 'pan_card', 'passport', 'driving_license', 'voter_id', 'selfie')),
    file_name VARCHAR(255) NOT NULL,
    file_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'rejected')),
    rejection_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, document_type)
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
    requester_name VARCHAR(255),
    requested_fields TEXT[] NOT NULL,
    purpose TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID REFERENCES kyc_tokens(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    performed_by VARCHAR(255) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_kyc_documents_user_id ON kyc_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_documents_status ON kyc_documents(status);
CREATE INDEX IF NOT EXISTS idx_kyc_tokens_user_id ON kyc_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_tokens_status ON kyc_tokens(status);
CREATE INDEX IF NOT EXISTS idx_consent_requests_token_id ON consent_requests(token_id);
CREATE INDEX IF NOT EXISTS idx_consent_requests_status ON consent_requests(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_token_id ON audit_logs(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Row Level Security (RLS) Policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE kyc_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE kyc_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Service role has full access to users" ON users;
DROP POLICY IF EXISTS "Service role has full access to kyc_documents" ON kyc_documents;
DROP POLICY IF EXISTS "Service role has full access to kyc_tokens" ON kyc_tokens;
DROP POLICY IF EXISTS "Service role has full access to consent_requests" ON consent_requests;
DROP POLICY IF EXISTS "Service role has full access to audit_logs" ON audit_logs;
DROP POLICY IF EXISTS "Users can view own profile" ON users;
DROP POLICY IF EXISTS "Users can insert own profile" ON users;
DROP POLICY IF EXISTS "Users can update own profile" ON users;
DROP POLICY IF EXISTS "Users can view own documents" ON kyc_documents;
DROP POLICY IF EXISTS "Users can insert own documents" ON kyc_documents;
DROP POLICY IF EXISTS "Users can delete own documents" ON kyc_documents;

-- Allow service role full access (for backend)
CREATE POLICY "Service role has full access to users" ON users
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role has full access to kyc_documents" ON kyc_documents
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role has full access to kyc_tokens" ON kyc_tokens
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role has full access to consent_requests" ON consent_requests
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role has full access to audit_logs" ON audit_logs
    FOR ALL USING (auth.role() = 'service_role');

-- Users can read/update their own profile
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON users
    FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Users can manage their own documents
CREATE POLICY "Users can view own documents" ON kyc_documents
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own documents" ON kyc_documents
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own documents" ON kyc_documents
    FOR DELETE USING (auth.uid() = user_id);

-- =====================================================
-- STORAGE BUCKET SETUP (Run in Supabase Dashboard)
-- =====================================================
-- 1. Go to Storage in Supabase Dashboard
-- 2. Create a new bucket named 'kyc-documents'
-- 3. Set it as a private bucket
-- 4. Add the following storage policies:

-- Storage policy: Users can upload to their own folder
-- CREATE POLICY "Users can upload own documents"
-- ON storage.objects FOR INSERT
-- WITH CHECK (bucket_id = 'kyc-documents' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Storage policy: Users can view their own documents
-- CREATE POLICY "Users can view own documents"
-- ON storage.objects FOR SELECT
-- USING (bucket_id = 'kyc-documents' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Storage policy: Users can delete their own documents
-- CREATE POLICY "Users can delete own documents"
-- ON storage.objects FOR DELETE
-- USING (bucket_id = 'kyc-documents' AND auth.uid()::text = (storage.foldername(name))[1]);
