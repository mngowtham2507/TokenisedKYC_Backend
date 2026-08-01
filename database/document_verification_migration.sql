-- Migration: Add document verification fields to kyc_documents table
-- This adds support for verified document sources (DigiLocker, UIDAI, NSDL, etc.)

-- Add new columns for document verification
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS verification_source VARCHAR(50);
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS verification_id VARCHAR(100);
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS issuer_signature TEXT;
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS issuer_name VARCHAR(255);
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS document_hash VARCHAR(64);
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS extracted_data JSONB;

-- Add check constraint for verification sources
-- Sources: digilocker, uidai, nsdl, manual_verified, unverified
ALTER TABLE kyc_documents DROP CONSTRAINT IF EXISTS kyc_documents_verification_source_check;
ALTER TABLE kyc_documents ADD CONSTRAINT kyc_documents_verification_source_check 
    CHECK (verification_source IS NULL OR verification_source IN ('digilocker', 'uidai', 'nsdl', 'passport_seva', 'rto', 'manual_verified', 'unverified'));

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_kyc_documents_verification ON kyc_documents(verification_source, status);

-- Comment explaining the verification sources:
-- digilocker: Document fetched from DigiLocker API (government authenticated)
-- uidai: Aadhaar verified directly via UIDAI e-KYC API
-- nsdl: PAN verified via NSDL/Income Tax Department
-- passport_seva: Passport verified via Passport Seva
-- rto: Driving License verified via Regional Transport Office
-- manual_verified: Manually verified by admin/agent
-- unverified: Document uploaded but not verified (should not be trusted)

COMMENT ON COLUMN kyc_documents.verification_source IS 'Source that verified the document authenticity';
COMMENT ON COLUMN kyc_documents.verification_id IS 'Unique ID from the verification source (e.g., DigiLocker URI)';
COMMENT ON COLUMN kyc_documents.issuer_signature IS 'Digital signature from the issuing authority';
COMMENT ON COLUMN kyc_documents.issuer_name IS 'Name of the issuing authority (e.g., UIDAI, Income Tax Dept)';
COMMENT ON COLUMN kyc_documents.verified_at IS 'Timestamp when the document was verified';
COMMENT ON COLUMN kyc_documents.document_hash IS 'SHA-256 hash of the document for integrity check';
COMMENT ON COLUMN kyc_documents.extracted_data IS 'Data extracted from the verified document (name, DOB, etc.)';
