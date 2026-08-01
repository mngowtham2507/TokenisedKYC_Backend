"""
Hashing utilities for token integrity
"""
import hashlib
import json


def hash_sha256(data: str) -> str:
    """Create SHA-256 hash of string data"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def hash_json(data: dict) -> str:
    """Create SHA-256 hash of JSON data (deterministic)"""
    # Sort keys for deterministic hashing
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hash_sha256(json_str)


def verify_hash(data: dict, expected_hash: str) -> bool:
    """Verify that data matches expected hash"""
    computed_hash = hash_json(data)
    return computed_hash == expected_hash
