"""
Cryptographic utilities for signing and verifying credentials
"""
import os
import base64
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import jwt
from dotenv import load_dotenv

load_dotenv()

# Path to store persistent keys
KEYS_FILE = os.path.join(os.path.dirname(__file__), '..', 'keys.json')

# System keys (loaded or generated)
_system_private_key = None
_system_public_key = None


def _load_or_generate_keys():
    """Load keys from file or generate new ones"""
    global _system_private_key, _system_public_key
    
    # Try to load from file
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, 'r') as f:
                keys = json.load(f)
                _system_private_key = keys.get('private_key')
                _system_public_key = keys.get('public_key')
                if _system_private_key and _system_public_key:
                    return
        except Exception as e:
            print(f"Warning: Could not load keys: {e}")
    
    # Generate new keys
    _system_private_key, _system_public_key = generate_key_pair()
    
    # Save to file
    try:
        with open(KEYS_FILE, 'w') as f:
            json.dump({
                'private_key': _system_private_key,
                'public_key': _system_public_key
            }, f)
        print("Generated and saved new system keys")
    except Exception as e:
        print(f"Warning: Could not save keys: {e}")


def generate_key_pair() -> tuple[str, str]:
    """Generate RSA key pair for a user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def get_system_keys() -> tuple[str, str]:
    """Get or generate system signing keys"""
    global _system_private_key, _system_public_key
    
    if not _system_private_key or not _system_public_key:
        _load_or_generate_keys()
    
    return _system_private_key, _system_public_key


def sign_credential(credential_data: dict) -> str:
    """
    Sign a verifiable credential using JWT
    """
    private_key, _ = get_system_keys()
    
    # Create JWT signature
    token = jwt.encode(
        credential_data,
        private_key,
        algorithm="RS256"
    )
    
    return token


def verify_signature(signed_token: str) -> dict:
    """
    Verify a signed credential
    Returns the decoded payload if valid
    """
    _, public_key = get_system_keys()
    
    try:
        payload = jwt.decode(
            signed_token,
            public_key,
            algorithms=["RS256"]
        )
        return {"valid": True, "payload": payload}
    except jwt.InvalidSignatureError:
        return {"valid": False, "error": "Invalid signature"}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Signature expired"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def sign_data_rsa(data: bytes, private_key_pem: str) -> str:
    """Sign data using RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')


def verify_data_rsa(data: bytes, signature: str, public_key_pem: str) -> bool:
    """Verify RSA signature"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        signature_bytes = base64.b64decode(signature)
        
        public_key.verify(
            signature_bytes,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
