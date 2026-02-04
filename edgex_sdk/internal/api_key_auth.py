"""
API Key authentication utilities for edgeX.

This module provides utilities for generating API credentials from wallet signatures
and signing requests using HMAC-SHA256.
"""

import base64
import hmac
import hashlib
import time
import urllib.parse
from typing import Dict, Any, Optional
from eth_hash.auto import keccak
from eth_account import Account
from eth_account.messages import encode_defunct


def generate_key_pair_from_signature(signature: str) -> Dict[str, str]:
    """
    Generate edgeX API key pair from wallet signature.

    Args:
        signature: Wallet signature (0x-prefixed hex string, 65 bytes)

    Returns:
        dict with keys: 'apiKey', 'passphrase', 'secret'
    """
    # 1. Remove 0x prefix and convert to bytes
    sig_hex = signature[2:] if signature.startswith('0x') else signature
    sig_bytes = bytes.fromhex(sig_hex)

    # 2. Split signature: r (first 32 bytes), s (middle 32 bytes)
    r = sig_bytes[0:32]
    s = sig_bytes[32:64]

    # 3. Keccak256 hash
    A = keccak(r)  # For generating secret
    _ = keccak(s)  # For generating apiKey and passphrase

    # 4. Generate secret from A (all 32 bytes, URL-safe Base64 encoded)
    secret = base64.urlsafe_b64encode(A).decode().rstrip('=')

    # 5. Generate apiKey from _ (first 16 bytes to UUID format)
    api_key_hex = _.hex()[:32]  # First 16 bytes
    api_key = f"{api_key_hex[0:8]}-{api_key_hex[8:12]}-{api_key_hex[12:16]}-{api_key_hex[16:20]}-{api_key_hex[20:32]}"

    # 6. Generate passphrase from _ (last 16 bytes, URL-safe Base64 encoded)
    passphrase = base64.urlsafe_b64encode(_[16:32]).decode().rstrip('=')

    return {
        'apiKey': api_key,
        'passphrase': passphrase,
        'secret': secret
    }


def generate_signature(timestamp: str, http_method: str, request_uri: str,
                      request_body: str, secret: str) -> str:
    """
    Generate edgeX API HMAC-SHA256 signature.

    Args:
        timestamp: Millisecond timestamp string
        http_method: HTTP method (GET, POST, etc.)
        request_uri: API path
        request_body: Request body (query string for GET, JSON for POST)
        secret: API Secret

    Returns:
        Signature (64-character hex string)
    """
    # 1. Build message
    message = timestamp + http_method + request_uri + request_body

    # 2. Process key: urlsafe_base64(encodeURI(secret))
    encoded_secret = urllib.parse.quote(secret, safe='')
    key = base64.urlsafe_b64encode(encoded_secret.encode()).decode()

    # 3. HMAC-SHA256 signature
    signature = hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature


def build_api_key_headers(api_key: str, passphrase: str, secret: str,
                          timestamp: str, http_method: str, request_uri: str,
                          request_body: str = '') -> Dict[str, str]:
    """
    Build HTTP headers for API Key authentication.

    Args:
        api_key: API Key
        passphrase: API Passphrase
        secret: API Secret
        timestamp: Millisecond timestamp
        http_method: HTTP method
        request_uri: Request URI path
        request_body: Request body (optional)

    Returns:
        Dictionary of headers
    """
    signature = generate_signature(timestamp, http_method, request_uri, request_body, secret)

    return {
        'X-edgeX-Api-Key': api_key,
        'X-edgeX-Passphrase': passphrase,
        'X-edgeX-Signature': signature,
        'X-edgeX-Timestamp': timestamp
    }


def get_current_timestamp() -> str:
    """Get current millisecond timestamp as string."""
    return str(int(time.time() * 1000))


def generate_credentials_from_wallet(wallet_private_key: str) -> Dict[str, str]:
    """
    Generate edgeX API credentials from wallet private key.

    This function:
    1. Constructs the signing message
    2. Signs with the wallet private key
    3. Generates API Key, Passphrase, and Secret from the signature

    Args:
        wallet_private_key: Wallet private key (0x-prefixed or not)

    Returns:
        dict with keys: 'apiKey', 'passphrase', 'secret'
    """
    # 1. Construct the message to sign
    message = "action: edgeX Onboard\nonlySignOn: https://pro.edgex.exchange"

    # 2. Sign the message with wallet
    # Ensure private key has 0x prefix
    if not wallet_private_key.startswith('0x'):
        wallet_private_key = '0x' + wallet_private_key

    # Create signable message
    message_obj = encode_defunct(text=message)

    # Sign the message
    signed_message = Account.sign_message(message_obj, wallet_private_key)
    signature = signed_message.signature.hex()

    # 3. Generate API credentials from signature
    return generate_key_pair_from_signature(signature)