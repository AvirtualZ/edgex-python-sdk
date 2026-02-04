"""
演示 EdgeX WebSocket API Key 签名计算过程
"""

import hmac
import hashlib
import base64
import urllib.parse
from eth_hash.auto import keccak
from eth_account import Account
from eth_account.messages import encode_defunct


def generate_key_pair_from_signature(signature: str):
    """从钱包签名生成 API Key 三件套"""
    sig_hex = signature[2:] if signature.startswith('0x') else signature
    sig_bytes = bytes.fromhex(sig_hex)

    r = sig_bytes[0:32]
    s = sig_bytes[32:64]

    A = keccak(r)  # 用于生成 secret
    _ = keccak(s)  # 用于生成 apiKey 和 passphrase

    # 使用 URL-safe Base64 编码
    secret = base64.urlsafe_b64encode(A).decode().rstrip('=')

    api_key_hex = _.hex()[:32]
    api_key = f"{api_key_hex[0:8]}-{api_key_hex[8:12]}-{api_key_hex[12:16]}-{api_key_hex[16:20]}-{api_key_hex[20:32]}"

    passphrase = base64.urlsafe_b64encode(_[16:32]).decode().rstrip('=')

    return {
        'apiKey': api_key,
        'passphrase': passphrase,
        'secret': secret
    }


def generate_signature(timestamp: str, http_method: str, request_uri: str,
                      request_body: str, secret: str) -> str:
    """生成 HMAC-SHA256 签名"""
    # 1. 构建签名消息
    message = timestamp + http_method + request_uri + request_body
    print(f"签名消息: {message}")

    # 2. 处理密钥: urlsafe_base64(encodeURI(secret))
    encoded_secret = urllib.parse.quote(secret, safe='')
    print(f"URL编码后的secret: {encoded_secret}")

    key = base64.urlsafe_b64encode(encoded_secret.encode()).decode()
    print(f"最终密钥: {key}")

    # 3. HMAC-SHA256 签名
    signature = hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature


def generate_credentials_from_wallet(wallet_private_key: str):
    """从钱包私钥生成 API 凭证"""
    message = "action: edgeX Onboard\nonlySignOn: https://pro.edgex.exchange"

    if not wallet_private_key.startswith('0x'):
        wallet_private_key = '0x' + wallet_private_key

    message_obj = encode_defunct(text=message)
    signed_message = Account.sign_message(message_obj, wallet_private_key)
    signature = signed_message.signature.hex()

    return generate_key_pair_from_signature(signature)


# ============ 演示签名计算过程 ============

if __name__ == "__main__":
    print("=" * 60)
    print("EdgeX WebSocket API Key 签名计算演示")
    print("=" * 60)

    # 步骤1: 从钱包私钥生成凭证
    print("\n步骤1: 从钱包私钥生成 API 凭证")
    print("-" * 60)

    # 这里需要你的真实 wallet_private_key
    wallet_private_key = "0x9192af8ffa7d63822df68353ea5670cbb59aabbef015f02e68c80499f2492c05"

    try:
        credentials = generate_credentials_from_wallet(wallet_private_key)

        print(f"API Key:      {credentials['apiKey']}")
        print(f"Passphrase:   {credentials['passphrase']}")
        print(f"Secret:       {credentials['secret']}")

        # 步骤2: 计算签名
        print("\n步骤2: 计算 WebSocket 签名")
        print("-" * 60)

        timestamp = "1770185020235"
        http_method = "GET"
        account_id = "712406899546391509"  # 替换为你的 account_id
        request_uri = f"/api/v1/private/ws"
        request_body = f"accountId={account_id}&timestamp={timestamp}"

        signature = generate_signature(
            timestamp=timestamp,
            http_method=http_method,
            request_uri=request_uri,
            request_body=request_body,
            secret=credentials['secret']
        )

        print(f"\n计算出的签名: {signature}")

        # 步骤3: 构建 sec-websocket-protocol
        print("\n步骤3: 构建 sec-websocket-protocol")
        print("-" * 60)

        import json

        auth_data = {
            "X-edgeX-Api-Key": credentials['apiKey'],
            "X-edgeX-Passphrase": credentials['passphrase'],
            "X-edgeX-Signature": signature,
            "X-edgeX-Timestamp": timestamp
        }

        protocol_value = base64.urlsafe_b64encode(json.dumps(auth_data).encode()).decode()
        print(f"sec-websocket-protocol: {protocol_value}")

    except Exception as e:
        print(f"\n错误: {e}")
        print("\n请替换以下变量后重试:")
        print("  1. wallet_private_key - 你的钱包私钥")
        print("  2. account_id - 你的 EdgeX account ID")
