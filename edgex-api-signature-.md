# edgeX API 签名算法逆向分析

## 请求头

| Header | 说明 |
|--------|------|
| `X-edgeX-Api-Key` | API Key (UUID 格式) |
| `X-edgeX-Passphrase` | Passphrase (Base64 编码) |
| `X-edgeX-Signature` | HMAC-SHA256 签名 (64位十六进制) |
| `X-edgeX-Timestamp` | 毫秒级时间戳 |

## 签名算法

### 核心逻辑

```javascript
// 原始代码 (从 index.6228c43031cb36ca.js 逆向)
let y = e => {
    var t, a;
    let r, i, s, {timestamp: o, httpMethod: l, requestUri: d, requestBody: c, secret: u} = e;
    return t = o + l + d + c,           // 消息 = timestamp + httpMethod + requestUri + requestBody
    r = new TextEncoder,
    a = btoa(encodeURI(u)),              // 密钥 = btoa(encodeURI(secret))
    i = r.encode(t),                     // 消息编码为 bytes
    (s = n.sha256.hmac.create(a)).update(i),  // HMAC-SHA256
    s.hex()                              // 返回十六进制
}
```

### 签名步骤

1. **拼接消息**: `message = timestamp + httpMethod + requestUri + requestBody`
2. **处理密钥**: `key = btoa(encodeURI(secret))`
3. **计算签名**: `signature = HMAC-SHA256(key, message).hex()`

### 参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `timestamp` | 毫秒级时间戳字符串 | `"1770023281565"` |
| `httpMethod` | 大写的 HTTP 方法 | `"GET"`, `"POST"` |
| `requestUri` | API 路径 | `/api/v1/private/user/getUserInfo` |
| `requestBody` | 请求体 | GET: 查询参数; POST: JSON 字符串 |
| `secret` | API Secret | `"********"` |

## 测试代码

### Node.js 实现

```javascript
const crypto = require('crypto');

/**
 * 生成 edgeX API 签名
 * @param {string} timestamp - 毫秒级时间戳
 * @param {string} httpMethod - HTTP 方法 (GET, POST 等)
 * @param {string} requestUri - API 路径
 * @param {string} requestBody - 请求体 (GET 为查询参数, POST 为 JSON)
 * @param {string} secret - API Secret
 * @returns {string} 签名 (64位十六进制)
 */
function generateSignature(timestamp, httpMethod, requestUri, requestBody, secret) {
  // 1. 拼接消息
  const message = timestamp + httpMethod + requestUri + requestBody;

  // 2. 处理密钥: btoa(encodeURI(secret))
  const key = Buffer.from(encodeURIComponent(secret)).toString('base64');

  // 3. HMAC-SHA256 签名
  const signature = crypto.createHmac('sha256', key).update(message).digest('hex');

  return signature;
}

// 测试
const secret = '*****';

// 测试1: GET 请求
const test1 = {
  timestamp: '1770023281565',
  httpMethod: 'GET',
  requestUri: '/api/v1/private/user/getSiteMessagePage',
  requestBody: '',
  expectedSig: '4fb183c895864899d4e98e5690c827433a28abe757e34e81e8d751fa3e1ed481'
};

const sig1 = generateSignature(
  test1.timestamp,
  test1.httpMethod,
  test1.requestUri,
  test1.requestBody,
  secret
);
console.log('Test 1:', sig1 === test1.expectedSig ? '✅ PASS' : '❌ FAIL');

// 测试2: GET 请求
const test2 = {
  timestamp: '1770023330270',
  httpMethod: 'GET',
  requestUri: '/api/v1/private/user/getUserInfo',
  requestBody: '',
  expectedSig: 'bb4ca232a70c78cfcabe6e4e72a1c6eb4dc10106c6338eb0d35fe9da7b0bbd14'
};

const sig2 = generateSignature(
  test2.timestamp,
  test2.httpMethod,
  test2.requestUri,
  test2.requestBody,
  secret
);
console.log('Test 2:', sig2 === test2.expectedSig ? '✅ PASS' : '❌ FAIL');
```

### Python 实现

```python
import hmac
import hashlib
import base64
import urllib.parse
import time

def generate_signature(timestamp: str, http_method: str, request_uri: str, request_body: str, secret: str) -> str:
    """
    生成 edgeX API 签名

    Args:
        timestamp: 毫秒级时间戳字符串
        http_method: HTTP 方法 (GET, POST 等)
        request_uri: API 路径
        request_body: 请求体
        secret: API Secret

    Returns:
        签名 (64位十六进制字符串)
    """
    # 1. 拼接消息
    message = timestamp + http_method + request_uri + request_body

    # 2. 处理密钥: base64(encodeURI(secret))
    encoded_secret = urllib.parse.quote(secret, safe='')
    key = base64.b64encode(encoded_secret.encode()).decode()

    # 3. HMAC-SHA256 签名
    signature = hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature


# 测试
if __name__ == '__main__':
    secret = '*****'

    # 测试1
    sig1 = generate_signature(
        '1770023281565',
        'GET',
        '/api/v1/private/user/getSiteMessagePage',
        '',
        secret
    )
    expected1 = '4fb183c895864899d4e98e5690c827433a28abe757e34e81e8d751fa3e1ed481'
    print(f'Test 1: {"✅ PASS" if sig1 == expected1 else "❌ FAIL"}')

    # 测试2
    sig2 = generate_signature(
        '1770023330270',
        'GET',
        '/api/v1/private/user/getUserInfo',
        '',
        secret
    )
    expected2 = 'bb4ca232a70c78cfcabe6e4e72a1c6eb4dc10106c6338eb0d35fe9da7b0bbd14'
    print(f'Test 2: {"✅ PASS" if sig2 == expected2 else "❌ FAIL"}')
```

## 完整请求示例

### Node.js 发起请求

```javascript
const crypto = require('crypto');
const axios = require('axios');

const API_KEY = '*****';
const PASSPHRASE = '*****';
const SECRET = '*****';
const BASE_URL = 'https://pro.edgex.exchange';

function generateSignature(timestamp, httpMethod, requestUri, requestBody, secret) {
  const message = timestamp + httpMethod + requestUri + requestBody;
  const key = Buffer.from(encodeURIComponent(secret)).toString('base64');
  return crypto.createHmac('sha256', key).update(message).digest('hex');
}

async function request(method, path, params = {}, data = null) {
  const timestamp = Date.now().toString();

  let requestUri = path;
  let requestBody = '';

  if (method === 'GET' && Object.keys(params).length > 0) {
    const queryString = new URLSearchParams(params).toString();
    requestUri = path;  // URI 不包含查询参数
    requestBody = queryString;  // requestBody 是查询参数
  } else if (method === 'POST' && data) {
    requestBody = JSON.stringify(data);
  }

  const signature = generateSignature(timestamp, method, requestUri, requestBody, SECRET);

  const headers = {
    'X-edgeX-Api-Key': API_KEY,
    'X-edgeX-Passphrase': PASSPHRASE,
    'X-edgeX-Signature': signature,
    'X-edgeX-Timestamp': timestamp,
    'Content-Type': 'application/json'
  };

  const url = method === 'GET' && Object.keys(params).length > 0
    ? `${BASE_URL}${path}?${new URLSearchParams(params).toString()}`
    : `${BASE_URL}${path}`;

  const response = await axios({
    method,
    url,
    headers,
    data: method === 'POST' ? data : undefined
  });

  return response.data;
}

// 使用示例
async function main() {
  // GET 请求
  const userInfo = await request('GET', '/api/v1/private/user/getUserInfo');
  console.log('User Info:', userInfo);

  // POST 请求
  const order = await request('POST', '/api/v1/private/order/createOrder', {}, {
    price: '66832.9',
    size: '0.001',
    type: 'LIMIT',
    side: 'BUY',
    // ... 其他参数
  });
  console.log('Order:', order);
}

main().catch(console.error);
```

## 密钥生成逻辑

从钱包签名生成 API 密钥对的完整过程。

### 签名消息格式

```
action: edgeX Onboard
onlySignOn: https://pro.edgex.exchange
```

### 算法步骤

```
签名 m (65 bytes) = wallet.signMessage(message)
    ↓
┌─────────────────────────────────────────────────────────────┐
│  r (前32字节)    │    s (中32字节)     │  v (1字节)         │
│  m[0:32]         │    m[32:64]          │  m[64:65]          │
└─────────────────────────────────────────────────────────────┘
    ↓                      ↓
 Keccak256(r)          Keccak256(s)
    ↓                      ↓
    A                      _
    ↓                      ↓
 Base64(A)            ┌────┴────┐
    ↓                 ↓         ↓
  secret         _[0:16]    _[16:32]
                    ↓         ↓
                UUID格式   Base64()
                    ↓         ↓
                 apiKey   passphrase
```

### 核心代码

```javascript
const { keccak256 } = require('ethers/lib/utils');

/**
 * 从钱包签名生成 edgeX API 密钥对
 * @param {string} signature - 钱包签名 (0x开头的十六进制字符串, 65字节)
 * @returns {object} { apiKey, passphrase, secret }
 */
function generateKeyPair(signature) {
  // 1. 去掉 0x 前缀，转为 Buffer
  const sigHex = signature.startsWith('0x') ? signature.slice(2) : signature;
  const sigBytes = Buffer.from(sigHex, 'hex');

  // 2. 分割签名: r (前32字节), s (中32字节)
  const r = sigBytes.slice(0, 32);
  const s = sigBytes.slice(32, 64);

  // 3. Keccak256 哈希
  const A = keccak256(r);  // 用于生成 secret
  const _ = keccak256(s);  // 用于生成 apiKey 和 passphrase

  // 4. 从 A 生成 secret (全部32字节 Base64编码)
  const ABytes = Buffer.from(A.slice(2), 'hex');
  const secret = ABytes.toString('base64').replace(/=+$/, '');

  // 5. 从 _ 生成 apiKey (前16字节转UUID格式)
  const _Bytes = Buffer.from(_.slice(2), 'hex');
  const apiKeyHex = _Bytes.slice(0, 16).toString('hex');
  const apiKey = [
    apiKeyHex.slice(0, 8),
    apiKeyHex.slice(8, 12),
    apiKeyHex.slice(12, 16),
    apiKeyHex.slice(16, 20),
    apiKeyHex.slice(20, 32)
  ].join('-');

  // 6. 从 _ 生成 passphrase (后16字节 Base64编码)
  const passphrase = _Bytes.slice(16, 32).toString('base64').replace(/=+$/, '');

  return { apiKey, passphrase, secret };
}

// 使用示例
const signature = '*****';
const keyPair = generateKeyPair(signature);
console.log(keyPair);
// {
//   apiKey: '*****',
//   passphrase: '*****',
//   secret: '*****'
// }
```

### Python 实现

```python
from eth_hash.auto import keccak
import base64

def generate_key_pair(signature: str) -> dict:
    """
    从钱包签名生成 edgeX API 密钥对

    Args:
        signature: 钱包签名 (0x开头的十六进制字符串, 65字节)

    Returns:
        dict: { 'apiKey', 'passphrase', 'secret' }
    """
    # 1. 去掉 0x 前缀，转为 bytes
    sig_hex = signature[2:] if signature.startswith('0x') else signature
    sig_bytes = bytes.fromhex(sig_hex)

    # 2. 分割签名: r (前32字节), s (中32字节)
    r = sig_bytes[0:32]
    s = sig_bytes[32:64]

    # 3. Keccak256 哈希
    A = keccak(r)  # 用于生成 secret
    _ = keccak(s)  # 用于生成 apiKey 和 passphrase

    # 4. 从 A 生成 secret
    secret = base64.b64encode(A).decode().rstrip('=')

    # 5. 从 _ 生成 apiKey
    api_key_hex = _.hex()[:32]  # 前16字节
    api_key = f"{api_key_hex[0:8]}-{api_key_hex[8:12]}-{api_key_hex[12:16]}-{api_key_hex[16:20]}-{api_key_hex[20:32]}"

    # 6. 从 _ 生成 passphrase
    passphrase = base64.b64encode(_[16:32]).decode().rstrip('=')

    return {
        'apiKey': api_key,
        'passphrase': passphrase,
        'secret': secret
    }


# 测试
if __name__ == '__main__':
    signature = '*****'
    key_pair = generate_key_pair(signature)

    print('apiKey:', key_pair['apiKey'])
    print('passphrase:', key_pair['passphrase'])
    print('secret:', key_pair['secret'])

    # 验证
    assert key_pair['apiKey'] == '*****'
    assert key_pair['passphrase'] == '*****'
    assert key_pair['secret'] == '*****'
    print('✅ All tests passed!')
```

### 完整流程示例

```javascript
const { ethers } = require('ethers');

async function createEdgeXApiKey(wallet) {
  // 1. 构造签名消息
  const message = `action: edgeX Onboard
onlySignOn: https://pro.edgex.exchange`;

  // 2. 钱包签名
  const signature = await wallet.signMessage(message);

  // 3. 生成密钥对
  const keyPair = generateKeyPair(signature);

  return {
    ...keyPair,
    signature,
    address: wallet.address
  };
}

// 使用示例
async function main() {
  // 从私钥创建钱包
  const privateKey = '0x...'; // 你的私钥
  const wallet = new ethers.Wallet(privateKey);

  const credentials = await createEdgeXApiKey(wallet);
  console.log('API Key:', credentials.apiKey);
  console.log('Passphrase:', credentials.passphrase);
  console.log('Secret:', credentials.secret);
}
```

### 测试数据

| 字段 | 值 |
|------|-----|
| 钱包地址 | `*****` |
| 签名消息 | `action: edgeX Onboard\nonlySignOn: https://pro.edgex.exchange` |
| 签名结果 | `*****` |
| Keccak256(r) | `*****` |
| Keccak256(s) | `*****` |
| **apiKey** | `*****` |
| **passphrase** | `*****` |
| **secret** | `*****` |

## 注意事项

1. **时间戳**: 必须是毫秒级时间戳，与服务器时间偏差不能太大
2. **requestBody**:
   - GET 请求: 是查询参数字符串 (不含 `?`)
   - POST 请求: 是完整的 JSON 字符串
3. **requestUri**: 只包含路径，不包含查询参数和域名
4. **密钥处理**: secret 需要先 `encodeURI` 再 `btoa` 编码

---

*逆向分析于 2026-02-02，源代码: index.6228c43031cb36ca.js*
