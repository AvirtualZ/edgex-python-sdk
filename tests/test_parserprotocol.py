# import base64, json;
# data='eyJYLWVkZ2VYLUFwaS1LZXkiOiI4OGUzODM2Zi1lZDBmLTk0MjUtZTA3Yy01ZDM2YTFlZDFhNDciLCJYLWVkZ2VYLVBhc3NwaHJhc2UiOiJpaWZJSU44cDZJY3RlYlZUWXdNX2VRIiwiWC1lZGdlWC1TaWduYXR1cmUiOiIzMzAxZmZlZWYzZDFhYTI1ZTk0MGVlNWZiNmM2N2IwN2EwN2JmMTRjN2M3NmY1YTVhZjI3N2JmNmQxOThlMDM3IiwiWC1lZGdlWC1UaW1lc3RhbXAiOiIxNzcwMTg1MDIwMjM1In0'; 
# padded = data + '=' * (4 - len(data) % 4); 
# print(json.dumps(json.loads(base64.b64decode(padded)), indent=2))







import json
import base64

# 1. JSON 对象
auth_data = {
  "x-edgex-api-key": "88e3836f-ed0f-9425-e07c-5d36a1ed1a47",
  "x-edgex-passphrase": "iifIIN8p6IctebVTYwM_eQ",
  "x-edgex-signature": "3301ffeef3d1aa25e940ee5fb6c67b07a07bf14c7c76f5a5af277bf6d198e037",
  "x-edgex-timestamp": "1770185020235"
}

# 2. JSON 转字符串（无空格）
json_str = json.dumps(auth_data, separators=(',', ':'))
# {"X-edgeX-Api-Key":"88e3836f-ed0f-9425-e07c-5d36a1ed1a47",...}

# 3. UTF-8 编码
json_bytes = json_str.encode('utf-8')

# 4. Base64 编码
b64_encoded = base64.b64encode(json_bytes).decode()
# eyJYLWVkZ2VYLUFwaS1LZXkiOiI4OGUzODM2Zi1lZDBmLTk0MjUtZTA3Yy01ZDM2YTFlZDFhNDciLCJYLWVkZ2VYLVBhc3NwaHJhc2UiOiJpaWZJSU44cDZJY3RlYlZUWXdNX2VRIiwiWC1lZGdlWC1TaWduYXR1cmUiOiIzMzAxZmZlZWYzZDFhYTI1ZTk0MGVlNWZiNmM2N2IwN2EwN2JmMTRjN2M3NmY1YTVhZjI3N2JmNmQxOThlMDM3IiwiWC1lZGdlWC1UaW1lc3RhbXAiOiIxNzcwMTg1MDIwMjM1In0=


print(b64_encoded)
