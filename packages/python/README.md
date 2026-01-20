# xhshow

<div align="center">

[![PyPI version](https://badge.fury.io/py/xhshow.svg)](https://badge.fury.io/py/xhshow)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://pypi.org/project/xhshow/)
[![License](https://img.shields.io/github/license/Cloxl/xhshow.svg)](https://github.com/Cloxl/xhshow/blob/main/LICENSE)
[![Downloads](https://pepy.tech/badge/xhshow)](https://pepy.tech/project/xhshow)

小红书请求签名生成库，支持GET和POST请求的x-s签名生成。

</div>

## 系统要求

- Python 3.10+

## 安装

```bash
pip install xhshow
```

## 使用方法

### 基本用法（推荐）

```python
from xhshow import Xhshow
import requests

client = Xhshow()

# 准备 cookies（支持字典或字符串格式）
cookies = {
    "a1": "your_a1_value",
    "web_session": "your_web_session",
    "webId": "your_web_id"
}
# 或使用 Cookie 字符串格式:
# cookies = "a1=your_a1_value; web_session=your_web_session; webId=your_web_id"

# 注意: uri 参数可以传递完整 URL 或 URI 路径，会自动提取 URI
headers = client.sign_headers_get(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",  # 完整 URL（推荐）
    # uri="/api/sns/web/v1/user_posted",  # 或者只传 URI 路径
    cookies=cookies,  # 传入完整 cookies
    params={"num": "30", "cursor": "", "user_id": "123"}
)

# 返回的 headers 包含以下字段:
# {
#     "x-s": "XYS_...",
#     "x-s-common": "...",
#     "x-t": "1234567890",
#     "x-b3-traceid": "...",
#     "x-xray-traceid": "..."
# }

# 方式1: 使用 update 方法更新现有 headers（推荐）
base_headers = {
    "User-Agent": "Mozilla/5.0...",
    "Content-Type": "application/json"
}
base_headers.update(headers)
response = requests.get(
    "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    params={"num": "30", "cursor": "", "user_id": "123"},
    headers=base_headers,
    cookies=cookies
)

# 方式2: 使用 ** 解包创建新 headers
response = requests.get(
    "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    params={"num": "30", "cursor": "", "user_id": "123"},
    headers={
        "User-Agent": "Mozilla/5.0...",
        "Content-Type": "application/json",
        **headers  # 解包签名 headers（会创建新字典）
    },
    cookies=cookies
)

# POST 请求示例：使用 sign_headers_post
headers_post = client.sign_headers_post(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/login",
    cookies=cookies,
    payload={"username": "test", "password": "123456"}
)

response = requests.post(
    "https://edith.xiaohongshu.com/api/sns/web/v1/login",
    json={"username": "test", "password": "123456"},
    headers={**base_headers, **headers_post},
    cookies=cookies
)

# 构建符合xhs平台的GET请求链接
full_url = client.build_url(
    base_url="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    params={"num": "30", "cursor": "", "user_id": "123"}
)
response = requests.get(full_url, headers=headers, cookies=cookies)

# 构建符合xhs平台的POST请求body
json_body = client.build_json_body(
    payload={"username": "test", "password": "123456"}
)
response = requests.post(url, data=json_body, headers=headers, cookies=cookies)
```

<details>
<summary>传统方法（单独生成各个字段）</summary>

```python
from xhshow import Xhshow
import requests

client = Xhshow()

# 注意: sign_headers_* 系列方法使用 cookies 参数
# 而 sign_xs_* 系列方法使用 a1_value 参数

# 使用统一方法 sign_headers（需要手动指定 method）
cookies = {"a1": "your_a1_value", "web_session": "..."}
headers = client.sign_headers(
    method="GET",  # 或 "POST"
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    cookies=cookies,  # sign_headers 使用 cookies 参数
    params={"num": "30"}  # GET 请求使用 params，POST 请求使用 payload
)

# GET 请求签名（使用 sign_xs_get - 只需要 a1_value）
x_s = client.sign_xs_get(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",  # v0.1.3及后续版本支持自动提取uri
    # uri="/api/sns/web/v1/user_posted"  # v0.1.2及以前版本需要主动提取uri
    a1_value="your_a1_cookie_value",  # sign_xs_* 系列使用 a1_value
    params={"num": "30", "cursor": "", "user_id": "123"}
)

# POST 请求签名（使用 sign_xs_post - 只需要 a1_value）
x_s = client.sign_xs_post(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/login",
    a1_value="your_a1_cookie_value",  # sign_xs_* 系列使用 a1_value
    payload={"username": "test", "password": "123456"}
)

# 生成其他 headers 字段
x_t = client.get_x_t()  # 时间戳（毫秒）
x_b3_traceid = client.get_b3_trace_id()  # 16位随机 trace id
x_xray_traceid = client.get_xray_trace_id()  # 32位 trace id

# 手动构建 headers
headers = {
    "x-s": x_s,
    "x-t": str(x_t),
    "x-b3-traceid": x_b3_traceid,
    "x-xray-traceid": x_xray_traceid
}

# 使用统一时间戳（可选，确保所有字段使用相同时间）
import time
timestamp = time.time()

x_s = client.sign_xs_get(
    uri="/api/sns/web/v1/user_posted",
    a1_value="your_a1_cookie_value",
    params={"num": "30"},
    timestamp=timestamp  # 传入统一时间戳
)
x_t = client.get_x_t(timestamp=timestamp)
x_xray_traceid = client.get_xray_trace_id(timestamp=int(timestamp * 1000))

# 生成 x-s-common 签名
# x-s-common 签名需要完整的 cookies
cookies = {
    "a1": "your_a1_value",
    "web_session": "your_web_session",
    "webId": "your_web_id"
}

# 方式1: 使用 sign_xsc 别名方法（推荐）
xs_common = client.sign_xsc(cookie_dict=cookies)

# 方式2: 使用完整方法名
xs_common = client.sign_xs_common(cookie_dict=cookies)

# 方式3: 支持 Cookie 字符串格式
cookie_string = "a1=your_a1_value; web_session=your_web_session; webId=your_web_id"
xs_common = client.sign_xsc(cookie_dict=cookie_string)

# 使用在请求中
headers = {
    "x-s-common": xs_common,
    # ... 其他 headers
}
```

</details>

### 会话管理（实验性功能）

`SessionManager` 用于模拟真实用户会话，维护状态化的签名参数，可能有助于提升长期稳定性。

**注意**：此功能基于 [#86](https://github.com/Cloxl/xhshow/issues/86) 理论分析，实际效果待验证。建议先在测试环境使用。

#### 基本使用

```python
from xhshow import Xhshow, SessionManager
import requests

client = Xhshow()
session = SessionManager()  # 创建会话管理器

cookies = {"a1": "...", "web_session": "...", "webId": "..."}

# 使用 session 参数进行签名
headers = client.sign_headers_get(
    uri="/api/sns/web/v1/user_posted",
    cookies=cookies,
    params={"num": "30"},
    session=session  # 传入 session
)

response = requests.get(
    "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    params={"num": "30"},
    headers=headers,
    cookies=cookies
)

# 同一个 session 可以在多次请求中复用
headers2 = client.sign_headers_get(
    uri="/api/sns/web/v1/homefeed",
    cookies=cookies,
    params={"page": "1"},
    session=session  # 复用同一个 session
)
```

#### 账户池管理

如果你有多个账户，需要为每个账户创建独立的 `SessionManager`：

```python
accounts = [
    {"a1": "account1_a1", "web_session": "session1"},
    {"a1": "account2_a1", "web_session": "session2"},
]

# 为每个账户创建独立的 session
sessions = {}
for account in accounts:
    sessions[account["a1"]] = SessionManager()

# 使用时匹配账户和对应的 session
for account in accounts:
    headers = client.sign_headers_get(
        uri="/api/sns/web/v1/user_posted",
        cookies=account,
        params={"num": "30"},
        session=sessions[account["a1"]]  # 使用对应账户的 session
    )
```

#### 工作原理

- **无 Session**：每次请求生成随机参数，可能被识别为机器人行为
- **有 Session**：维护固定的页面加载时间戳和单调递增的计数器，模拟真实用户在同一页面中的连续操作

**适用场景：**
- 长期运行的爬虫或服务

### 解密签名

```python
# 解密 x3 签名
decoded_bytes = client.decode_x3("mns0101_Q2vPHtH+lQJYGQfhxG271BIvFFhx...")

# 解密完整的 XYS 签名
decoded_data = client.decode_xs("XYS_2UQhPsHCH0c1Pjh9HjIj2erjwjQhyoPT...")
```

### 自定义配置

```python
from xhshow import CryptoConfig, Xhshow

custom_config = CryptoConfig().with_overrides(
    X3_PREFIX="custom_",
    SIGNATURE_DATA_TEMPLATE={"x0": "4.2.6", "x1": "xhs-pc-web", "x2": "Windows", "x3": "", "x4": ""},
    SEQUENCE_VALUE_MIN=20,
    SEQUENCE_VALUE_MAX=60
)

client = Xhshow(config=custom_config)
```

## 参数说明

### **sign_headers** 系列方法（推荐使用）
- `uri`: 请求 URI 或完整 URL（会自动提取 URI）
- `cookies`: 完整的 cookie 字典或 cookie 字符串
  - 字典格式: `{"a1": "...", "web_session": "...", "webId": "..."}`
  - 字符串格式: `"a1=...; web_session=...; webId=..."`
- `xsec_appid`: 应用标识符，默认为 `xhs-pc-web`
- `params`: GET 请求参数（仅在 method="GET" 时使用）
- `payload`: POST 请求参数（仅在 method="POST" 时使用）
- `timestamp`: 可选的统一时间戳（秒）

### **sign_xs** 系列方法
- `uri`: 请求 URI 或完整 URL
- `a1_value`: cookie 中的 a1 值（字符串）
- `xsec_appid`: 应用标识符，默认为 `xhs-pc-web`
- `params/payload`: 请求参数（GET 用 params，POST 用 payload）
- `timestamp`: 可选的统一时间戳（秒）

### **sign_xsc** 系列方法
- `cookie_dict`: 完整的 cookie 字典或 cookie 字符串

## 开发环境

### 环境准备

```bash
# 安装uv包管理器
curl -LsSf https://astral.sh/uv/install.sh | sh

# 克隆项目
git clone https://github.com/Cloxl/xhshow
cd xhshow

# 安装依赖
uv sync --dev
```

### 开发流程

```bash
# 运行测试
uv run pytest tests/ -v

# 代码检查
uv run ruff check src/ tests/ --ignore=UP036,E501

# 代码格式化
uv run ruff format src/ tests/

# 构建包
uv build
```

### Git工作流

```bash
# 创建功能分支
git checkout -b feat/your-feature

# 提交代码（遵循conventional commits规范）
git commit -m "feat(client): 添加新功能描述"

# 推送到远程
git push origin feat/your-feature
```

## 功能建议

如果您有任何功能建议或想法，欢迎在 [#60](https://github.com/Cloxl/xhshow/issues/60) 中提交。我们期待您的宝贵建议，共同打造更好的 xhshow！

## License

[MIT](LICENSE)