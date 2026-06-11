# xhshow

<div align="center">

[![PyPI version](https://badge.fury.io/py/xhshow.svg)](https://badge.fury.io/py/xhshow)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://pypi.org/project/xhshow/)
[![License](https://img.shields.io/github/license/Cloxl/xhshow.svg)](https://github.com/Cloxl/xhshow/blob/main/LICENSE)
[![Downloads](https://pepy.tech/badge/xhshow)](https://pepy.tech/project/xhshow)

小红书请求签名生成库，生成 `x-s`、`x-s-common`、`x-rap-param` 等请求头。

</div>

## 系统要求

- Python 3.10+

## 安装

```bash
pip install xhshow
```

## 快速开始

```python
from xhshow import Xhshow
import requests

client = Xhshow()
cookies = {"a1": "...", "web_session": "...", "webId": "..."}

# uri 可传完整 URL 或 URI 路径，自动提取
headers = client.sign_headers_get(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    cookies=cookies,
    params={"num": "30", "cursor": "", "user_id": "123"},
)

response = requests.get(
    "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
    params={"num": "30", "cursor": "", "user_id": "123"},
    headers=headers,
    cookies=cookies,
)
```

返回的 headers：

```python
{
    "x-s": "XYS_...",
    "x-s-common": "...",
    "x-t": "1234567890",
    "x-b3-traceid": "...",
    "x-xray-traceid": "...",
    "x-mns": "unload",
    "xy-direction": "42",
}
```

POST 请求使用 `sign_headers_post`，参数从 `params` 换成 `payload`：

```python
headers = client.sign_headers_post(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/login",
    cookies=cookies,
    payload={"username": "test", "password": "123456"},
)
```

## x-rap-param

feed、搜索、笔记发布等接口需要额外的 `x-rap-param` 风控头。传入 `x_rap=True` 即可在签名 headers 中自动生成：

```python
headers = client.sign_headers_post(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/feed",
    cookies=cookies,
    payload={"source_note_id": "..."},
    x_rap=True,           # 生成 x-rap-param
    user_id="5ff...",     # 可选，用于计算 xy-direction 分片，省略则随机
)
```

- `x_rap`：是否生成 `x-rap-param`。算法基于请求 API 路径 + body 计算，GET/POST 均支持。
- `user_id`：传入则 `xy-direction` 由 user_id 经 MurmurHash3 算出，否则取随机值。

也可单独调用底层算法：

```python
from xhshow.core.xrap import x_rap_param

value = x_rap_param(
    "//edith.xiaohongshu.com/api/sns/web/v1/feed",
    {"source_note_id": "..."},
)
```

## 搜索与账号参数

```python
client.get_search_id()           # 搜索接口 search_id（base36）
client.get_search_request_id()   # 搜索接口 request_id："{random}-{ts_ms}"

Xhshow.generate_a1()             # 生成 a1 cookie（52 位）
Xhshow.generate_web_id(a1)       # 由 a1 生成 web_id（32 位 hex）
```

## 单独生成字段

```python
# x-s 签名（仅需 a1）
x_s = client.sign_xs_get(uri="/api/sns/web/v1/user_posted", a1_value="...", params={"num": "30"})
x_s = client.sign_xs_post(uri="/api/sns/web/v1/login", a1_value="...", payload={...})

# x-s-common（需完整 cookies，支持字典或字符串）
xs_common = client.sign_xsc(cookie_dict=cookies)

# 其他 headers 字段
x_t = client.get_x_t()                  # 毫秒时间戳
x_b3 = client.get_b3_trace_id()         # 16 位 trace id
x_xray = client.get_xray_trace_id()     # 32 位 trace id

# 统一时间戳（确保各字段时间一致）
import time
ts = time.time()
x_s = client.sign_xs_get(uri="...", a1_value="...", params={"num": "30"}, timestamp=ts)
x_t = client.get_x_t(timestamp=ts)
x_xray = client.get_xray_trace_id(timestamp=int(ts * 1000))
```

## 会话管理（实验性）

`SessionManager` 维护状态化签名参数（固定页面加载时间戳 + 单调递增计数器），模拟真实用户连续操作，可能提升长期稳定性。基于 [#86](https://github.com/Cloxl/xhshow/issues/86) 理论分析，实际效果待验证。

```python
from xhshow import Xhshow, SessionManager

client = Xhshow()
session = SessionManager()

headers = client.sign_headers_get(
    uri="/api/sns/web/v1/user_posted",
    cookies=cookies,
    params={"num": "30"},
    session=session,   # 同一 session 可跨多次请求复用
)
```

多账户时为每个账户创建独立 `SessionManager`，按账户匹配复用。

## 工具方法

```python
# 构建符合 xhs 平台的 GET 链接 / POST body
full_url = client.build_url(base_url="...", params={...})
json_body = client.build_json_body(payload={...})

# 解密
client.decode_x3("mns0101_...")   # 解密 x3 签名
client.decode_xs("XYS_...")       # 解密完整 XYS 签名
```

## 自定义配置

```python
from xhshow import CryptoConfig, Xhshow

config = CryptoConfig().with_overrides(
    X3_PREFIX="custom_",
    SEQUENCE_VALUE_MIN=20,
    SEQUENCE_VALUE_MAX=60,
)
client = Xhshow(config=config)
```

## 开发

```bash
# 安装 uv 后
git clone https://github.com/Cloxl/xhshow && cd xhshow
uv sync --dev

uv run pytest tests/ -v                                  # 测试
uv run ruff check src/ tests/ --ignore=UP036,E501        # 检查
uv run ruff format src/ tests/                           # 格式化
uv build                                                 # 构建
```

提交遵循 conventional commits 规范。
## 功能建议

如果您有任何功能建议或想法，欢迎在 [#60](https://github.com/Cloxl/xhshow/issues/60) 中提交。我们期待您的宝贵建议，共同打造更好的 xhshow！

## 社区

本项目分享于 [LINUX DO](https://linux.do) —— 真诚、友善、团结、专业的技术社区。欢迎来逛逛。

## License

[MIT](LICENSE)
