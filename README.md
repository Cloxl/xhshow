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

### 基本用法

```python
from xhshow import Xhshow
import requests

client = Xhshow()

# GET请求签名
signature = client.sign_xs_get(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",  # v0.1.3及后续版本支持自动提取uri
    # uri="/api/sns/web/v1/user_posted"  # v0.1.2及以前版本需要主动提取uri
    a1_value="your_a1_cookie_value",
    params={"num": "30", "cursor": "", "user_id": "123"}
)

# POST请求签名
signature = client.sign_xs_post(
    uri="https://edith.xiaohongshu.com/api/sns/web/v1/login",
    a1_value="your_a1_cookie_value",
    payload={"username": "test", "password": "123456"}
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

- `uri`: 请求URI（去除https域名和查询参数）
- `a1_value`: cookie中的a1值
- `xsec_appid`: 应用标识符，默认为 `xhs-pc-web`
- `params/payload`: 请求参数（GET用params，POST用payload）

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