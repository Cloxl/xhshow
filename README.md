# xhshow

<div align="center">

[![PyPI version](https://badge.fury.io/py/xhshow.svg)](https://badge.fury.io/py/xhshow)
[![Python](https://img.shields.io/pypi/pyversions/xhshow.svg)](https://pypi.org/project/xhshow/)
[![License](https://img.shields.io/github/license/Cloxl/xhshow.svg)](https://github.com/Cloxl/xhshow/blob/main/LICENSE)
[![CI](https://github.com/Cloxl/xhshow/workflows/CI/badge.svg)](https://github.com/Cloxl/xhshow/actions)
[![Downloads](https://pepy.tech/badge/xhshow)](https://pepy.tech/project/xhshow)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

小红书请求签名生成库，支持GET和POST请求的x-s签名生成。

</div>

## 系统要求

- Python 3.10+

## 安装

```bash
pip install xhshow
```

## 使用方法

### 推荐使用便捷方法

```python
from xhshow import Xhshow

client = Xhshow()

# GET请求签名
signature = client.sign_xs_get(
    uri="/api/sns/web/v1/user_posted",
    a1_value="your_a1_cookie_value",
    params={"num": "30", "cursor": "", "user_id": "123"}
)

# POST请求签名
signature = client.sign_xs_post(
    uri="/api/sns/web/v1/login", 
    a1_value="your_a1_cookie_value",
    payload={"username": "test", "password": "123456"}
)
```

### 通用方法

```python
from xhshow import Xhshow

client = Xhshow()

# 通用签名方法
signature = client.sign_xs(
    method="GET",  # 或 "POST"
    uri="/api/sns/web/v1/user_posted",
    a1_value="your_a1_cookie_value",
    payload={"num": "30", "cursor": "", "user_id": "123"}
)
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

## License

[MIT](LICENSE)