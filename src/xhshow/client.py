import hashlib
import json
from typing import Any, Literal

from .core.crypto import CryptoProcessor
from .utils.validators import (
    validate_get_signature_params,
    validate_post_signature_params,
    validate_signature_params,
)

__all__ = ["Xhshow"]


class Xhshow:
    """小红书请求客户端封装"""

    def __init__(self):
        self.crypto_processor = CryptoProcessor()

    def _build_content_string(
        self, method: str, uri: str, payload: dict[str, Any] | None = None
    ) -> str:
        """
        构建内容字符串（用于MD5计算和签名生成）

        Args:
            method: 请求方法 ("GET" 或 "POST")
            uri: 请求URI（不包含查询参数）
            payload: 请求参数

        Returns:
            str: 构建的内容字符串
        """
        payload = payload or {}

        if method.upper() == "POST":
            return uri + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        else:
            if not payload:
                return uri
            else:
                params = [
                    f"{key}={','.join(str(v) for v in value) if isinstance(value, list | tuple) else (str(value) if value is not None else '')}"  # noqa: E501
                    for key, value in payload.items()
                ]
                return f"{uri}?{'&'.join(params)}"

    def _generate_d_value(self, content: str) -> str:
        """
        从内容字符串生成d值（MD5哈希）

        Args:
            content: 已构建的内容字符串

        Returns:
            str: 32位小写MD5哈希值
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def _build_signature(
        self,
        d_value: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        string_param: str = "",
    ) -> str:
        """
        构建签名

        Args:
            d_value: d值（MD5哈希）
            a1_value: cookie 中的a1值
            xsec_appid: 应用标识符
            string_param: 字符串参数

        Returns:
            str: Base58编码的签名
        """
        # 构建载荷数组
        payload_array = self.crypto_processor.build_payload_array(
            d_value, a1_value, xsec_appid, string_param
        )

        # XOR变换
        xor_result = self.crypto_processor.bit_ops.xor_transform_array(payload_array)

        # Base58编码
        return self.crypto_processor.b58encoder.encode_to_b58(xor_result)

    @validate_signature_params
    def sign_xs(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
    ) -> str:
        """
        生成请求签名（支持GET和POST）

        Args:
            method: 请求方法 ("GET" 或 "POST")
            uri: 请求URI(去除https域名 去除查询参数)
            a1_value: cookie中的a1值
            xsec_appid: 应用标识符 默认为`xhs-pc-web`
            payload: 请求参数
                - GET请求时：params值
                - POST请求时：payload值

        Returns:
            str: 完整的签名字符串

        Raises:
            TypeError: 参数类型错误
            ValueError: 参数值错误
        """
        signature_data = self.crypto_processor.config.SIGNATURE_DATA_TEMPLATE.copy()

        # 构建内容字符串
        content_string = self._build_content_string(method, uri, payload)

        # 生成d值和x3签名
        d_value = self._generate_d_value(content_string)
        signature_data["x3"] = (
            self.crypto_processor.config.X3_PREFIX
            + self._build_signature(d_value, a1_value, xsec_appid, content_string)
        )
        return (
            self.crypto_processor.config.XYS_PREFIX
            + self.crypto_processor.b64encoder.encode_to_b64(
                json.dumps(signature_data, separators=(",", ":"), ensure_ascii=False)
            )
        )

    @validate_get_signature_params
    def sign_xs_get(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
    ) -> str:
        """
        生成GET请求签名（便捷方法）

        Args:
            uri: 请求URI(去除https域名 去除查询参数)
            a1_value: cookie中的a1值
            xsec_appid: 应用标识符 默认为`xhs-pc-web`
            params: GET请求参数

        Returns:
            str: 完整的签名字符串

        Raises:
            TypeError: 参数类型错误
            ValueError: 参数值错误
        """
        return self.sign_xs("GET", uri, a1_value, xsec_appid, params)

    @validate_post_signature_params
    def sign_xs_post(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
    ) -> str:
        """
        生成POST请求签名（便捷方法）

        Args:
            uri: 请求URI(去除https域名 去除查询参数)
            a1_value: cookie中的a1值
            xsec_appid: 应用标识符 默认为`xhs-pc-web`
            payload: POST请求体数据

        Returns:
            str: 完整的签名字符串

        Raises:
            TypeError: 参数类型错误
            ValueError: 参数值错误
        """
        return self.sign_xs("POST", uri, a1_value, xsec_appid, payload)
