"""参数验证工具"""

from collections.abc import Callable
from functools import wraps
from typing import Any, Literal, TypeVar

F = TypeVar("F", bound=Callable[..., Any])
HttpMethod = Literal["GET", "POST"]

__all__ = [
    "RequestSignatureValidator",
    "validate_signature_params",
    "validate_get_signature_params",
    "validate_post_signature_params",
]


class RequestSignatureValidator:
    """请求签名参数验证器"""

    @staticmethod
    def validate_method(method: Any) -> HttpMethod:
        """验证HTTP方法参数"""
        if not isinstance(method, str):
            raise TypeError(f"method must be str, got {type(method).__name__}")

        method = method.strip().upper()
        if method not in ("GET", "POST"):
            raise ValueError(f"method must be 'GET' or 'POST', got '{method}'")

        return method  # type: ignore

    @staticmethod
    def validate_uri(uri: Any) -> str:
        """验证URI参数"""
        if not isinstance(uri, str):
            raise TypeError(f"uri must be str, got {type(uri).__name__}")

        if not uri.strip():
            raise ValueError("uri cannot be empty")

        return uri.strip()

    @staticmethod
    def validate_a1_value(a1_value: Any) -> str:
        """验证a1值参数"""
        if not isinstance(a1_value, str):
            raise TypeError(f"a1_value must be str, got {type(a1_value).__name__}")

        if not a1_value.strip():
            raise ValueError("a1_value cannot be empty")

        return a1_value.strip()

    @staticmethod
    def validate_xsec_appid(xsec_appid: Any) -> str:
        """验证xsec_appid参数"""
        if not isinstance(xsec_appid, str):
            raise TypeError(f"xsec_appid must be str, got {type(xsec_appid).__name__}")

        if not xsec_appid.strip():
            raise ValueError("xsec_appid cannot be empty")

        return xsec_appid.strip()

    @staticmethod
    def validate_payload(payload: Any) -> dict[str, Any] | None:
        """验证payload参数"""
        if payload is not None and not isinstance(payload, dict):
            raise TypeError(
                f"payload must be dict or None, got {type(payload).__name__}"
            )

        # 验证payload键类型
        if payload is not None:
            for key in payload.keys():
                if not isinstance(key, str):
                    raise TypeError(
                        f"payload keys must be str, got {type(key).__name__} "
                        f"for key '{key}'"
                    )

        return payload


def validate_signature_params(func: F) -> F:  # type: ignore  # noqa: UP047
    """
    参数验证装饰器，用于验证sign_xs方法的参数

    Args:
        func: 被装饰的方法

    Returns:
        装饰后的方法
    """

    @wraps(func)
    def wrapper(
        self,
        method: Any,
        uri: Any,
        a1_value: Any,
        xsec_appid: Any = "xhs-pc-web",
        payload: Any = None,
    ):
        validator = RequestSignatureValidator()

        # 验证和标准化参数
        validated_method = validator.validate_method(method)
        validated_uri = validator.validate_uri(uri)
        validated_a1_value = validator.validate_a1_value(a1_value)
        validated_xsec_appid = validator.validate_xsec_appid(xsec_appid)
        validated_payload = validator.validate_payload(payload)

        # 调用原方法
        return func(
            self,
            validated_method,
            validated_uri,
            validated_a1_value,
            validated_xsec_appid,
            validated_payload,
        )

    return wrapper  # type: ignore


def validate_get_signature_params(func: F) -> F:  # type: ignore  # noqa: UP047
    """
    参数验证装饰器，用于验证sign_xs_get方法的参数

    Args:
        func: 被装饰的方法

    Returns:
        装饰后的方法
    """

    @wraps(func)
    def wrapper(
        self,
        uri: Any,
        a1_value: Any,
        xsec_appid: Any = "xhs-pc-web",
        params: Any = None,
    ):
        validator = RequestSignatureValidator()

        # 验证和标准化参数
        validated_uri = validator.validate_uri(uri)
        validated_a1_value = validator.validate_a1_value(a1_value)
        validated_xsec_appid = validator.validate_xsec_appid(xsec_appid)
        validated_params = validator.validate_payload(params)

        # 调用原方法
        return func(
            self,
            validated_uri,
            validated_a1_value,
            validated_xsec_appid,
            validated_params,
        )

    return wrapper  # type: ignore


def validate_post_signature_params(func: F) -> F:  # type: ignore  # noqa: UP047
    """
    参数验证装饰器，用于验证sign_xs_post方法的参数

    Args:
        func: 被装饰的方法

    Returns:
        装饰后的方法
    """

    @wraps(func)
    def wrapper(
        self,
        uri: Any,
        a1_value: Any,
        xsec_appid: Any = "xhs-pc-web",
        payload: Any = None,
    ):
        validator = RequestSignatureValidator()

        # 验证和标准化参数
        validated_uri = validator.validate_uri(uri)
        validated_a1_value = validator.validate_a1_value(a1_value)
        validated_xsec_appid = validator.validate_xsec_appid(xsec_appid)
        validated_payload = validator.validate_payload(payload)

        # 调用原方法
        return func(
            self,
            validated_uri,
            validated_a1_value,
            validated_xsec_appid,
            validated_payload,
        )

    return wrapper  # type: ignore
