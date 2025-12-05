import hashlib
import json
import time
from typing import Any, Literal

from .config import CryptoConfig
from .core.crypto import CryptoProcessor
from .utils.random_gen import RandomGenerator
from .utils.url_utils import build_url, extract_uri
from .utils.validators import (
    validate_get_signature_params,
    validate_post_signature_params,
    validate_signature_params,
)

__all__ = ["Xhshow"]


class Xhshow:
    """Xiaohongshu request client wrapper"""

    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self.crypto_processor = CryptoProcessor(self.config)
        self.random_generator = RandomGenerator()

    def _build_content_string(self, method: str, uri: str, payload: dict[str, Any] | None = None) -> str:
        """
        Build content string (used for MD5 calculation and signature generation)

        Args:
            method: Request method ("GET" or "POST")
            uri: Request URI (without query parameters)
            payload: Request parameters

        Returns:
            str: Built content string
        """
        payload = payload or {}

        if method.upper() == "POST":
            return uri + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        else:
            if not payload:
                return uri
            else:
                # XHS signature algorithm requires only '=' to be encoded as '%3D',
                # other characters (including ',') should remain unencoded
                params = [
                    f"{key}={(','.join(str(v) for v in value) if isinstance(value, list | tuple) else (str(value) if value is not None else '')).replace('=', '%3D')}"  # noqa: E501
                    for key, value in payload.items()
                ]
                return f"{uri}?{'&'.join(params)}"

    def _generate_d_value(self, content: str) -> str:
        """
        Generate d value (MD5 hash) from content string

        Args:
            content: Built content string

        Returns:
            str: 32-character lowercase MD5 hash
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def _build_signature(
        self,
        d_value: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        string_param: str = "",
        timestamp: float | None = None,
    ) -> str:
        """
        Build signature

        Args:
            d_value: d value (MD5 hash)
            a1_value: a1 value from cookies
            xsec_appid: Application identifier
            string_param: String parameter
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            str: Base64 encoded signature
        """
        payload_array = self.crypto_processor.build_payload_array(
            d_value, a1_value, xsec_appid, string_param, timestamp
        )

        xor_result = self.crypto_processor.bit_ops.xor_transform_array(payload_array)

        return self.crypto_processor.b64encoder.encode_x3(xor_result[:124])

    @validate_signature_params
    def sign_xs(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> str:
        """
        Generate request signature (supports GET and POST)

        Args:
            method: Request method ("GET" or "POST")
            uri: Request URI or full URL
                - URI only: "/api/sns/web/v1/user_posted"
                - Full URL: "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted"
                - Full URL with query: "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted?num=30"
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            payload: Request parameters
                - GET request: params value
                - POST request: payload value
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        uri = extract_uri(uri)

        signature_data = self.crypto_processor.config.SIGNATURE_DATA_TEMPLATE.copy()

        content_string = self._build_content_string(method, uri, payload)

        d_value = self._generate_d_value(content_string)
        signature_data["x3"] = self.crypto_processor.config.X3_PREFIX + self._build_signature(
            d_value, a1_value, xsec_appid, content_string, timestamp
        )
        return self.crypto_processor.config.XYS_PREFIX + self.crypto_processor.b64encoder.encode(
            json.dumps(signature_data, separators=(",", ":"), ensure_ascii=False)
        )

    @validate_get_signature_params
    def sign_xs_get(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> str:
        """
        Generate GET request signature (convenience method)

        Args:
            uri: Request URI or full URL
                - URI only: "/api/sns/web/v1/user_posted"
                - Full URL: "https://edith.xiaohongshu.com/api/sns/web/v1/user_posted"
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            params: GET request parameters
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        return self.sign_xs("GET", uri, a1_value, xsec_appid, payload=params, timestamp=timestamp)

    @validate_post_signature_params
    def sign_xs_post(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> str:
        """
        Generate POST request signature (convenience method)

        Args:
            uri: Request URI or full URL
                - URI only: "/api/sns/web/v1/login"
                - Full URL: "https://edith.xiaohongshu.com/api/sns/web/v1/login"
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            payload: POST request body data
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        return self.sign_xs("POST", uri, a1_value, xsec_appid, payload=payload, timestamp=timestamp)

    def decode_x3(self, x3_signature: str) -> bytearray:
        """
        Decrypt x3 signature (Base64 format)

        Args:
            x3_signature: x3 signature string (can include or exclude prefix)

        Returns:
            bytearray: Decrypted original byte array

        Raises:
            ValueError: Invalid signature format
        """
        if x3_signature.startswith(self.config.X3_PREFIX):
            x3_signature = x3_signature[len(self.config.X3_PREFIX) :]

        decoded_bytes = self.crypto_processor.b64encoder.decode_x3(x3_signature)
        return self.crypto_processor.bit_ops.xor_transform_array(list(decoded_bytes))

    def decode_xs(self, xs_signature: str) -> dict[str, Any]:
        """
        Decrypt complete XYS signature

        Args:
            xs_signature: Complete signature string (can include or exclude XYS_ prefix)

        Returns:
            dict: Decrypted signature data including x0, x1, x2, x3, x4 fields

        Raises:
            ValueError: Invalid signature format or JSON parsing failed
        """
        if xs_signature.startswith(self.config.XYS_PREFIX):
            xs_signature = xs_signature[len(self.config.XYS_PREFIX) :]

        json_string = self.crypto_processor.b64encoder.decode(xs_signature)
        try:
            signature_data = json.loads(json_string)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid signature: JSON decode failed - {e}") from e

        return signature_data

    def build_url(self, base_url: str, params: dict[str, Any] | None = None) -> str:
        """
        Build complete URL with query parameters (convenience method)

        Args:
            base_url: Base URL (can include or exclude protocol/host)
            params: Query parameters dictionary

        Returns:
            str: Complete URL with properly encoded query string

        Examples:
            >>> client = Xhshow()
            >>> client.build_url("https://api.example.com/path", {"key": "value=test"})
            'https://api.example.com/path?key=value%3Dtest'
        """
        return build_url(base_url, params)

    def build_json_body(self, payload: dict[str, Any]) -> str:
        """
        Build JSON body string for POST request (convenience method)

        Args:
            payload: Request payload dictionary

        Returns:
            str: JSON string with compact format and unicode characters preserved

        Examples:
            >>> client = Xhshow()
            >>> client.build_json_body({"username": "test", "password": "123456"})
            '{"username":"test","password":"123456"}'
        """
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    def get_b3_trace_id(self) -> str:
        """
        Generate x-b3-traceid for HTTP request headers

        Returns:
            str: 16-character hexadecimal trace ID

        Examples:
            >>> client = Xhshow()
            >>> client.get_b3_trace_id()
            '63cd207ddeb2e360'
        """
        return self.random_generator.generate_b3_trace_id()

    def get_xray_trace_id(self, timestamp: int | None = None, seq: int | None = None) -> str:
        """
        Generate x-xray-traceid for HTTP request headers

        Args:
            timestamp: Unix timestamp in milliseconds (defaults to current time)
            seq: Sequence number 0 to 2^23-1 (defaults to random value)

        Returns:
            str: 32-character hexadecimal trace ID

        Examples:
            >>> client = Xhshow()
            >>> client.get_xray_trace_id()
            'cd7621e82d9c24e90bfd937d92bbbd1b'
            >>> client.get_xray_trace_id(timestamp=1764896636081, seq=5)
            'cd7604be588000051a7fb8ae74496a76'
        """
        return self.random_generator.generate_xray_trace_id(timestamp, seq)

    def get_x_t(self, timestamp: float | None = None) -> int:
        """
        Generate x-t header value (Unix timestamp in milliseconds)

        Args:
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            int: Unix timestamp in milliseconds

        Examples:
            >>> client = Xhshow()
            >>> client.get_x_t()
            1764902784843
            >>> client.get_x_t(timestamp=1764896636.081)
            1764896636081
        """
        if timestamp is None:
            timestamp = time.time()
        return int(timestamp * 1000)

    def sign_headers(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> dict[str, str]:
        """
        Generate complete request headers with signature and trace IDs

        Args:
            method: Request method ("GET" or "POST")
            uri: Request URI or full URL
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            params: GET request parameters (only used when method="GET")
            payload: POST request body data (only used when method="POST")
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            dict: Complete headers including x-s, x-t, x-b3-traceid, x-xray-traceid

        Examples:
            >>> client = Xhshow()
            >>> # GET request
            >>> headers = client.sign_headers(
            ...     method="GET",
            ...     uri="/api/sns/web/v1/user_posted",
            ...     a1_value="your_a1_value",
            ...     params={"num": "30"}
            ... )
            >>> # POST request
            >>> headers = client.sign_headers(
            ...     method="POST",
            ...     uri="/api/sns/web/v1/login",
            ...     a1_value="your_a1_value",
            ...     payload={"username": "test"}
            ... )
            >>> headers.keys()
            dict_keys(['x-s', 'x-t', 'x-b3-traceid', 'x-xray-traceid'])
        """
        if timestamp is None:
            timestamp = time.time()

        method_upper = method.upper()

        # Validate method and parameters
        if method_upper == "GET":
            if payload is not None:
                raise ValueError("GET requests must use 'params', not 'payload'")
            request_data = params
        elif method_upper == "POST":
            if params is not None:
                raise ValueError("POST requests must use 'payload', not 'params'")
            request_data = payload
        else:
            raise ValueError(f"Unsupported method: {method}")

        x_s = self.sign_xs(method_upper, uri, a1_value, xsec_appid, request_data, timestamp)
        x_t = self.get_x_t(timestamp)
        x_b3_traceid = self.get_b3_trace_id()
        x_xray_traceid = self.get_xray_trace_id(timestamp=int(timestamp * 1000))

        return {
            "x-s": x_s,
            "x-t": str(x_t),
            "x-b3-traceid": x_b3_traceid,
            "x-xray-traceid": x_xray_traceid,
        }

    def sign_headers_get(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> dict[str, str]:
        """
        Generate complete request headers for GET request (convenience method)

        Args:
            uri: Request URI or full URL
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            params: GET request parameters
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            dict: Complete headers including x-s, x-t, x-b3-traceid, x-xray-traceid

        Examples:
            >>> client = Xhshow()
            >>> headers = client.sign_headers_get(
            ...     uri="/api/sns/web/v1/user_posted",
            ...     a1_value="your_a1_value",
            ...     params={"num": "30"}
            ... )
        """
        return self.sign_headers("GET", uri, a1_value, xsec_appid, params=params, timestamp=timestamp)

    def sign_headers_post(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> dict[str, str]:
        """
        Generate complete request headers for POST request (convenience method)

        Args:
            uri: Request URI or full URL
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            payload: POST request body data
            timestamp: Unix timestamp in seconds (defaults to current time)

        Returns:
            dict: Complete headers including x-s, x-t, x-b3-traceid, x-xray-traceid

        Examples:
            >>> client = Xhshow()
            >>> headers = client.sign_headers_post(
            ...     uri="/api/sns/web/v1/login",
            ...     a1_value="your_a1_value",
            ...     payload={"username": "test", "password": "123456"}
            ... )
        """
        return self.sign_headers("POST", uri, a1_value, xsec_appid, payload=payload, timestamp=timestamp)
