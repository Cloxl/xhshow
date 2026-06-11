import base64
import hashlib
import json
import time
import urllib.parse
from typing import Any, Literal

from .config import CryptoConfig
from .core.common_sign import XsCommonSigner
from .core.crypto import CryptoProcessor
from .core.xrap import x_rap_param
from .core.xyw_crypto import build_xyw_payload_hex
from .session import SessionManager, SignState
from .utils.random_gen import RandomGenerator
from .utils.sharding import get_sharding_key
from .utils.url_utils import build_url, extract_uri
from .utils.validators import (
    validate_get_signature_params,
    validate_post_signature_params,
    validate_signature_params,
    validate_xs_common_params,
)

__all__ = ["Xhshow", "SessionManager", "SignState"]


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
                params = []
                for key, value in payload.items():
                    if isinstance(value, list | tuple):
                        value_str = ",".join(str(v) for v in value)
                    elif value is not None:
                        value_str = str(value)
                    else:
                        value_str = ""

                    encoded_value = urllib.parse.quote(value_str, safe=",")
                    params.append(f"{key}={encoded_value}")

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
            d_value, d_value, a1_value, xsec_appid, string_param, timestamp
        )

        xor_result = self.crypto_processor.bit_ops.xor_transform_array(payload_array)

        return self.crypto_processor.b64encoder.encode_x3(xor_result[: self.config.PAYLOAD_LENGTH])

    @validate_signature_params
    def sign_xs(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
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
            session: Optional session manager for stateful signing.

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        uri = extract_uri(uri)
        content_string = self._build_content_string(method, uri, payload)
        d_value = self._generate_d_value(content_string)
        m_value = d_value if method == "GET" else hashlib.md5(uri.encode("utf-8")).hexdigest()

        sign_state = session.get_current_state(content_string) if session else None

        payload_array = self.crypto_processor.build_payload_array(
            d_value, m_value, a1_value, xsec_appid, content_string, timestamp, sign_state=sign_state
        )
        xor_result = self.crypto_processor.bit_ops.xor_transform_array(payload_array)
        x3_signature = self.crypto_processor.b64encoder.encode_x3(xor_result[: self.config.PAYLOAD_LENGTH])

        signature_data = self.crypto_processor.config.SIGNATURE_DATA_TEMPLATE.copy()
        signature_data["x3"] = self.crypto_processor.config.X3_PREFIX + x3_signature

        return self.crypto_processor.config.XYS_PREFIX + self.crypto_processor.b64encoder.encode(
            json.dumps(signature_data, separators=(",", ":"), ensure_ascii=False)
        )

    @validate_signature_params
    def sign_xyw(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: Any = None,
    ) -> str:
        """
        Generate XYW_ signature using AES-128-CBC encryption.

        Required for data-fetching APIs (user_posted, otherinfo, etc.) that reject
        XYS_ format with HTTP 406. Uses an independent crypto path from sign_xs.

        Args:
            method: Request method ("GET" or "POST")
            uri: Request URI or full URL
            a1_value: a1 value from cookies
            xsec_appid: Application identifier, defaults to ``xhs-pc-web``
            payload: Request parameters (GET params or POST body)
            timestamp: Unix timestamp in seconds (defaults to current time)
            session: Unused, accepted for decorator compatibility.

        Returns:
            str: XYW_ format signature string
        """
        uri = extract_uri(uri)
        content_string = self._build_content_string(method, uri, payload)

        timestamp_ms = str(self.get_x_t(timestamp))
        payload_hex = build_xyw_payload_hex(
            full_uri=content_string,
            a1_value=a1_value,
            timestamp_ms=timestamp_ms,
            config=self.config,
        )

        xyw_data = {
            "signSvn": self.config.XYW_SIGN_SVN,
            "signType": self.config.XYW_SIGN_TYPE,
            "appId": xsec_appid,
            "signVersion": self.config.XYW_SIGN_VERSION,
            "payload": payload_hex,
        }
        xyw_json = json.dumps(xyw_data, separators=(",", ":"), ensure_ascii=False)
        return self.config.XYW_PREFIX + base64.b64encode(xyw_json.encode("utf-8")).decode("utf-8")

    def sign_xs_common(
        self,
        cookie_dict: dict[str, Any] | str,
    ) -> str:
        """
        Generate x-s-common signature

        Args:
            cookie_dict: Complete cookie dictionary or cookie string

        Returns:
            Encoded x-s-common signature string
        """
        parsed_cookies = self._parse_cookies(cookie_dict)
        signer = XsCommonSigner(self.config)
        return signer.sign(parsed_cookies)

    @validate_get_signature_params
    def sign_xs_get(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
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
            session: Optional session manager for stateful signing.

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        return self.sign_xs("GET", uri, a1_value, xsec_appid, payload=params, timestamp=timestamp, session=session)

    @validate_post_signature_params
    def sign_xs_post(
        self,
        uri: str,
        a1_value: str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
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
            session: Optional session manager for stateful signing.

        Returns:
            str: Complete signature string

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        return self.sign_xs("POST", uri, a1_value, xsec_appid, payload=payload, timestamp=timestamp, session=session)

    @validate_xs_common_params
    def sign_xsc(
        self,
        cookie_dict: dict[str, Any] | str,
    ) -> str:
        """
        Convenience wrapper to generate the `x-s-common` signature.

        Args:
            cookie_dict: Enter your complete cookie dictionary

        Returns:
            Encoded signature string suitable for the `x-s-common` header.

        Raises:
            TypeError: Parameter type error
            ValueError: Parameter value error
        """
        return self.sign_xs_common(cookie_dict)

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

    def get_search_id(self) -> str:
        """
        Generate search_id for search endpoint requests

        Returns:
            str: Base36 encoded search ID

        Examples:
            >>> client = Xhshow()
            >>> client.get_search_id()
            '2bzhtisx9gp4rnrufbcyn'
        """
        return self.random_generator.generate_search_id()

    def get_search_request_id(self) -> str:
        """
        Generate search request_id for search endpoint requests

        Returns:
            str: Format "{random}-{timestamp_ms}"

        Examples:
            >>> client = Xhshow()
            >>> client.get_search_request_id()
            '1234567890-1764902784843'
        """
        return self.random_generator.generate_search_request_id()

    @staticmethod
    def generate_a1() -> str:
        """
        Generate a1 cookie value

        Returns:
            str: 52-character a1 cookie value

        Examples:
            >>> a1 = Xhshow.generate_a1()
            >>> len(a1)
            52
        """
        return RandomGenerator.generate_a1()

    @staticmethod
    def generate_web_id(a1: str) -> str:
        """
        Generate web_id from a1 cookie value

        Args:
            a1: a1 cookie value

        Returns:
            str: 32-character hex web_id

        Examples:
            >>> Xhshow.generate_web_id("19ab1e5ce48c3b3c5c50e2c040a801cfcca0a4ac50000571046")
            'e4b89785b2150758e1a37b5c72ef91b5'
        """
        return RandomGenerator.generate_web_id(a1)

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

    def _parse_cookies(self, cookies: dict[str, Any] | str) -> dict[str, Any]:
        """
        Parse cookies to dict format

        Args:
            cookies: Cookie dictionary or cookie string

        Returns:
            dict: Parsed cookie dictionary
        """
        if isinstance(cookies, str):
            from http.cookies import SimpleCookie

            ck = SimpleCookie()
            ck.load(cookies)
            return {k: morsel.value for k, morsel in ck.items()}
        return cookies

    def sign_headers(
        self,
        method: Literal["GET", "POST"],
        uri: str,
        cookies: dict[str, Any] | str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
        sign_format: Literal["xys", "xyw"] = "xys",
        user_id: str | None = None,
        x_rap: bool = False,
    ) -> dict[str, str]:
        """
        Generate complete request headers with signature and trace IDs

        Args:
            method: Request method ("GET" or "POST")
            uri: Request URI or full URL
            cookies: Complete cookie dictionary or cookie string
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            params: GET request parameters (only used when method="GET")
            payload: POST request body data (only used when method="POST")
            timestamp: Unix timestamp in seconds (defaults to current time)
            session: Optional session manager for stateful signing.
            sign_format: Signature format to use.
                - "xys": Traditional XYS_ format (default, works for non-data APIs)
                - "xyw": XYW_ format (required for data-fetching APIs like user_posted
                  which reject XYS_ with HTTP 406 since ~March 2026)
            user_id: Optional user ID for xy-direction sharding. If provided,
                computes sharding key from user_id; otherwise uses random value.
            x_rap: Whether to generate x-rap-param header. Required for
                feed, search, and note publishing endpoints.

        Returns:
            dict: Complete headers including x-s, x-s-common, x-t, x-b3-traceid, x-xray-traceid

        Examples:
            >>> client = Xhshow()
            >>> cookies = {"a1": "your_a1_value", "web_session": "..."}
            >>> # GET request with XYW_ format (for data APIs)
            >>> headers = client.sign_headers(
            ...     method="GET",
            ...     uri="/api/sns/web/v1/user_posted",
            ...     cookies=cookies,
            ...     params={"num": "30"},
            ...     sign_format="xyw"
            ... )
            >>> # POST request with x-rap-param
            >>> headers = client.sign_headers(
            ...     method="POST",
            ...     uri="/api/sns/web/v1/feed",
            ...     cookies=cookies,
            ...     payload={"source_note_id": "..."},
            ...     x_rap=True
            ... )
        """
        if timestamp is None:
            timestamp = time.time()

        method_upper = method.upper()

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

        if sign_format not in ("xys", "xyw"):
            raise ValueError(f"Unsupported sign_format={sign_format!r}; expected 'xys' or 'xyw'")

        cookie_dict = self._parse_cookies(cookies)
        a1_value = cookie_dict.get("a1")
        if not a1_value:
            raise ValueError("Missing 'a1' in cookies")

        if sign_format == "xyw":
            x_s = self.sign_xyw(method_upper, uri, a1_value, xsec_appid, request_data, timestamp)
        else:
            x_s = self.sign_xs(method_upper, uri, a1_value, xsec_appid, request_data, timestamp, session)

        x_s_common = self.sign_xs_common(cookie_dict)
        x_t = self.get_x_t(timestamp)
        x_b3_traceid = self.get_b3_trace_id()
        x_xray_traceid = self.get_xray_trace_id(timestamp=int(timestamp * 1000))

        headers = {
            "x-s": x_s,
            "x-s-common": x_s_common,
            "x-t": str(x_t),
            "x-b3-traceid": x_b3_traceid,
            "x-xray-traceid": x_xray_traceid,
            "x-mns": "unload",
            "xy-direction": str(get_sharding_key(user_id)),
        }

        if x_rap:
            rap_uri = extract_uri(uri)
            rap_api = "//edith.xiaohongshu.com" + rap_uri
            rap_data = request_data or {}
            headers["x-rap-param"] = x_rap_param(rap_api, rap_data)

        return headers

    def sign_headers_get(
        self,
        uri: str,
        cookies: dict[str, Any] | str,
        xsec_appid: str = "xhs-pc-web",
        params: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
        sign_format: Literal["xys", "xyw"] = "xys",
        user_id: str | None = None,
        x_rap: bool = False,
    ) -> dict[str, str]:
        """
        Generate complete request headers for GET request (convenience method)

        Args:
            uri: Request URI or full URL
            cookies: Complete cookie dictionary or cookie string
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            params: GET request parameters
            timestamp: Unix timestamp in seconds (defaults to current time)
            session: Optional session manager for stateful signing.
            sign_format: "xys" (default) or "xyw" (for data APIs that reject XYS_ with 406)
            user_id: Optional user ID for xy-direction sharding.
            x_rap: Whether to generate x-rap-param header.

        Returns:
            dict: Complete headers including x-s, x-s-common, x-t, x-b3-traceid, x-xray-traceid
        """
        return self.sign_headers(
            "GET",
            uri,
            cookies,
            xsec_appid,
            params=params,
            timestamp=timestamp,
            session=session,
            sign_format=sign_format,
            user_id=user_id,
            x_rap=x_rap,
        )

    def sign_headers_post(
        self,
        uri: str,
        cookies: dict[str, Any] | str,
        xsec_appid: str = "xhs-pc-web",
        payload: dict[str, Any] | None = None,
        timestamp: float | None = None,
        session: SessionManager | None = None,
        sign_format: Literal["xys", "xyw"] = "xys",
        user_id: str | None = None,
        x_rap: bool = False,
    ) -> dict[str, str]:
        """
        Generate complete request headers for POST request (convenience method)

        Args:
            uri: Request URI or full URL
            cookies: Complete cookie dictionary or cookie string
            xsec_appid: Application identifier, defaults to `xhs-pc-web`
            payload: POST request body data
            timestamp: Unix timestamp in seconds (defaults to current time)
            session: Optional session manager for stateful signing.
            sign_format: "xys" (default) or "xyw" (for data APIs that reject XYS_ with 406)
            user_id: Optional user ID for xy-direction sharding.
            x_rap: Whether to generate x-rap-param header.

        Returns:
            dict: Complete headers including x-s, x-s-common, x-t, x-b3-traceid, x-xray-traceid
        """
        return self.sign_headers(
            "POST",
            uri,
            cookies,
            xsec_appid,
            payload=payload,
            timestamp=timestamp,
            session=session,
            sign_format=sign_format,
            user_id=user_id,
            x_rap=x_rap,
        )
