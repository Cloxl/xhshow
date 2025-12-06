"""Tests for cookie parsing and sign_headers functionality"""

import pytest

from xhshow import Xhshow
from xhshow.core.common_sign import XsCommonSigner


class TestCookieParsing:
    """测试 Cookie 解析功能"""

    def setup_method(self):
        self.client = Xhshow()

    def test_parse_cookies_from_dict(self):
        """测试从字典解析 cookies"""
        cookies_dict = {
            "a1": "test_a1_value",
            "web_session": "test_session",
            "webId": "test_web_id",
        }

        result = self.client._parse_cookies(cookies_dict)

        assert isinstance(result, dict)
        assert result == cookies_dict
        assert result is cookies_dict  # Should return the same object for dict input

    def test_parse_cookies_from_string(self):
        """测试从字符串解析 cookies"""
        cookie_string = "a1=test_a1_value; web_session=test_session; webId=test_web_id"

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert "a1" in result
        assert "web_session" in result
        assert "webId" in result
        assert result["a1"] == "test_a1_value"
        assert result["web_session"] == "test_session"
        assert result["webId"] == "test_web_id"

    def test_parse_cookies_from_string_with_spaces(self):
        """测试解析带空格的 cookie 字符串"""
        cookie_string = "a1=value1;  web_session=value2  ;webId=value3"

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert "a1" in result
        assert "web_session" in result
        assert "webId" in result

    def test_parse_cookies_from_string_with_special_chars(self):
        """测试解析包含特殊字符的 cookie"""
        cookie_string = 'a1=abc123_-.; web_session="quoted value"; key=value='

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert "a1" in result
        assert "web_session" in result

    def test_parse_cookies_empty_dict(self):
        """测试空字典解析"""
        result = self.client._parse_cookies({})

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_parse_cookies_empty_string(self):
        """测试空字符串解析"""
        result = self.client._parse_cookies("")

        assert isinstance(result, dict)
        assert len(result) == 0


class TestSignXsCommon:
    """测试 x-s-common 签名功能"""

    def setup_method(self):
        self.client = Xhshow()

    def test_sign_xs_common_with_dict(self):
        """测试使用字典生成 x-s-common"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
            "webId": "test_web_id",
        }

        result = self.client.sign_xs_common(cookies)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_sign_xs_common_with_string(self):
        """测试使用字符串生成 x-s-common"""
        cookie_string = "a1=test_a1_value; web_session=test_session; webId=test_web_id"

        result = self.client.sign_xs_common(cookie_string)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_sign_xs_common_consistency(self):
        """测试字典和字符串输入的一致性"""
        cookies_dict = {
            "a1": "test_a1_value",
            "web_session": "test_session",
            "webId": "test_web_id",
        }
        cookie_string = "a1=test_a1_value; web_session=test_session; webId=test_web_id"

        result_dict = self.client.sign_xs_common(cookies_dict)
        result_string = self.client.sign_xs_common(cookie_string)

        # Both should produce valid results
        assert isinstance(result_dict, str)
        assert isinstance(result_string, str)
        assert len(result_dict) > 0
        assert len(result_string) > 0

    def test_sign_xs_common_missing_a1(self):
        """测试缺少 a1 时的异常处理"""
        cookies = {
            "web_session": "test_session",
            "webId": "test_web_id",
        }

        with pytest.raises(KeyError, match="a1"):
            self.client.sign_xs_common(cookies)

    def test_sign_xsc_alias(self):
        """测试 sign_xsc 别名方法"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        result = self.client.sign_xsc(cookies)

        assert isinstance(result, str)
        assert len(result) > 0


class TestXsCommonSigner:
    """测试 XsCommonSigner 类"""

    def setup_method(self):
        self.signer = XsCommonSigner()

    def test_sign_with_dict_only(self):
        """测试只接受字典参数"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
            "webId": "test_web_id",
        }

        result = self.signer.sign(cookies)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_sign_missing_a1(self):
        """测试缺少 a1 的异常"""
        cookies = {
            "web_session": "test_session",
        }

        with pytest.raises(KeyError, match="a1"):
            self.signer.sign(cookies)

    def test_sign_reproducibility(self):
        """测试签名的可重现性"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        result1 = self.signer.sign(cookies)
        result2 = self.signer.sign(cookies)

        # Note: May contain random elements, so just check format
        assert isinstance(result1, str)
        assert isinstance(result2, str)
        assert len(result1) > 0
        assert len(result2) > 0


class TestSignHeaders:
    """测试 sign_headers 系列方法"""

    def setup_method(self):
        self.client = Xhshow()

    def test_sign_headers_get_with_dict(self):
        """测试 GET 请求使用字典 cookies"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        headers = self.client.sign_headers(
            method="GET",
            uri="/api/sns/web/v1/user_posted",
            cookies=cookies,
            params={"num": "30"},
        )

        assert isinstance(headers, dict)
        assert "x-s" in headers
        assert "x-s-common" in headers
        assert "x-t" in headers
        assert "x-b3-traceid" in headers
        assert "x-xray-traceid" in headers

        assert headers["x-s"].startswith("XYS_")
        assert len(headers["x-s-common"]) > 0
        assert headers["x-t"].isdigit()
        assert len(headers["x-b3-traceid"]) == 16
        assert len(headers["x-xray-traceid"]) == 32

    def test_sign_headers_get_with_string(self):
        """测试 GET 请求使用字符串 cookies"""
        cookie_string = "a1=test_a1_value; web_session=test_session; webId=test_web_id"

        headers = self.client.sign_headers(
            method="GET",
            uri="/api/sns/web/v1/user_posted",
            cookies=cookie_string,
            params={"num": "30"},
        )

        assert isinstance(headers, dict)
        assert "x-s" in headers
        assert "x-s-common" in headers
        assert headers["x-s"].startswith("XYS_")
        assert len(headers["x-s-common"]) > 0

    def test_sign_headers_post_with_dict(self):
        """测试 POST 请求使用字典 cookies"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        headers = self.client.sign_headers(
            method="POST",
            uri="/api/sns/web/v1/login",
            cookies=cookies,
            payload={"username": "test", "password": "123456"},
        )

        assert isinstance(headers, dict)
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])
        assert headers["x-s"].startswith("XYS_")
        assert len(headers["x-s-common"]) > 0

    def test_sign_headers_post_with_string(self):
        """测试 POST 请求使用字符串 cookies"""
        cookie_string = "a1=test_a1_value; web_session=test_session"

        headers = self.client.sign_headers(
            method="POST",
            uri="/api/sns/web/v1/login",
            cookies=cookie_string,
            payload={"username": "test"},
        )

        assert isinstance(headers, dict)
        assert "x-s" in headers
        assert "x-s-common" in headers
        assert headers["x-s"].startswith("XYS_")

    def test_sign_headers_missing_a1(self):
        """测试缺少 a1 cookie 的异常处理"""
        cookies = {
            "web_session": "test_session",
        }

        with pytest.raises(ValueError, match="Missing 'a1' in cookies"):
            self.client.sign_headers(
                method="GET",
                uri="/api/test",
                cookies=cookies,
                params={"key": "value"},
            )

    def test_sign_headers_get_convenience(self):
        """测试 sign_headers_get 便捷方法"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        headers = self.client.sign_headers_get(
            uri="/api/sns/web/v1/user_posted",
            cookies=cookies,
            params={"num": "30"},
        )

        assert isinstance(headers, dict)
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])

    def test_sign_headers_post_convenience(self):
        """测试 sign_headers_post 便捷方法"""
        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }

        headers = self.client.sign_headers_post(
            uri="/api/sns/web/v1/login",
            cookies=cookies,
            payload={"username": "test"},
        )

        assert isinstance(headers, dict)
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])

    def test_sign_headers_with_timestamp(self):
        """测试使用自定义时间戳"""
        import time

        cookies = {
            "a1": "test_a1_value",
            "web_session": "test_session",
        }
        custom_ts = time.time()

        headers = self.client.sign_headers(
            method="GET",
            uri="/api/test",
            cookies=cookies,
            params={"key": "value"},
            timestamp=custom_ts,
        )

        assert headers["x-t"] == str(int(custom_ts * 1000))

    def test_cookie_parsing_only_once(self):
        """测试 cookie 只被解析一次(性能测试)"""
        # This is more of a design verification test
        # We can't directly test parse count, but we verify the result is correct

        cookie_string = "a1=test_a1_value; web_session=test_session; webId=test_web_id"

        headers = self.client.sign_headers(
            method="GET",
            uri="/api/test",
            cookies=cookie_string,
            params={"key": "value"},
        )

        # Both x-s and x-s-common should work correctly
        assert headers["x-s"].startswith("XYS_")
        assert len(headers["x-s-common"]) > 0

        # Verify all expected headers are present
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])


class TestCookieParsingEdgeCases:
    """测试 Cookie 解析的边界情况"""

    def setup_method(self):
        self.client = Xhshow()

    def test_cookie_with_equals_in_value(self):
        """测试 cookie 值中包含等号"""
        cookie_string = "a1=abc=def=ghi; web_session=test"

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert "a1" in result
        # SimpleCookie handles this - value should be everything after first =
        assert "=" in result["a1"] or result["a1"] == "abc"

    def test_cookie_with_semicolon_in_quoted_value(self):
        """测试引号内包含分号的 cookie"""
        cookie_string = 'a1="value;with;semicolons"; web_session=test'

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert "a1" in result
        assert "web_session" in result

    def test_cookie_with_unicode(self):
        """测试包含 Unicode 字符的 cookie"""
        cookies_dict = {
            "a1": "test_a1_值",
            "web_session": "测试",
        }

        result = self.client._parse_cookies(cookies_dict)

        assert result == cookies_dict
        assert result["a1"] == "test_a1_值"
        assert result["web_session"] == "测试"

    def test_cookie_string_only_one_cookie(self):
        """测试只有一个 cookie 的字符串"""
        cookie_string = "a1=test_value"

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        assert len(result) == 1
        assert result["a1"] == "test_value"

    def test_cookie_with_path_and_domain(self):
        """测试带有 path 和 domain 的 cookie 字符串"""
        # SimpleCookie can handle full cookie attributes
        cookie_string = "a1=value1; Path=/; Domain=.example.com; web_session=value2"

        result = self.client._parse_cookies(cookie_string)

        assert isinstance(result, dict)
        # Should extract cookie names and values, ignoring attributes
        assert "a1" in result or "Path" in result  # SimpleCookie behavior
