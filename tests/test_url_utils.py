import hashlib

import pytest

from xhshow import Xhshow
from xhshow.session import SessionManager
from xhshow.utils.url_utils import build_url, extract_api_path, extract_uri


class TestExtractApiPath:
    """Test extract_api_path function for all edge cases"""

    def test_post_with_json_body(self):
        """POST request with JSON body"""
        uri = '/api/sns/web/v1/homefeed{"cursor_score":"","num":47}'
        result = extract_api_path(uri)
        assert result == "/api/sns/web/v1/homefeed"
        assert hashlib.md5(result.encode()).hexdigest() == "6cb167ba87e1a756420d916fc234803c"

    def test_get_with_query_params(self):
        """GET request with query parameters"""
        uri = "/api/sns/web/v1/user_posted?num=30&user_id=123"
        result = extract_api_path(uri)
        assert result == "/api/sns/web/v1/user_posted"

    def test_plain_uri_no_params(self):
        """Plain URI without params or body"""
        uri = "/api/sns/web/v1/login"
        result = extract_api_path(uri)
        assert result == "/api/sns/web/v1/login"

    def test_question_before_brace(self):
        """Edge case: ? appears before {"""
        uri = '/api/test?param=1{"data":"value"}'
        result = extract_api_path(uri)
        assert result == "/api/test"

    def test_brace_before_question(self):
        """Edge case: { appears before ?"""
        uri = '/api/test{"key":"value"}?extra=param'
        result = extract_api_path(uri)
        assert result == "/api/test"

    def test_multiple_braces(self):
        """Multiple { in body"""
        uri = '/api/test{"nested":{"key":"value"}}'
        result = extract_api_path(uri)
        assert result == "/api/test"

    def test_multiple_question_marks(self):
        """Multiple ? in query string"""
        uri = "/api/test?param1=value?weird=true"
        result = extract_api_path(uri)
        assert result == "/api/test"

    def test_empty_path(self):
        """Edge case: root path"""
        uri = "/"
        result = extract_api_path(uri)
        assert result == "/"

    def test_path_with_special_chars(self):
        """Path containing special characters"""
        uri = "/api/user/@username/posts?limit=10"
        result = extract_api_path(uri)
        assert result == "/api/user/@username/posts"

    def test_chinese_in_body(self):
        """JSON body with Chinese characters"""
        uri = '/api/search{"keyword":"测试"}'
        result = extract_api_path(uri)
        assert result == "/api/search"

    def test_url_encoded_query(self):
        """URL encoded query parameters"""
        uri = "/api/search?q=%E6%B5%8B%E8%AF%95"
        result = extract_api_path(uri)
        assert result == "/api/search"

    def test_nested_path(self):
        """Deeply nested path"""
        uri = "/api/v1/users/123/posts/456/comments?sort=desc"
        result = extract_api_path(uri)
        assert result == "/api/v1/users/123/posts/456/comments"

    def test_path_ending_with_slash(self):
        """Path ending with /"""
        uri = "/api/users/?page=1"
        result = extract_api_path(uri)
        assert result == "/api/users/"

    def test_brace_at_start(self):
        """Edge case: { at the very start"""
        uri = '{"invalid":"path"}'
        result = extract_api_path(uri)
        assert result == ""

    def test_question_at_start(self):
        """Edge case: ? at the very start"""
        uri = "?invalid=path"
        result = extract_api_path(uri)
        assert result == ""


class TestExtractUri:
    def test_extract_uri_from_full_url(self):
        url = "https://edith.xiaohongshu.com/api/sns/web/v2/comment/sub/page"
        assert extract_uri(url) == "/api/sns/web/v2/comment/sub/page"

    def test_extract_uri_from_url_with_query(self):
        url = "https://edith.xiaohongshu.com/api/sns/web/v2/comment/sub/page?num=10&cursor=abc"
        assert extract_uri(url) == "/api/sns/web/v2/comment/sub/page"

    def test_extract_uri_from_uri_only(self):
        uri = "/api/sns/web/v1/user_posted"
        assert extract_uri(uri) == "/api/sns/web/v1/user_posted"

    def test_extract_uri_with_fragment(self):
        url = "https://example.com/path#section"
        assert extract_uri(url) == "/path"

    def test_extract_uri_empty_string(self):
        with pytest.raises(ValueError, match="URL must be a non-empty string"):
            extract_uri("")

    def test_extract_uri_none(self):
        with pytest.raises(ValueError, match="URL must be a non-empty string"):
            extract_uri(None)  # type: ignore

    def test_extract_uri_root_path(self):
        with pytest.raises(ValueError, match="Cannot extract valid URI path"):
            extract_uri("https://example.com/")

    def test_extract_uri_no_path(self):
        with pytest.raises(ValueError, match="Cannot extract valid URI path"):
            extract_uri("https://example.com")


class TestBuildUrl:
    def test_build_url_without_params(self):
        url = build_url("https://api.example.com/path")
        assert url == "https://api.example.com/path"

    def test_build_url_with_simple_params(self):
        url = build_url("https://api.example.com/path", {"a": "1", "b": "2"})
        assert url == "https://api.example.com/path?a=1&b=2"

    def test_build_url_with_equals_in_value(self):
        url = build_url("https://api.example.com/path", {"key": "value=test"})
        assert url == "https://api.example.com/path?key=value%3Dtest"

    def test_build_url_with_list_value(self):
        url = build_url("/api/path", {"ids": [1, 2, 3]})
        assert url == "/api/path?ids=1,2,3"

    def test_build_url_with_tuple_value(self):
        url = build_url("/api/path", {"tags": ("a", "b", "c")})
        assert url == "/api/path?tags=a,b,c"

    def test_build_url_with_none_value(self):
        url = build_url("/api/path", {"empty": None})
        assert url == "/api/path?empty="

    def test_build_url_with_existing_query(self):
        url = build_url("/api/path?existing=param", {"new": "value"})
        assert url == "/api/path?existing=param&new=value"

    def test_build_url_empty_base_url(self):
        with pytest.raises(ValueError, match="base_url must be a non-empty string"):
            build_url("")

    def test_build_url_none_base_url(self):
        with pytest.raises(ValueError, match="base_url must be a non-empty string"):
            build_url(None)  # type: ignore

    def test_build_url_none_params(self):
        url = build_url("https://api.example.com/path", None)
        assert url == "https://api.example.com/path"


class TestGithubSmokeTest:
    """Smoke tests for GitHub CI"""

    def test_extract_uri_basic(self):
        result = extract_uri("https://edith.xiaohongshu.com/api/sns/web/v1/search")
        assert result == "/api/sns/web/v1/search"

    def test_build_url_basic(self):
        result = build_url("/api/search", {"q": "test"})
        assert result == "/api/search?q=test"


class TestXhshowClientUrlMethods:
    """Test URL utility methods exposed through Xhshow client"""

    def test_client_build_url(self):
        client = Xhshow()
        url = client.build_url("https://api.example.com/path", {"key": "value"})
        assert url == "https://api.example.com/path?key=value"

    def test_client_build_url_with_equals(self):
        client = Xhshow()
        url = client.build_url("/api/path", {"token": "abc=def"})
        assert url == "/api/path?token=abc%3Ddef"

    def test_client_sign_with_full_url(self):
        client = Xhshow()
        signature = client.sign_xs_get(
            uri="https://edith.xiaohongshu.com/api/sns/web/v1/user_posted",
            a1_value="test_a1_value",
            params={"num": "30"},
        )
        assert signature.startswith("XYS_")

    def test_client_sign_with_empty_uri(self):
        client = Xhshow()
        with pytest.raises(ValueError, match="uri cannot be empty"):
            client.sign_xs_get(
                uri="",
                a1_value="test_a1_value",
                params={"num": "30"},
            )

    def test_client_sign_with_none_uri(self):
        client = Xhshow()
        with pytest.raises(TypeError, match="uri must be str"):
            client.sign_xs_get(
                uri=None,  # type: ignore
                a1_value="test_a1_value",
                params={"num": "30"},
            )

    def test_client_sign_with_empty_a1_value(self):
        client = Xhshow()
        with pytest.raises(ValueError, match="a1_value cannot be empty"):
            client.sign_xs_get(
                uri="/api/sns/web/v1/user_posted",
                a1_value="",
                params={"num": "30"},
            )

    def test_client_sign_with_invalid_params(self):
        client = Xhshow()
        with pytest.raises(TypeError, match="payload must be dict or None"):
            client.sign_xs_get(
                uri="/api/sns/web/v1/user_posted",
                a1_value="test_a1_value",
                params="invalid",  # type: ignore
            )

    def test_client_sign_with_session(self):
        client = Xhshow()
        session = SessionManager()
        for _ in range(10):
            signature = client.sign_xs_get(
                uri="/api/sns/web/v1/user_posted",
                a1_value="test_a1_value",
                params={"num": "30"},
                session=session,
            )

        assert signature.startswith("XYS_")
