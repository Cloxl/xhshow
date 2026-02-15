from urllib.parse import urlparse

__all__ = ["extract_uri", "build_url", "extract_api_path"]


def extract_api_path(uri_with_data: str) -> str:
    """
    Extract pure API path from URI (removes query params and JSON body)

    Args:
        uri_with_data: URI that may contain query params or JSON body
            - With JSON body: "/api/homefeed{\"num\":47}"
            - With query params: "/api/homefeed?num=47"
            - Plain URI: "/api/homefeed"

    Returns:
        str: Pure API path without params or body

    Examples:
        >>> extract_api_path('/api/homefeed{"num":47}')
        '/api/homefeed'
        >>> extract_api_path('/api/homefeed?num=47')
        '/api/homefeed'
        >>> extract_api_path('/api/homefeed')
        '/api/homefeed'
    """
    brace_pos = uri_with_data.find("{")
    question_pos = uri_with_data.find("?")

    if brace_pos != -1 and question_pos != -1:
        return uri_with_data[: min(brace_pos, question_pos)]
    elif brace_pos != -1:
        return uri_with_data[:brace_pos]
    elif question_pos != -1:
        return uri_with_data[:question_pos]
    else:
        return uri_with_data


def extract_uri(url: str) -> str:
    """
    Extract URI path from full URL (removes protocol, host, query, fragment)

    Args:
        url: Full URL or URI path
            - Full URL: "https://edith.xiaohongshu.com/api/sns/web/v2/comment/sub/page?num=10"
            - URI only: "/api/sns/web/v2/comment/sub/page"

    Returns:
        str: URI path without query string

    Raises:
        ValueError: If URL is invalid or path cannot be extracted

    Examples:
        >>> extract_uri("https://edith.xiaohongshu.com/api/sns/web/v2/comment/sub/page")
        '/api/sns/web/v2/comment/sub/page'

        >>> extract_uri("https://edith.xiaohongshu.com/api/sns/web/v2/comment/sub/page?num=10")
        '/api/sns/web/v2/comment/sub/page'

        >>> extract_uri("/api/sns/web/v2/comment/sub/page")
        '/api/sns/web/v2/comment/sub/page'
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    url = url.strip()

    parsed = urlparse(url)

    path = parsed.path

    if not path or path == "/":
        raise ValueError(f"Cannot extract valid URI path from URL: {url}")

    return path


def build_url(base_url: str, params: dict | None = None) -> str:
    """
    Build complete URL with query parameters (handles parameter escaping)

    IMPORTANT: This function uses XHS platform-specific encoding rules.
    Only '=' characters are encoded as '%3D'. Other special characters
    (including ',') are NOT encoded, as required by XHS signature algorithm.
    DO NOT use urllib.parse.urlencode as it would encode additional characters
    and break the signature verification.

    Args:
        base_url: Base URL (can include or exclude protocol/host)
        params: Query parameters dictionary

    Returns:
        str: Complete URL with properly encoded query string

    Examples:
        >>> build_url("https://api.example.com/path", {"key": "value=test"})
        'https://api.example.com/path?key=value%3Dtest'

        >>> build_url("/api/path", {"a": "1", "b": "2"})
        '/api/path?a=1&b=2'

        >>> build_url("/api/path", {"tags": ["tech", "python"]})
        '/api/path?tags=tech,python'

        >>> build_url("/api/path?existing=1", {"new": "2"})
        '/api/path?existing=1&new=2'

        >>> build_url("/api/path?", {"key": "value"})
        '/api/path?key=value'
    """
    if not base_url or not isinstance(base_url, str):
        raise ValueError("base_url must be a non-empty string")

    if not params:
        return base_url

    query_parts = []
    for key, value in params.items():
        if isinstance(value, list | tuple):
            formatted_value = ",".join(str(v) for v in value)
        elif value is not None:
            formatted_value = str(value)
        else:
            formatted_value = ""

        # XHS platform requires only '=' to be encoded as '%3D'
        # Other special characters must remain unencoded for signature matching
        encoded_value = formatted_value.replace("=", "%3D")
        query_parts.append(f"{key}={encoded_value}")

    query_string = "&".join(query_parts)

    # Determine correct separator based on URL structure
    if "?" not in base_url:
        separator = "?"
    elif base_url.endswith(("?", "&")):
        separator = ""
    else:
        separator = "&"

    return f"{base_url}{separator}{query_string}"
