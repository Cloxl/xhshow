from urllib.parse import urlparse

__all__ = ["extract_uri", "build_url"]


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

        encoded_value = formatted_value.replace("=", "%3D")
        query_parts.append(f"{key}={encoded_value}")

    query_string = "&".join(query_parts)
    separator = "&" if "?" in base_url else "?"

    return f"{base_url}{separator}{query_string}"
