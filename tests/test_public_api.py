import re

from xhshow import Xhshow
from xhshow.utils.random_gen import RandomGenerator
from xhshow.utils.sharding import get_sharding_key


def test_generate_a1_length():
    a1 = RandomGenerator.generate_a1()
    assert len(a1) == 52
    assert a1.isalnum()


def test_generate_web_id_known_pair():
    a1 = "19ab1e5ce48c3b3c5c50e2c040a801cfcca0a4ac50000571046"
    web_id = RandomGenerator.generate_web_id(a1)
    assert web_id == "9a1f41a6292d4e1742bb95f8f9fd1ad3"
    assert len(web_id) == 32
    assert re.fullmatch(r"[0-9a-f]{32}", web_id)


def test_search_id_is_base36():
    search_id = Xhshow().get_search_id()
    assert re.fullmatch(r"[0-9a-z]+", search_id)


def test_search_request_id_format():
    request_id = Xhshow().get_search_request_id()
    random_part, _, ts_part = request_id.partition("-")
    assert random_part.isdigit()
    assert ts_part.isdigit()
    assert len(ts_part) == 13  # millisecond timestamp


def test_sharding_key_deterministic_and_ranged():
    user_id = "5ff0e6c70000000001008f9a"
    assert get_sharding_key(user_id) == 36
    assert get_sharding_key(user_id) == get_sharding_key(user_id)


def test_sharding_key_random_in_range():
    for _ in range(50):
        assert 10 <= get_sharding_key(None) <= 100


def test_sign_headers_includes_mns_and_direction():
    cookies = {"a1": "abc123", "web_session": "sess", "webId": "wid"}
    headers = Xhshow().sign_headers_get(
        uri="/api/sns/web/v1/user_posted",
        cookies=cookies,
        params={"num": "30"},
    )
    assert headers["x-mns"] == "unload"
    assert headers["xy-direction"].isdigit()
    assert "x-rap-param" not in headers


def test_sign_headers_xy_direction_from_user_id():
    cookies = {"a1": "abc123", "web_session": "sess"}
    headers = Xhshow().sign_headers_get(
        uri="/api/sns/web/v1/user_posted",
        cookies=cookies,
        params={"num": "30"},
        user_id="5ff0e6c70000000001008f9a",
    )
    assert headers["xy-direction"] == "36"


def test_sign_headers_adds_xrap_when_enabled():
    cookies = {"a1": "abc123", "web_session": "sess"}
    headers = Xhshow().sign_headers_post(
        uri="/api/sns/web/v1/feed",
        cookies=cookies,
        payload={"source_note_id": "x"},
        x_rap=True,
    )
    assert "x-rap-param" in headers
    assert headers["x-rap-param"]
