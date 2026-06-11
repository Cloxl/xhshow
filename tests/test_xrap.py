import base64
import zlib

from xhshow.core.xrap import _encrypt_session_key, encrypt_block16, x_rap_param
from xhshow.utils.hash import xxh32  # noqa: F401

_EXPECTED_XRAP_B64 = (
    "ByQBBgAAAAEAAAAUAAABpPpzq6EAACg8AAAARQAAAAAAAAAAbWR6ejk0+smAqSAwipWIVZfre4sVCgAAABAIl9JTzVw4tViZZs/KPlVWzr8icnY"
    "+/OjuWTYbJ5T6PqquYAnYChZfQuIh98LpfBi4m7eHNiwoD50ubguIdIoezZUwES7ZF/iZtWJOfwv+Rmk59BrRvb+c1+vOwgCyPqfare0BNCljbA"
    "+BeaiEC/LxxADu+k11cFJ8jC/WtRYmd/22OjISKZEIk3IbhxGwlOXWXKKE3Y3z/TzI/TV0lZy5mFbf/9HLnRisUC1MnvZ5rAcIEfFyfJZmu7nVT"
    "RkIyPeFzKCYZpzeYLzPzpNDMwDIutu5LRF0T1rxafLuCB9irrV3YEy3h4ZKf19fGzPZIwDRDehjzmwR5JBECHuv+K+MFjMLN/jncDxBYasO0maf"
    "pyy9sgdPkMsE1Hq950mTMUSlCTIsX1yogVyc2PYxZzqrQTo/KbtfJdwQ4fAPWifEnd/daKSbTzN9u36theA0p54wYhUXUY9rVk56wwrS8c63AhA"
    "5DELbYzpAp3+9/+ZUnTP+ToNzyRl6zo1YQX67y9voKdfVS7dIPxstdWqOTaK8qalhONOXrwlDMG4vx4LGLAAAAZ8="
)


def test_encrypt_block16_known_pair():
    plain = bytes.fromhex("68ea78695e744b016d7a53a43a246167")
    assert encrypt_block16(plain).hex() == "d827df1c42d55ec61c0aec7d534fd817"


def test_encrypt_session_key_known_pair():
    assert _encrypt_session_key(b"wapilabkmyv4wl46").hex() == "fac980a920308a95885597eb7b8b150a00000010"


def test_xrap_param_packet_shape():
    value = x_rap_param(
        "//edith.xiaohongshu.com/api/sns/web/v1/homefeed",
        '{"a":1}',
        aes_key="wapilabkmyv4wl46",
        random_string="mdzz94",
        inner_key="h9w3tl5em3w4t67c",
        timestamp_ms=0x0000019EB07ACDB2,
        gzip_mtime=0x6A291532,
        body_encry_time=69,
        body_rand32=0xF95AD1C7,
        mask=0x65,
    )
    raw = base64.b64decode(value)
    assert raw[:4].hex() == "07240106"
    assert int.from_bytes(raw[4:8], "big") == 1
    assert int.from_bytes(raw[8:12], "big") == 20
    assert raw[36:42] == b"mdzz94"

    # fully deterministic when all randomness is fixed
    assert value == _EXPECTED_XRAP_B64
    assert zlib.crc32(raw[12:]) == 0x36C738DF
