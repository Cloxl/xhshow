from dataclasses import dataclass, field, replace
from typing import Any

__all__ = ["CryptoConfig"]


@dataclass(frozen=True)
class CryptoConfig:
    """Configuration constants for cryptographic operations"""

    # Gid encrypt parameters
    DES_KEY = "zbp30y86"
    GID_URL = "https://as.xiaohongshu.com/api/sec/v1/shield/webprofile"
    DATA_PALTFORM = "Windows"
    DATA_SVN = "2"
    DATA_SDK_VERSION = "4.2.6"
    DATA_webBuild = "5.0.3"

    # Bitwise operation constants
    MAX_32BIT: int = 0xFFFFFFFF
    MAX_SIGNED_32BIT: int = 0x7FFFFFFF
    MAX_BYTE: int = 255

    # Base64 encoding constants
    STANDARD_BASE64_ALPHABET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    CUSTOM_BASE64_ALPHABET: str = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
    X3_BASE64_ALPHABET: str = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"

    # XOR key for payload transformation (124 bytes)
    HEX_KEY: str = "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277"  # noqa: E501

    # Hexadecimal processing constants
    EXPECTED_HEX_LENGTH: int = 32
    OUTPUT_BYTE_COUNT: int = 8
    HEX_CHUNK_SIZE: int = 2

    # Payload construction constants
    VERSION_BYTES: list[int] = field(default_factory=lambda: [119, 104, 96, 41])

    # Random value ranges
    SEQUENCE_VALUE_MIN: int = 15
    SEQUENCE_VALUE_MAX: int = 50
    WINDOW_PROPS_LENGTH_MIN: int = 900
    WINDOW_PROPS_LENGTH_MAX: int = 1200

    # Checksum constants (16 bytes total)
    CHECKSUM_VERSION: int = 1
    CHECKSUM_XOR_KEY: int = 115
    CHECKSUM_FIXED_TAIL: list[int] = field(
        default_factory=lambda: [249, 65, 103, 103, 201, 181, 131, 99, 94, 7, 68, 250, 132, 21]
    )

    # Environment fingerprint generation parameters
    ENV_FINGERPRINT_XOR_KEY: int = 41
    ENV_FINGERPRINT_TIME_OFFSET_MIN: int = 10
    ENV_FINGERPRINT_TIME_OFFSET_MAX: int = 50

    # Signature data template
    SIGNATURE_DATA_TEMPLATE: dict[str, str] = field(
        default_factory=lambda: {
            "x0": "4.2.6",
            "x1": "xhs-pc-web",
            "x2": "Windows",
            "x3": "",
            "x4": "",
        }
    )

    # Prefix constants
    X3_PREFIX: str = "mns0301_"
    XYS_PREFIX: str = "XYS_"

    # Trace ID generation constants
    HEX_CHARS: str = "abcdef0123456789"
    XRAY_TRACE_ID_SEQ_MAX: int = 8388607  # 2^23-1
    XRAY_TRACE_ID_TIMESTAMP_SHIFT: int = 23
    XRAY_TRACE_ID_PART1_LENGTH: int = 16
    XRAY_TRACE_ID_PART2_LENGTH: int = 16
    B3_TRACE_ID_LENGTH: int = 16

    # b1 secret key
    B1_SECRET_KEY: str = "xhswebmplfbt"

    SIGNATURE_XSCOMMON_TEMPLATE: dict[str, Any] = field(
        default_factory=lambda: {
            "s0": 5,
            "s1": "",
            "x0": "1",
            "x1": "4.2.6",
            "x2": "Windows",
            "x3": "xhs-pc-web",
            "x4": "4.86.0",
            "x5": "",
            "x6": "",
            "x7": "",
            "x8": "",
            "x9": -596800761,
            "x10": 0,
            "x11": "normal",
        }
    )

    PUBLIC_USERAGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
    )

    def with_overrides(self, **kwargs: Any) -> "CryptoConfig":
        """
        Create a new config instance with overridden values

        Args:
            **kwargs: Field names and their new values

        Returns:
            CryptoConfig: New config instance with updated values

        Examples:
            >>> config = CryptoConfig().with_overrides(
            ...     SEQUENCE_VALUE_MIN=20,
            ...     SEQUENCE_VALUE_MAX=60,
            ...     XYS_PREFIX="CUSTOM_"
            ... )
        """
        return replace(self, **kwargs)
