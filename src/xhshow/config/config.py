from dataclasses import dataclass

__all__ = ["CryptoConfig"]


@dataclass(frozen=True)
class CryptoConfig:
    """Configuration constants for cryptographic operations"""

    # Bitwise operation constants
    MAX_32BIT = 0xFFFFFFFF  # 32-bit unsigned integer maximum value mask
    MAX_SIGNED_32BIT = 0x7FFFFFFF  # 32-bit signed integer maximum value

    # Base58 encoding constants
    BASE58_ALPHABET = "NOPQRStuvwxWXYZabcyz012DEFTKLMdefghijkl4563GHIJBC7mnop89+/AUVqrsOPQefghijkABCDEFGuvwz0123456789xy"  # Base58 encoding character table
    STANDARD_BASE64_ALPHABET = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    CUSTOM_BASE64_ALPHABET = (
        "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
    )
    BASE58_BASE = 58  # Base58 radix
    BYTE_SIZE = 256  # Byte size (2^8)

    # XOR key
    HEX_KEY = "af572b95ca65b2d9ec76bb5d2e97cb653299cc663399cc663399cce673399cce6733190c06030100000000008040209048241289c4e271381c0e0703018040a05028148ac56231180c0683c16030984c2693c964b259ac56abd5eaf5fafd7e3f9f4f279349a4d2e9743a9d4e279349a4d2e9f47a3d1e8f47239148a4d269341a8d4623110884422190c86432994ca6d3e974baddee773b1d8e47a35128148ac5623198cce6f3f97c3e1f8f47a3d168b45aad562b158ac5e2f1f87c3e9f4f279349a4d269b45aad56"

    # Timestamp related constants
    TIMESTAMP_BYTES_COUNT = 16  # Timestamp byte array length
    TIMESTAMP_XOR_KEY = 41  # Timestamp encoding XOR key
    STARTUP_TIME_OFFSET_MIN = 1000  # Startup time offset minimum value
    STARTUP_TIME_OFFSET_MAX = 4000  # Startup time offset maximum value

    # Hexadecimal processing constants
    EXPECTED_HEX_LENGTH = 32  # Expected hexadecimal parameter length
    OUTPUT_BYTE_COUNT = 8  # Output byte count after processing
    HEX_CHUNK_SIZE = 2  # Hexadecimal character chunk size

    # Payload construction constants
    VERSION_BYTES = [119, 104, 96, 41]  # Version identifier bytes
    FIXED_SEPARATOR_BYTES = [
        16,
        0,
        0,
        0,
        15,
        5,
        0,
        0,
        47,
        1,
        0,
        0,
    ]  # Fixed separator bytes
    RANDOM_BYTE_COUNT = 4  # Random byte count
    FIXED_INT_VALUE_1 = 15  # Fixed integer value 1
    FIXED_INT_VALUE_2 = 1291  # Fixed integer value 2

    ENV_STATIC_BYTES = [  # Environment variable static bytes
        1,
        249,
        83,
        102,
        103,
        201,
        181,
        131,
        99,
        94,
        7,
        68,
        250,
        132,
        21,
    ]

    # Signature data template
    SIGNATURE_DATA_TEMPLATE = {
        "x0": "4.2.6",
        "x1": "xhs-pc-web",
        "x2": "Windows",
        "x3": "",
        "x4": "object",
    }

    # Prefix constants
    X3_PREFIX = "mns0101_"
    XYS_PREFIX = "XYS_"
