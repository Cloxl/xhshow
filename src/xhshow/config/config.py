from dataclasses import dataclass

__all__ = ["CryptoConfig"]


@dataclass(frozen=True)
class CryptoConfig:
    """加密处理相关配置常量"""

    # 位操作相关常量
    MAX_32BIT = 0xFFFFFFFF  # 32位无符号整数最大值掩码
    MAX_SIGNED_32BIT = 0x7FFFFFFF  # 32位有符号整数最大值

    # Base58编码相关常量
    BASE58_ALPHABET = "NOPQRStuvwxWXYZabcyz012DEFTKLMdefghijkl4563GHIJBC7mnop89+/AUVqrsOPQefghijkABCDEFGuvwz0123456789xy"  # Base58编码字符表
    STANDARD_BASE64_ALPHABET = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    CUSTOM_BASE64_ALPHABET = (
        "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
    )
    BASE58_BASE = 58  # Base58进制基数
    BYTE_SIZE = 256  # 字节大小(2^8)

    # XOR 密钥
    HEX_KEY = "af572b95ca65b2d9ec76bb5d2e97cb653299cc663399cc663399cce673399cce6733190c06030100000000008040209048241289c4e271381c0e0703018040a05028148ac56231180c0683c16030984c2693c964b259ac56abd5eaf5fafd7e3f9f4f279349a4d2e9743a9d4e279349a4d2e9f47a3d1e8f47239148a4d269341a8d4623110884422190c86432994ca6d3e974baddee773b1d8e47a35128148ac5623198cce6f3f97c3e1f8f47a3d168b45aad562b158ac5e2f1f87c3e9f4f279349a4d269b45aad56"

    # 时间戳相关常量
    TIMESTAMP_BYTES_COUNT = 16  # 时间戳字节数组长度
    TIMESTAMP_XOR_KEY = 41  # 时间戳编码XOR密钥
    STARTUP_TIME_OFFSET_MIN = 1000  # 启动时间偏移最小值
    STARTUP_TIME_OFFSET_MAX = 4000  # 启动时间偏移最大值

    # 十六进制处理相关常量
    EXPECTED_HEX_LENGTH = 32  # 十六进制参数预期长度
    OUTPUT_BYTE_COUNT = 8  # 处理后输出字节数
    HEX_CHUNK_SIZE = 2  # 十六进制字符块大小

    # 载荷构建相关常量
    VERSION_BYTES = [119, 104, 96, 41]  # 版本标识字节
    FIXED_SEPARATOR_BYTES = [16, 0, 0, 0, 15, 5, 0, 0, 47, 1, 0, 0]  # 固定分隔符字节
    RANDOM_BYTE_COUNT = 4  # 随机字节数量
    FIXED_INT_VALUE_1 = 15  # 固定整数值1
    FIXED_INT_VALUE_2 = 1291  # 固定整数值2

    ENV_STATIC_BYTES = [  # 环境变量静态字节
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

    # 签名数据模板
    SIGNATURE_DATA_TEMPLATE = {
        "x0": "4.2.2",
        "x1": "xhs-pc-web",
        "x2": "Windows",
        "x3": "",
        "x4": "object",
    }

    # 前缀常量
    X3_PREFIX = "mns0101_"
    XYS_PREFIX = "XYS_"
