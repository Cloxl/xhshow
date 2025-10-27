"""十六进制处理模块"""

from ..config import CryptoConfig

__all__ = ["HexProcessor"]


class HexProcessor:
    """十六进制数据处理工具类"""

    def __init__(self, config: CryptoConfig):
        self.config = config

    def hex_string_to_bytes(self, hex_string: str) -> list[int]:
        """
        将十六进制字符串转换为字节数组

        Args:
            hex_string (str): 十六进制字符串

        Returns:
            list[int]: 字节数组
        """
        byte_values = []
        for i in range(0, len(hex_string), self.config.HEX_CHUNK_SIZE):
            hex_chunk = hex_string[i : i + self.config.HEX_CHUNK_SIZE]
            byte_values.append(int(hex_chunk, 16))
        return byte_values

    def process_hex_parameter(self, hex_string: str, xor_key: int) -> list[int]:
        """
        处理十六进制参数

        Args:
            hex_string (str): 32字符十六进制字符串
            xor_key (int): XOR密钥

        Returns:
            list[int]: 处理后的8字节整数列表

        Raises:
            ValueError: 当hex_string长度不为32时
        """
        if len(hex_string) != self.config.EXPECTED_HEX_LENGTH:
            raise ValueError(
                f"hex parameter must be {self.config.EXPECTED_HEX_LENGTH} characters"
            )

        byte_values = self.hex_string_to_bytes(hex_string)
        return [byte_val ^ xor_key for byte_val in byte_values][
            : self.config.OUTPUT_BYTE_COUNT
        ]
