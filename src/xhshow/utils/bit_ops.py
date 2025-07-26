"""位操作和种子变换模块"""

from ..config import CryptoConfig

__all__ = ["BitOperations"]


class BitOperations:
    """位操作和种子变换工具类"""

    def __init__(self):
        self.config = CryptoConfig()

    def normalize_to_32bit(self, value: int) -> int:
        """
        将值标准化为32位

        Args:
            value (int): 输入值

        Returns:
            int: 32位标准化值
        """
        return value & self.config.MAX_32BIT

    def to_signed_32bit(self, unsigned_value: int) -> int:
        """
        将无符号32位值转换为有符号32位值

        Args:
            unsigned_value (int): 无符号32位值

        Returns:
            int: 有符号32位值
        """
        if unsigned_value > self.config.MAX_SIGNED_32BIT:
            return unsigned_value - 0x100000000
        return unsigned_value

    def compute_seed_value(self, seed_32bit: int) -> int:
        """
        计算种子值变换

        Args:
            seed_32bit (int): 32位种子值

        Returns:
            int: 变换后的有符号32位整数
        """
        normalized_seed = self.normalize_to_32bit(seed_32bit)

        shift_15_bits = normalized_seed >> 15
        shift_13_bits = normalized_seed >> 13
        shift_12_bits = normalized_seed >> 12
        shift_10_bits = normalized_seed >> 10

        xor_masked_result = (shift_15_bits & ~shift_13_bits) | (
            shift_13_bits & ~shift_15_bits
        )
        shifted_result = (
            (xor_masked_result ^ shift_12_bits ^ shift_10_bits) << 31
        ) & self.config.MAX_32BIT

        return self.to_signed_32bit(shifted_result)

    def xor_transform_array(self, source_integers: list[int]) -> bytearray:
        """
        对整数数组进行XOR变换

        Args:
            source_integers (list[int]): 源整数数组

        Returns:
            bytearray: 变换后的字节数组
        """
        result_bytes = bytearray(len(source_integers))

        for index in range(len(source_integers)):
            result_bytes[index] = (
                source_integers[index] ^ bytes.fromhex(self.config.HEX_KEY)[index]
            ) & 0xFF

        return result_bytes
