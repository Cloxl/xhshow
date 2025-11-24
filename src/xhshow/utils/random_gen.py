import random

from ..config import CryptoConfig

__all__ = ["RandomGenerator"]


class RandomGenerator:
    """随机数生成工具类"""

    def __init__(self):
        self.config = CryptoConfig()

    def generate_random_bytes(self, byte_count: int) -> list[int]:
        """
        生成指定长度的随机字节数组

        Args:
            byte_count (int): 需要生成的字节数量

        Returns:
            list[int]: 随机字节数组
        """
        return [random.randint(0, 255) for _ in range(byte_count)]

    def generate_random_byte_in_range(self, min_val: int, max_val: int) -> int:
        """
        生成指定范围内的随机字节

        Args:
            min_val (int): 最小值
            max_val (int): 最大值

        Returns:
            int: 指定范围内的随机整数
        """
        return random.randint(min_val, max_val)

    def generate_random_int(self) -> int:
        """
        生成4字节随机整数

        Returns:
            int: 32位随机整数
        """
        return random.randint(0, self.config.MAX_32BIT)
