import struct
import time

from ..config import CryptoConfig
from ..utils.bit_ops import BitOperations
from ..utils.encoder import Base64Encoder
from ..utils.hex_utils import HexProcessor
from ..utils.random_gen import RandomGenerator

__all__ = ["CryptoProcessor"]


class CryptoProcessor:
    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self.bit_ops = BitOperations(self.config)
        self.b64encoder = Base64Encoder(self.config)
        self.hex_processor = HexProcessor(self.config)
        self.random_gen = RandomGenerator()

    def _int_to_le_bytes(self, val: int, length: int = 4) -> list[int]:
        """Convert integer to little-endian byte array"""
        arr = []
        for _ in range(length):
            arr.append(val & 0xFF)
            val >>= 8
        return arr

    def _str_to_len_prefixed_bytes(self, s: str) -> list[int]:
        """Convert UTF-8 string to byte array with 1-byte length prefix"""
        buf = s.encode("utf-8")
        return [len(buf)] + list(buf)

    def env_fingerprint_a(self, ts: int, xor_key: int) -> list[int]:
        """Generate environment fingerprint A with checksum"""
        data = bytearray(struct.pack("<Q", ts))

        sum1 = sum(data[1:5])
        sum2 = sum(data[5:8])

        mark = ((sum1 & 0xFF) + sum2) & 0xFF
        data[0] = mark

        for i in range(len(data)):
            data[i] ^= xor_key

        return list(data)

    def env_fingerprint_b(self, ts: int) -> list[int]:
        """Generate simple environment fingerprint B (no encryption)"""
        return list(struct.pack("<Q", ts))

    def build_payload_array(
        self,
        hex_parameter: str,
        a1_value: str,
        app_identifier: str = "xhs-pc-web",
        string_param: str = "",
    ) -> list[int]:
        """
        Build payload array (t.js version - exact match)

        Args:
            hex_parameter (str): 32-character hexadecimal parameter (MD5 hash)
            a1_value (str): a1 value from cookies
            app_identifier (str): Application identifier, default "xhs-pc-web"
            string_param (str): String parameter (used for URI length calculation)

        Returns:
            list[int]: Complete payload byte array (124 bytes)
        """
        payload = []

        payload.extend(self.config.VERSION_BYTES)

        seed = self.random_gen.generate_random_int()
        seed_bytes = self._int_to_le_bytes(seed, 4)
        payload.extend(seed_bytes)
        seed_byte_0 = seed_bytes[0]

        timestamp = time.time()
        payload.extend(self.env_fingerprint_a(int(timestamp * 1000), self.config.ENV_FINGERPRINT_XOR_KEY))

        time_offset = self.random_gen.generate_random_byte_in_range(
            self.config.ENV_FINGERPRINT_TIME_OFFSET_MIN,
            self.config.ENV_FINGERPRINT_TIME_OFFSET_MAX,
        )
        payload.extend(self.env_fingerprint_b(int((timestamp - time_offset) * 1000)))

        sequence_value = self.random_gen.generate_random_byte_in_range(
            self.config.SEQUENCE_VALUE_MIN, self.config.SEQUENCE_VALUE_MAX
        )
        payload.extend(self._int_to_le_bytes(sequence_value, 4))

        window_props_length = self.random_gen.generate_random_byte_in_range(
            self.config.WINDOW_PROPS_LENGTH_MIN, self.config.WINDOW_PROPS_LENGTH_MAX
        )
        payload.extend(self._int_to_le_bytes(window_props_length, 4))

        # URI length
        uri_length = len(string_param)
        payload.extend(self._int_to_le_bytes(uri_length, 4))

        # MD5 XOR segment
        md5_bytes = bytes.fromhex(hex_parameter)
        for i in range(8):
            payload.append(md5_bytes[i] ^ seed_byte_0)

        # A1 length
        payload.append(52)

        # A1 content
        a1_bytes = a1_value.encode("utf-8")
        if len(a1_bytes) > 52:
            a1_bytes = a1_bytes[:52]
        elif len(a1_bytes) < 52:
            a1_bytes = a1_bytes + b"\x00" * (52 - len(a1_bytes))
        payload.extend(a1_bytes)

        # Source length
        payload.append(10)

        # Source content
        source_bytes = app_identifier.encode("utf-8")
        if len(source_bytes) > 10:
            source_bytes = source_bytes[:10]
        elif len(source_bytes) < 10:
            source_bytes = source_bytes + b"\x00" * (10 - len(source_bytes))
        payload.extend(source_bytes)

        payload.append(1)

        payload.append(self.config.CHECKSUM_VERSION)
        payload.append(seed_byte_0 ^ self.config.CHECKSUM_XOR_KEY)
        payload.extend(self.config.CHECKSUM_FIXED_TAIL)

        return payload
