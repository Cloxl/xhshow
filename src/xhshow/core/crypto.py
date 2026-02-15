import hashlib
import struct
import time
from typing import TYPE_CHECKING

from ..config import CryptoConfig
from ..utils.bit_ops import BitOperations
from ..utils.encoder import Base64Encoder
from ..utils.hex_utils import HexProcessor
from ..utils.random_gen import RandomGenerator
from ..utils.url_utils import extract_api_path

if TYPE_CHECKING:
    from ..session import SignState


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

    def _rotate_left(self, val: int, n: int) -> int:
        """32-bit left rotation"""
        return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

    def _custom_hash_v2(self, input_bytes: list[int]) -> list[int]:
        """
        Custom hash function for a3 field generation
        Input: byte list (must be multiple of 8)
        Output: 16-byte list
        """
        s0, s1, s2, s3 = self.config.HASH_IV
        length = len(input_bytes)

        s0 ^= length
        s1 ^= length << 8
        s2 ^= length << 16
        s3 ^= length << 24

        for i in range(length // 8):
            v0, v1 = struct.unpack("<II", bytes(input_bytes[i * 8 : (i + 1) * 8]))

            s0 = self._rotate_left(((s0 + v0) & 0xFFFFFFFF) ^ s2, 7)
            s1 = self._rotate_left(((v0 ^ s1) + s3) & 0xFFFFFFFF, 11)
            s2 = self._rotate_left(((s2 + v1) & 0xFFFFFFFF) ^ s0, 13)
            s3 = self._rotate_left(((s3 ^ v1) + s1) & 0xFFFFFFFF, 17)

        t0 = s0 ^ length
        t1 = s1 ^ t0
        t2 = (s2 + t1) & 0xFFFFFFFF
        t3 = s3 ^ t2

        s0 = (self._rotate_left(t0, 9) + (s2 := self._rotate_left(t2, 17))) & 0xFFFFFFFF
        s1 = (s1 := self._rotate_left(t1, 13)) ^ (s3 := self._rotate_left(t3, 19))
        s2 = (s2 + s0) & 0xFFFFFFFF
        s3 = s3 ^ s1

        result = []
        for s in [s0, s1, s2, s3]:
            result.extend(self._int_to_le_bytes(s, 4))
        return result

    def build_payload_array(
        self,
        hex_parameter: str,
        a1_value: str,
        app_identifier: str = "xhs-pc-web",
        string_param: str = "",
        timestamp: float | None = None,
        sign_state: "SignState | None" = None,
    ) -> list[int]:
        """
        Build 144-byte payload array (mns0301 version)

        Args:
            hex_parameter (str): 32-character hexadecimal parameter (MD5 hash of uri+data)
            a1_value (str): a1 value from cookies
            app_identifier (str): Application identifier, default "xhs-pc-web"
            string_param (str): String parameter (URI+data for MD5 and length calculation)
            timestamp (float | None): Unix timestamp in seconds (defaults to current time)
            sign_state (SignState | None): Optional state for realistic signature generation.

        Returns:
            list[int]: Complete payload byte array (144 bytes)
        """
        timestamp = time.time() if timestamp is None else timestamp
        seed = self.random_gen.generate_random_int()
        seed_byte = seed & 0xFF

        payload = list(self.config.VERSION_BYTES)
        payload.extend(self._int_to_le_bytes(seed, 4))

        ts_bytes = self._int_to_le_bytes(int(timestamp * 1000), 8)
        payload.extend(ts_bytes)

        if sign_state:
            payload.extend(self._int_to_le_bytes(sign_state.page_load_timestamp, 8))
            payload.extend(self._int_to_le_bytes(sign_state.sequence_value, 4))
            payload.extend(self._int_to_le_bytes(sign_state.window_props_length, 4))
            payload.extend(self._int_to_le_bytes(sign_state.uri_length, 4))
        else:
            payload.extend(
                self._int_to_le_bytes(
                    int(
                        (
                            timestamp
                            - self.random_gen.generate_random_byte_in_range(
                                self.config.ENV_FINGERPRINT_TIME_OFFSET_MIN,
                                self.config.ENV_FINGERPRINT_TIME_OFFSET_MAX,
                            )
                        )
                        * 1000
                    ),
                    8,
                )
            )
            payload.extend(
                self._int_to_le_bytes(
                    self.random_gen.generate_random_byte_in_range(
                        self.config.SEQUENCE_VALUE_MIN, self.config.SEQUENCE_VALUE_MAX
                    ),
                    4,
                )
            )
            payload.extend(
                self._int_to_le_bytes(
                    self.random_gen.generate_random_byte_in_range(
                        self.config.WINDOW_PROPS_LENGTH_MIN, self.config.WINDOW_PROPS_LENGTH_MAX
                    ),
                    4,
                )
            )
            payload.extend(self._int_to_le_bytes(len(string_param.encode("utf-8")), 4))

        payload.extend([bytes.fromhex(hex_parameter)[i] ^ seed_byte for i in range(8)])

        a1_bytes = a1_value.encode("utf-8")[:52].ljust(52, b"\x00")
        payload.append(len(a1_bytes))
        payload.extend(a1_bytes)

        app_bytes = app_identifier.encode("utf-8")[:10].ljust(10, b"\x00")
        payload.append(len(app_bytes))
        payload.extend(app_bytes)

        part11 = [1, seed_byte ^ self.config.ENV_TABLE[0]]
        part11.extend(self.config.ENV_TABLE[i] ^ self.config.ENV_CHECKS_DEFAULT[i] for i in range(1, 15))
        payload.extend(part11)

        api_path = extract_api_path(string_param)
        md5_path_bytes = [int(hashlib.md5(api_path.encode("utf-8")).hexdigest()[i : i + 2], 16) for i in range(0, 32, 2)]

        payload.extend(
            [2, 97, 51, 16] + [b ^ seed_byte for b in self._custom_hash_v2(ts_bytes + md5_path_bytes)]
        )

        assert len(payload) == 144, f"Payload length error: {len(payload)}, expected 144"
        return payload
