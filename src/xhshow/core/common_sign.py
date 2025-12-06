"""x-s-common signature generation"""

import json
from typing import Any

from ..config import CryptoConfig
from ..core.crc32_encrypt import CRC32
from ..generators.fingerprint import FingerprintGenerator
from ..utils.encoder import Base64Encoder

__all__ = ["XsCommonSigner"]


class XsCommonSigner:
    """Generate x-s-common signatures"""

    def __init__(self, config: CryptoConfig | None = None):
        self.config = config or CryptoConfig()
        self._fp_generator = FingerprintGenerator(self.config)
        self._encoder = Base64Encoder(self.config)

    def sign(self, cookie_dict: dict[str, Any]) -> str:
        """
        Generate x-s-common signature

        Args:
            cookie_dict: Cookie dictionary (must be dict, not string)

        Returns:
            x-s-common signature string

        Raises:
            KeyError: If 'a1' cookie is missing
        """
        a1_value = cookie_dict["a1"]
        fingerprint = self._fp_generator.generate(cookies=cookie_dict, user_agent=self.config.PUBLIC_USERAGENT)
        b1 = self._fp_generator.generate_b1(fingerprint)

        x9 = CRC32.crc32_js_int(b1)

        sign_struct = dict(self.config.SIGNATURE_XSCOMMON_TEMPLATE)
        sign_struct["x5"] = a1_value
        sign_struct["x8"] = b1
        sign_struct["x9"] = x9

        sign_json = json.dumps(sign_struct, separators=(",", ":"), ensure_ascii=False)
        xs_common = self._encoder.encode(sign_json)

        return xs_common
