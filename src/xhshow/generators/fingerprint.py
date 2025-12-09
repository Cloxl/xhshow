"""Browser fingerprint generator"""

import hashlib
import json
import random
import secrets
import time
import urllib.parse

from Crypto.Cipher import ARC4

from ..config import CryptoConfig
from ..data import fingerprint_data as FPData
from ..utils import encoder
from . import fingerprint_helpers as helpers

__all__ = ["FingerprintGenerator"]


class FingerprintGenerator:
    """XHS Fingerprint generation function"""

    def __init__(self, config: CryptoConfig):
        self.config = config
        self._b1_key = self.config.B1_SECRET_KEY.encode()
        self._encoder = encoder.Base64Encoder(self.config)

    def generate_b1(self, fp: dict) -> str:
        """
        Generate b1 parameter from fingerprint

        Args:
            fp: Fingerprint dictionary

        Returns:
            Base64 encoded b1 string
        """
        b1_fp = {
            "x33": fp["x33"],
            "x34": fp["x34"],
            "x35": fp["x35"],
            "x36": fp["x36"],
            "x37": fp["x37"],
            "x38": fp["x38"],
            "x39": fp["x39"],
            "x42": fp["x42"],
            "x43": fp["x43"],
            "x44": fp["x44"],
            "x45": fp["x45"],
            "x46": fp["x46"],
            "x48": fp["x48"],
            "x49": fp["x49"],
            "x50": fp["x50"],
            "x51": fp["x51"],
            "x52": fp["x52"],
            "x82": fp["x82"],
        }
        b1_json = json.dumps(b1_fp, separators=(",", ":"), ensure_ascii=False)
        cipher = ARC4.new(self._b1_key)
        ciphertext = cipher.encrypt(b1_json.encode("utf-8")).decode("latin1")
        encoded_url = urllib.parse.quote(ciphertext, safe="!*'()~_-")
        b = []
        for c in encoded_url.split("%")[1:]:
            chars = list(c)
            b.append(int("".join(chars[:2]), 16))
            [b.append(ord(j)) for j in chars[2:]]

        b1 = self._encoder.encode(bytearray(b))

        return b1

    def generate(self, cookies: dict, user_agent: str) -> dict:
        """
        Generate browser fingerprint

        Args:
            cookies: Cookie dictionary
            user_agent: User agent string

        Returns:
            Complete fingerprint dictionary
        """
        cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items())

        screen_config = helpers.get_screen_config()
        is_incognito_mode = helpers.weighted_random_choice(["true", "false"], [0.95, 0.05])
        vendor, renderer = helpers.get_renderer_info()

        x78_y = random.randint(2350, 2450)
        fp = {
            "x1": user_agent,
            "x2": "false",
            "x3": "zh-CN",
            "x4": helpers.weighted_random_choice(
                FPData.COLOR_DEPTH_OPTIONS["values"],
                FPData.COLOR_DEPTH_OPTIONS["weights"],
            ),
            "x5": helpers.weighted_random_choice(
                FPData.DEVICE_MEMORY_OPTIONS["values"],
                FPData.DEVICE_MEMORY_OPTIONS["weights"],
            ),
            "x6": "24",
            "x7": f"{vendor},{renderer}",
            "x8": helpers.weighted_random_choice(FPData.CORE_OPTIONS["values"], FPData.CORE_OPTIONS["weights"]),
            "x9": f"{screen_config['width']};{screen_config['height']}",
            "x10": f"{screen_config['availWidth']};{screen_config['availHeight']}",
            "x11": "-480",
            "x12": "Asia/Shanghai",
            "x13": is_incognito_mode,
            "x14": is_incognito_mode,
            "x15": is_incognito_mode,
            "x16": "false",
            "x17": "false",
            "x18": "un",
            "x19": "Win32",
            "x20": "",
            "x21": FPData.BROWSER_PLUGINS,
            "x22": helpers.generate_webgl_hash(),
            "x23": "false",
            "x24": "false",
            "x25": "false",
            "x26": "false",
            "x27": "false",
            "x28": "0,false,false",
            "x29": "4,7,8",
            "x30": "swf object not loaded",
            "x33": "0",
            "x34": "0",
            "x35": "0",
            "x36": f"{random.randint(1, 20)}",
            "x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|1|0|0|0|0|0",
            "x38": "0|0|1|0|1|0|0|0|0|0|1|0|1|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0",
            "x39": 0,
            "x40": "0",
            "x41": "0",
            "x42": "3.4.4",
            "x43": helpers.generate_canvas_hash(),
            "x44": f"{int(time.time() * 1000)}",
            "x45": "__SEC_CAV__1-1-1-1-1|__SEC_WSA__|",
            "x46": "false",
            "x47": "1|0|0|0|0|0",
            "x48": "",
            "x49": "{list:[],type:}",
            "x50": "",
            "x51": "",
            "x52": "",
            "x55": "380,380,360,400,380,400,420,380,400,400,360,360,440,420",
            "x56": f"{vendor}|{renderer}|{helpers.generate_webgl_hash()}|35",
            "x57": cookie_string,
            "x58": "180",
            "x59": "2",
            "x60": "63",
            "x61": "1291",
            "x62": "2047",
            "x63": "0",
            "x64": "0",
            "x65": "0",
            "x66": {
                "referer": "",
                "location": "https://www.xiaohongshu.com/explore",
                "frame": 0,
            },
            "x67": "1|0",
            "x68": "0",
            "x69": "326|1292|30",
            "x70": ["location"],
            "x71": "true",
            "x72": "complete",
            "x73": "1191",
            "x74": "0|0|0",
            "x75": "Google Inc.",
            "x76": "true",
            "x77": "1|1|1|1|1|1|1|1|1|1",
            "x78": {
                "x": 0,
                "y": x78_y,
                "left": 0,
                "right": 290.828125,
                "bottom": x78_y + 18,
                "height": 18,
                "top": x78_y,
                "width": 290.828125,
                "font": FPData.FONTS,
            },
            "x82": "_0x17a2|_0x1954",
            "x31": "124.04347527516074",
            "x79": "144|599565058866",
            "x53": hashlib.md5(secrets.token_bytes(32)).hexdigest(),
            "x54": FPData.VOICE_HASH_OPTIONS,
            "x80": "1|[object FileSystemDirectoryHandle]",
        }

        return fp

    def update(self, fp: dict, cookies: dict, url: str) -> None:
        """
        Update fingerprint with new cookies and URL

        Args:
            fp: Fingerprint dictionary to update
            cookies: Updated cookie dictionary
            url: Current URL
        """
        cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items())

        fp.update(
            {
                "x39": 0,
                "x44": f"{time.time() * 1000}",
                "x57": cookie_string,
                "x66": {
                    "referer": "https://www.xiaohongshu.com/explore",
                    "location": url,
                    "frame": 0,
                },
            }
        )
