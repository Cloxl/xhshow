"""
Created on Wed Nov 5 2025 AM
@author: <Edward Furlong>
Describe: generate fingerprint payload for encrypt x-s-common params, that current FP include much important information
1. user_agent  2. cookie info  3. timeZone need same current request location, just be care concurrent with proxy addr
4. encrypt code version  5.whether browser has been tampered picture hash value  6. some others detect(hook, screen)
"""

import hashlib
import json
import random
import secrets
import time
import urllib.parse
from typing import Any

from Crypto.Cipher import ARC4

from ..config import CryptoConfig
from . import encoder


class XhsFpGenerator:
    """XHS Fingerprint generate function"""

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.__b1_key = self.config.B1_SECRET_KEY.encode()

    @staticmethod
    def __weighted_random_choice(options: list, weights: list) -> Any:
        """
        Random choice a value from list according to the given weights
        Argument:
            options (list): option list
            weights (list): weight list mapping the option list(Without Normalization)
        """
        return f"{random.choices(options, weights=weights, k=1)[0]}"

    @staticmethod
    def __get_renderer_info() -> list:
        renderer_info_list = [
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 400 (0x00000166) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 4400 (0x00001112) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 4600 (0x00000412) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 520 (0x1912) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 530 (0x00001912) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 550 (0x00001512) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 6000 (0x1606) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(TM) Graphics 540 (0x1912) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(TM) Graphics 550 (0x1913) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics 640 (0x161C) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 600 (0x3E80) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00003EA0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 655 (0x00009BC8) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x000046A8) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(R) Xe MAX Graphics (0x00009BC0) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A370M (0x0000AF51) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A380 (0x0000AF41) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A380M (0x0000AF5E) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A550 (0x0000AF42) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A770 (0x0000AF43) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel Arc A770M (0x0000AF50) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) Graphics (RPL‑P GT1) (0x0000A702) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) UHD Graphics 770 (0x00004680) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) HD Graphics 4400 (0x00001122) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) Graphics (ADL‑S GT1) (0x0000A0A1) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) Graphics (RKL GT1) (0x0000A9A1) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Mesa Intel(R) UHD Graphics (CML GT2) (0x00009A14) OpenGL 4.6)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics 3000 (0x00001022) Direct3D9Ex vs_3_0 ps_3_0, igdumd64.dll)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) HD Graphics Family (0x00000A16) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris Pro OpenGL Engine, OpenGL 4.1)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics 645 (0x1616) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics 655 (0x161E) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 730 (0x0000A100) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Intel)|ANGLE (Intel, Intel(R) UHD Graphics 805 (0x0000B0A0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Vega 3 Graphics (0x000015E0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Vega 8 Graphics (0x000015D8) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Vega 11 Graphics (0x000015DD) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Graphics (0x00001636) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 5500 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 560 (0x000067EF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 570 (0x000067DF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 580 2048SP (0x00006FDF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 590 (0x000067FF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6600 (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6600 XT (0x000073FF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6650 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6700 XT (0x000073DF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6800 (0x000073BF) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 6900 XT (0x000073C2) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon RX 7700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Pro 5300M OpenGL Engine, OpenGL 4.1)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon Pro 5500 XT OpenGL Engine, OpenGL 4.1)",
            "Google Inc. (AMD)|ANGLE (AMD, AMD Radeon R7 370 Series (0x00006811) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (AMD)|ANGLE (AMD, ATI Technologies Inc. AMD Radeon RX Vega 64 OpenGL Engine, OpenGL 4.1)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 (0x00001C81) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Ti (0x00001C8C) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB (0x000010DE) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1070 (0x00001B81) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 (0x00001B80) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 (0x00001F06) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 SUPER (0x00001F06) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 2070 (0x00001F10) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 2070 SUPER (0x00001F10) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x0000250F) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti (0x00002489) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 (0x00002488) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Ti (0x000028A5) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 (0x00002206) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Ti (0x00002208) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 3090 (0x00002204) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 (0x00002882) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Ti (0x00002803) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 (0x00002786) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti (0x00002857) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4080 (0x00002819) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 (0x00002684) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA Quadro RTX 5000 Ada Generation (0x000026B2) Direct3D11 vs_5_0 ps_5_0, D3D11)",  # noqa: E501
            "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA Quadro P400 (0x00001CB3) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Google Inc. (Google)|ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",  # noqa: E501
            "Google Inc. (Google)|ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)",
            "Google Inc. (Google)|ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device), SwiftShader driver)",
        ]

        return random.choice(renderer_info_list).split("|")

    @staticmethod
    def __get_width_and_height():
        width, height = XhsFpGenerator.__weighted_random_choice(
            ["1366;768", "1600;900", "1920;1080", "2560;1440", "3840;2160", "7680;4320"],
            [0.25, 0.15, 0.35, 0.15, 0.08, 0.02],
        ).split(";")
        if random.choice([True, False]):
            availWidth = int(width) - int(
                XhsFpGenerator.__weighted_random_choice([0, 30, 60, 80], [0.1, 0.4, 0.3, 0.2])
            )
            availHeight = height
        else:
            availWidth = width
            availHeight = int(height) - int(
                XhsFpGenerator.__weighted_random_choice([30, 60, 80, 100], [0.2, 0.5, 0.2, 0.1])
            )

        return width, height, availWidth, availHeight

    def generate_b1(self, fp):
        config = CryptoConfig()
        b64_encoder = encoder.Base64Encoder(config)
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
        cipher = ARC4.new(self.__b1_key)
        ciphertext = cipher.encrypt(b1_json.encode("utf-8")).decode("latin1")
        encoded_url = urllib.parse.quote(ciphertext, safe="!*'()~_-")
        b = []
        for c in encoded_url.split("%")[1:]:
            chars = list(c)
            b.append(int("".join(chars[:2]), 16))
            [b.append(ord(j)) for j in chars[2:]]

        b1 = b64_encoder.custom_to_b64(bytearray(b))

        return b1

    @staticmethod
    def get_fingerprint(cookies: dict, user_agent: str) -> dict:
        cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items())

        width, height, availWidth, availHeight = XhsFpGenerator.__get_width_and_height()

        is_incognito_mode = XhsFpGenerator.__weighted_random_choice(["true", "false"], [0.95, 0.05])

        vendor, renderer = XhsFpGenerator.__get_renderer_info()

        x78_y = random.randint(2350, 2450)
        fp = {
            "x1": user_agent,
            "x2": "false",  # navigator.webdriver
            "x3": "zh-CN",  # navigator.language
            "x4": XhsFpGenerator.__weighted_random_choice([16, 24, 30, 32], [0.05, 0.6, 0.05, 0.3]),
            # screen.colorDepth
            "x5": XhsFpGenerator.__weighted_random_choice([1, 2, 4, 8, 12, 16], [0.10, 0.25, 0.4, 0.2, 0.03, 0.01]),
            # navigator.deviceMemory
            "x6": "24",  # screen.pixelDepth
            "x7": f"{vendor},{renderer}",
            "x8": XhsFpGenerator.__weighted_random_choice(
                [2, 4, 6, 8, 12, 16, 24, 32], [0.1, 0.4, 0.2, 0.15, 0.08, 0.04, 0.02, 0.01]
            ),
            "x9": f"{width};{height}",
            "x10": f"{availWidth};{availHeight}",
            "x11": "-480",  # new Date().getTimezoneOffset()。
            "x12": "Asia/Shanghai",  # Intl.DateTimeFormat().resolvedOptions().timeZone       default timezone
            "x13": is_incognito_mode,  # window.sessionStorage detect
            "x14": is_incognito_mode,  # window.localStorage detect
            "x15": is_incognito_mode,  # window.indexedDB detect
            "x16": "false",
            "x17": "false",
            "x18": "un",
            "x19": "Win32",
            "x20": "",
            "x21": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
            # navigator.plugins
            "x22": hashlib.md5(secrets.token_bytes(32)).hexdigest(),
            "x23": "false",  # DOM environment detect
            "x24": "false",
            "x25": "false",
            "x26": "false",
            "x27": "false",
            "x28": "0,false,false",
            "x29": "4,7,8",
            "x30": "swf object not loaded",  # detect Flash（SWF） Boolean(navigator.plugins['Shockwave Flash']);
            # "x32": "0", # haven't used
            "x33": "0",  # whether in WeChat browser                 constant
            "x34": "0",  # whether js paint tool is Brian Paul       constant
            "x35": "0",  # whether did have loaded Modernizr         constant
            "x36": f"{random.randint(1, 20)}",  # window.history.length   history stack length
            "x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|1|0|0|0|0|0",
            "x38": "0|0|1|0|1|0|0|0|0|0|1|0|1|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0",
            "x39": 0,  # localStorage.getItem('sc');   plus one by every fresh page
            "x40": "0",  # localStorage.getItem('ptt');
            "x41": "0",  # localStorage.getItem('pst');
            "x42": "3.4.4",  # Fingerprint.js version        // constant
            "x43": "742cc32c",  # Detecting whether a browser has been tampered with by comparing
            # the hash value of an image
            "x44": f"{int(time.time() * 1000)}",  # current timestamp
            "x45": "__SEC_CAV__1-1-1-1-1|__SEC_WSA__|",
            # risk control SDK information if risk just show like __SEC_WSA__|
            "x46": "false",
            # navigator.__proto__.hasOwnProperty('webdriver');                              risk control
            # Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');  // true → risk control
            "x47": "1|0|0|0|0|0",  # recognize different browser「unique feature」 //  constant
            "x48": "",
            "x49": "{list:[],type:}",
            "x50": "",
            "x51": "",
            "x52": "",
            "x55": "380,380,360,400,380,400,420,380,400,400,360,360,440,420",
            "x56": f"{vendor}|{renderer}|{hashlib.md5(secrets.token_bytes(32)).hexdigest()}|35",
            # x7 | Fingerprint2.x64hash128(WebGLRenderingContext.getSupportedExtensions()) | WebGLRenderingContext.getSupportedExtensions().length   # noqa: E501
            "x57": cookie_string,
            "x58": "180",  # document.getElementsByTagName('div') // count div (just above 177, not strict) constant
            "x59": "2",  # performance.getEntriesByType("resource").length
            "x60": "63",  # risk control score        // constant
            "x61": "1291",  # Object.getOwnPropertyNames(window) .length  // window object amount
            "x62": "2047",  # HOOK detect 1,1,1,1,1,1,1,1,1,1,1  11个1(通过) 组成二进制2047 constant
            "x63": "0",  # JS VMP file \n detect         // constant
            "x64": "0",  # HOOK ToString number detect
            "x65": "0",
            "x66": {  # navigator.userAgent
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
            "x75": "Google Inc.",  # Navigator.vendor
            "x76": "true",  # navigator.cookieEnabled
            "x77": "1|1|1|1|1|1|1|1|1|1",  # constant
            "x78": {
                "x": 0,
                "y": x78_y,
                "left": 0,
                "right": 290.828125,
                "bottom": x78_y + 18,
                "height": 18,
                "top": x78_y,
                "width": 290.828125,
                "font": 'system-ui, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji", -apple-system, "Segoe UI", Roboto, Ubuntu, Cantarell, "Noto Sans", sans-serif, BlinkMacSystemFont, "Helvetica Neue", Arial, "PingFang SC", "PingFang TC", "PingFang HK", "Microsoft Yahei", "Microsoft JhengHei"',  # noqa: E501
            },
            "x82": "_0x17a2|_0x1954",  # get iframe.contentWindow | contentWindow.window
            "x31": "124.04347527516074",
            "x79": "144|599565058866",
            # navigator.webkitTemporaryStorage.queryUsageAndQuota(used, granted)
            "x53": hashlib.md5(secrets.token_bytes(32)).hexdigest(),
            # "235c6559af50acefe4755120d05570a0"  if "edge/" in user_agent else "993da9a681fd3994c9f53de11f2903b3",
            # speechSynthesis.getVoices()  Fingerprint2.x64hash128
            "x54": "10311144241322244122",
            "x80": "1|[object FileSystemDirectoryHandle]",
        }

        return fp

    @staticmethod
    def update_fingerprint(fp: dict, cookies: dict, url: str) -> None:
        cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items())

        fp.update(
            {
                "x39": 0,  # localStorage.getItem('p1');  Add the value with every request +1
                "x44": f"{time.time() * 1000}",  # current timestamp multiply 1000
                "x57": cookie_string,
                "x66": {  # navigator.userAgent
                    "referer": "https://www.xiaohongshu.com/explore",
                    "location": url,
                    "frame": 0,
                },
            }
        )


# test
# if __name__ == '__main__':
#     cookie_str = (
#         'abRequestId=6824d155-7a52-5954-8e0b-52621534b645; a1=199326716575ch0ke4fatjw4p6s5f36p9gyb1z0ep50000367754'
#         '; webId=236dbdde593bd45175a14b220bf2cda8; gid'
#         '=yjjqJKWqYSjWyjjqJKWyKku82W2Sx8Td4i09vdUVE4UKMD282iqKUy888qKWW2482dfW0SJf; x-user-id-creator.xiaohongshu'
#         '.com=62653884000000001000d895; customerClientId=211311472456037; access-token-creator.xiaohongshu.com'
#         '=customer.creator.AT-68c5175501602299901050976ci4wzrowbjolncn; galaxy_creator_session_id'
#         '=dv0q3EYVV52XFb03dqv9wFqc5wOrcnZBBG6q; galaxy.creator.beaker.session.id=1757908666550096704063; webBuild=4'
#         '.81.0; web_session=040069b9c0b8fa37713448b6e43a4b16f2f1b5; xsecappid=xhs-pc-web; loadts=1758606105469; '
#         'acw_tc=0ad586d517586066572636904e2fbedce995fe2d22709cedcfeabec5ab856d; websectiga'
#         '=10f9a40ba454a07755a08f27ef8194c53637eba4551cf9751c009d9afb564467; sec_poison_id=7d693d02-b858-4476-a432'
#         '-5c003b3ff9f0; unread={%22ub%22:%2268d13701000000000b03cfc1%22%2C%22ue%22:%2268c26c99000000001d026ca5%22%2C'
#         '%22uc%22:24}')
#     c = SimpleCookie()
#     c.load(cookie_str)
#     cookie_dict = {k: morsel.value for k, morsel in c.items()}
#
#     headers = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 "
#                "Safari/537.36")
#
#     crypto_config = CryptoConfig()
#     gfp = XhsFpGenerator(crypto_config)
#     fp = gfp.get_fingerprint(cookies=cookie_dict, user_agent=headers)
#     b1 = gfp.generate_b1(fp)
#     print(b1)
