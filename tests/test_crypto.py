import pytest

from xhshow import CryptoProcessor, Xhshow
from xhshow.core.crc32_encrypt import CRC32


class TestCryptoProcessor:
    """测试CryptoProcessor核心加密处理器"""

    def setup_method(self):
        self.crypto = CryptoProcessor()

    def test_build_payload_array_basic(self):
        """测试载荷数组构建基本功能"""
        hex_param = "d41d8cd98f00b204e9800998ecf8427e"
        a1_value = "test_a1_value"

        result = self.crypto.build_payload_array(hex_param, a1_value)

        assert isinstance(result, list)
        assert len(result) > 50
        assert all(isinstance(x, int) and 0 <= x <= 255 for x in result)

    def test_bit_ops_normalize_to_32bit(self):
        """测试32位标准化"""
        result = self.crypto.bit_ops.normalize_to_32bit(0x1FFFFFFFF)
        assert result == 0xFFFFFFFF

        result = self.crypto.bit_ops.normalize_to_32bit(858975407)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_bit_ops_compute_seed_value(self):
        """测试种子值计算"""
        seed = 858975407
        result = self.crypto.bit_ops.compute_seed_value(seed)

        assert isinstance(result, int)
        assert -2147483648 <= result <= 2147483647

    def test_bit_ops_xor_transform_array(self):
        """测试XOR数组变换"""
        test_array = [119, 104, 96, 41, 175, 87, 91, 112]
        result = self.crypto.bit_ops.xor_transform_array(test_array)

        assert isinstance(result, bytearray)
        assert len(result) == len(test_array)
        assert all(isinstance(x, int) and 0 <= x <= 255 for x in result)

    def test_base58_encoder(self):
        """测试Base58编码"""
        # Base58已移除,此测试不再需要
        pass

    def test_base64_encoder(self):
        """测试自定义Base64编码"""
        test_string = "Hello, World!"
        result = self.crypto.b64encoder.encode(test_string)

        assert isinstance(result, str)
        assert len(result) > 0

        # Test round-trip encode/decode
        decoded = self.crypto.b64encoder.decode(result)
        assert decoded == test_string

    def test_base64_decoder_invalid_input(self):
        """测试Base64解码对非法输入的异常处理"""
        invalid_inputs = [
            "!!!invalid!!!",  # Invalid characters
            "abc",  # Invalid length (not multiple of 4)
            "YWJj*Zw==",  # Invalid character
        ]

        for invalid in invalid_inputs:
            with pytest.raises(ValueError):
                self.crypto.b64encoder.decode(invalid)

    def test_base64_x3_encoder(self):
        """测试x3签名Base64编码"""
        test_bytes = bytearray([1, 2, 3, 4, 5])
        result = self.crypto.b64encoder.encode_x3(test_bytes)

        assert isinstance(result, str)
        assert len(result) > 0

        # Test round-trip encode/decode
        decoded = self.crypto.b64encoder.decode_x3(result)
        assert decoded == test_bytes

    def test_base64_x3_decoder_invalid_input(self):
        """测试x3签名Base64解码对非法输入的异常处理"""
        # Test with truly invalid Base64 after alphabet translation
        with pytest.raises(ValueError):
            # String with incorrect padding
            self.crypto.b64encoder.decode_x3("abc")

    def test_hex_processor(self):
        """测试十六进制处理"""
        hex_string = "d41d8cd98f00b204e9800998ecf8427e"
        xor_key = 175

        result = self.crypto.hex_processor.process_hex_parameter(hex_string, xor_key)

        assert isinstance(result, list)
        assert len(result) == 8
        assert all(isinstance(x, int) and 0 <= x <= 255 for x in result)

    def test_random_generator(self):
        """测试随机数生成器"""
        # 测试随机字节
        result = self.crypto.random_gen.generate_random_bytes(10)
        assert isinstance(result, list)
        assert len(result) == 10
        assert all(isinstance(x, int) and 0 <= x <= 255 for x in result)

        # 测试范围随机数
        result = self.crypto.random_gen.generate_random_byte_in_range(10, 20)
        assert isinstance(result, int)
        assert 10 <= result <= 20

        # 测试32位随机数
        result = self.crypto.random_gen.generate_random_int()
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF


class TestXhshow:
    """测试Xhshow客户端类"""

    def setup_method(self):
        self.client = Xhshow()

    def test_build_content_string_get(self):
        """测试GET请求的内容字符串构建"""
        method = "GET"
        uri = "/api/sns/web/v1/user_posted"
        payload = {"num": "30", "cursor": "", "user_id": "123"}

        result = self.client._build_content_string(method, uri, payload)

        assert isinstance(result, str)
        assert uri in result
        assert "num=30" in result
        assert "user_id=123" in result
        assert result.startswith(uri + "?")

    def test_build_content_string_post(self):
        """测试POST请求的内容字符串构建"""
        method = "POST"
        uri = "/api/sns/web/v1/login"
        payload = {"username": "test", "password": "123456"}

        result = self.client._build_content_string(method, uri, payload)

        assert isinstance(result, str)
        assert result.startswith(uri)
        assert '"username":"test"' in result
        assert '"password":"123456"' in result

    def test_generate_d_value_get(self):
        """测试GET请求的d值生成"""
        method = "GET"
        uri = "/api/sns/web/v1/user_posted"
        payload = {"num": "30", "cursor": "", "user_id": "123"}

        content_string = self.client._build_content_string(method, uri, payload)
        result = self.client._generate_d_value(content_string)

        assert isinstance(result, str)
        assert len(result) == 32
        int(result, 16)

    def test_generate_d_value_post(self):
        """测试POST请求的d值生成"""
        method = "POST"
        uri = "/api/sns/web/v1/login"
        payload = {"username": "test", "password": "123456"}

        content_string = self.client._build_content_string(method, uri, payload)
        result = self.client._generate_d_value(content_string)

        assert isinstance(result, str)
        assert len(result) == 32
        int(result, 16)

    def test_build_signature(self):
        """测试签名构建"""
        d_value = "d41d8cd98f00b204e9800998ecf8427e"
        a1_value = "test_a1_value"

        result = self.client._build_signature(d_value, a1_value)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_sign_xs_get(self):
        """测试GET请求签名生成"""
        method = "GET"
        uri = "/api/sns/web/v1/user_posted"
        a1_value = "test_a1_value"
        payload = {"num": "30", "cursor": "", "user_id": "123"}

        result = self.client.sign_xs(method, uri, a1_value, payload=payload)

        assert isinstance(result, str)
        assert result.startswith("XYS_")
        assert len(result) > 10

    def test_sign_xs_post(self):
        """测试POST请求签名生成"""
        method = "POST"
        uri = "/api/sns/web/v1/login"
        a1_value = "test_a1_value"
        payload = {"username": "test", "password": "123456"}

        result = self.client.sign_xs(method, uri, a1_value, payload=payload)

        assert isinstance(result, str)
        assert result.startswith("XYS_")
        assert len(result) > 10

    def test_sign_xs_no_payload(self):
        """测试无payload的请求签名生成"""
        method = "GET"
        uri = "/api/sns/web/v1/homefeed"
        a1_value = "test_a1_value"

        result = self.client.sign_xs(method, uri, a1_value)

        assert isinstance(result, str)
        assert result.startswith("XYS_")
        assert len(result) > 10

    def test_sign_xs_get_convenience(self):
        """测试GET请求便捷方法"""
        uri = "/api/sns/web/v1/user_posted"
        a1_value = "test_a1_value"
        params = {"num": "30", "cursor": "", "user_id": "123"}

        result = self.client.sign_xs_get(uri, a1_value, params=params)

        assert isinstance(result, str)
        assert result.startswith("XYS_")
        assert len(result) > 10

    def test_sign_xs_post_convenience(self):
        """测试POST请求便捷方法"""
        uri = "/api/sns/web/v1/login"
        a1_value = "test_a1_value"
        payload = {"username": "test", "password": "123456"}

        result = self.client.sign_xs_post(uri, a1_value, payload=payload)

        assert isinstance(result, str)
        assert result.startswith("XYS_")
        assert len(result) > 10


class TestIntegration:
    """集成测试"""

    def test_full_signature_generation_pipeline(self):
        """测试完整的签名生成流程"""
        client = Xhshow()

        # 测试数据
        method = "GET"
        uri = "/api/sns/web/v1/user_posted"
        a1_value = "test_a1_value"
        xsec_appid = "xhs-pc-web"
        payload = {
            "num": "30",
            "cursor": "",
            "user_id": "1234567890",
            "image_formats": ["jpg", "webp", "avif"],
        }

        signature = client.sign_xs(
            method=method,
            uri=uri,
            a1_value=a1_value,
            xsec_appid=xsec_appid,
            payload=payload,
        )

        # 验证签名格式
        assert isinstance(signature, str)
        assert signature.startswith("XYS_")
        assert len(signature) > 50

        # 验证可重现性
        signature2 = client.sign_xs(
            method=method,
            uri=uri,
            a1_value=a1_value,
            xsec_appid=xsec_appid,
            payload=payload,
        )

        # 格式一致但内容不同
        assert signature2.startswith("XYS_")
        assert len(signature2) == len(signature)

    def test_sign_xs_parameter_validation(self):
        """测试sign_xs参数验证"""
        client = Xhshow()

        # 正常参数
        valid_method = "GET"
        valid_uri = "/api/test"
        valid_a1 = "test_a1"

        # 测试method类型验证
        with pytest.raises(TypeError, match="method must be str"):
            client.sign_xs(123, valid_uri, valid_a1)  # type: ignore

        with pytest.raises(TypeError, match="method must be str"):
            client.sign_xs(None, valid_uri, valid_a1)  # type: ignore

        # 测试uri类型验证
        with pytest.raises(TypeError, match="uri must be str"):
            client.sign_xs(valid_method, 123, valid_a1)  # type: ignore

        # 测试a1_value类型验证
        with pytest.raises(TypeError, match="a1_value must be str"):
            client.sign_xs(valid_method, valid_uri, 123)  # type: ignore

        # 测试xsec_appid类型验证
        with pytest.raises(TypeError, match="xsec_appid must be str"):
            client.sign_xs(
                valid_method,
                valid_uri,
                valid_a1,
                xsec_appid=123,  # type: ignore
            )

        # 测试payload类型验证
        with pytest.raises(TypeError, match="payload must be dict or None"):
            client.sign_xs(
                valid_method,
                valid_uri,
                valid_a1,
                payload="invalid",  # type: ignore
            )

        with pytest.raises(TypeError, match="payload must be dict or None"):
            client.sign_xs(
                valid_method,
                valid_uri,
                valid_a1,
                payload=123,  # type: ignore
            )

        # 测试method值验证
        with pytest.raises(ValueError, match="method must be 'GET' or 'POST'"):
            client.sign_xs("PUT", valid_uri, valid_a1)  # type: ignore

        with pytest.raises(ValueError, match="method must be 'GET' or 'POST'"):
            client.sign_xs("DELETE", valid_uri, valid_a1)  # type: ignore

        # 测试空字符串验证
        with pytest.raises(ValueError, match="uri cannot be empty"):
            client.sign_xs(valid_method, "", valid_a1)

        with pytest.raises(ValueError, match="uri cannot be empty"):
            client.sign_xs(valid_method, "   ", valid_a1)

        with pytest.raises(ValueError, match="a1_value cannot be empty"):
            client.sign_xs(valid_method, valid_uri, "")

        with pytest.raises(ValueError, match="a1_value cannot be empty"):
            client.sign_xs(valid_method, valid_uri, "   ")

        with pytest.raises(ValueError, match="xsec_appid cannot be empty"):
            client.sign_xs(valid_method, valid_uri, valid_a1, xsec_appid="")

        # 测试payload键类型验证
        with pytest.raises(TypeError, match="payload keys must be str"):
            client.sign_xs(
                valid_method,
                valid_uri,
                valid_a1,
                payload={123: "value"},  # type: ignore
            )

        # 测试正常情况（验证参数会被正确处理）
        result = client.sign_xs("  get  ", "  /api/test  ", "  test_a1  ")  # type: ignore
        assert isinstance(result, str)
        assert result.startswith("XYS_")

    def test_timestamp_parameter_support(self):
        """测试时间戳参数支持"""
        import time

        client = Xhshow()
        uri = "/api/sns/web/v1/user_posted"
        a1_value = "test_a1_value"
        params = {"num": "30"}

        # Test with default timestamp
        sig1 = client.sign_xs_get(uri, a1_value, params=params)
        assert isinstance(sig1, str)
        assert sig1.startswith("XYS_")

        # Test with custom timestamp
        custom_ts = time.time()
        sig2 = client.sign_xs_get(uri, a1_value, params=params, timestamp=custom_ts)
        assert isinstance(sig2, str)
        assert sig2.startswith("XYS_")

        # Test POST with timestamp
        sig3 = client.sign_xs_post(
            uri="/api/sns/web/v1/login",
            a1_value=a1_value,
            payload={"user": "test"},
            timestamp=custom_ts,
        )
        assert isinstance(sig3, str)
        assert sig3.startswith("XYS_")

        # Test sign_xs with timestamp
        sig4 = client.sign_xs(method="GET", uri=uri, a1_value=a1_value, payload=params, timestamp=custom_ts)
        assert isinstance(sig4, str)
        assert sig4.startswith("XYS_")

    def test_trace_id_generation(self):
        """测试 Trace ID 生成"""
        import time

        client = Xhshow()

        # Test b3 trace id
        b3_id = client.get_b3_trace_id()
        assert isinstance(b3_id, str)
        assert len(b3_id) == 16
        assert all(c in "0123456789abcdef" for c in b3_id)

        # Test xray trace id with default timestamp
        xray_id1 = client.get_xray_trace_id()
        assert isinstance(xray_id1, str)
        assert len(xray_id1) == 32
        assert all(c in "0123456789abcdef" for c in xray_id1)

        # Test xray trace id with custom timestamp
        custom_ts = int(time.time() * 1000)
        xray_id2 = client.get_xray_trace_id(timestamp=custom_ts)
        assert isinstance(xray_id2, str)
        assert len(xray_id2) == 32

        # Test xray trace id with custom timestamp and seq
        xray_id3 = client.get_xray_trace_id(timestamp=custom_ts, seq=12345)
        assert isinstance(xray_id3, str)
        assert len(xray_id3) == 32

    def test_unified_timestamp_usage(self):
        """测试统一时间戳使用场景"""
        import time

        client = Xhshow()
        unified_ts = time.time()

        # Use same timestamp for signature and trace IDs
        signature = client.sign_xs_post(
            uri="/api/sns/web/v1/login",
            a1_value="test_a1",
            payload={"user": "test"},
            timestamp=unified_ts,
        )

        b3_id = client.get_b3_trace_id()
        xray_id = client.get_xray_trace_id(timestamp=int(unified_ts * 1000))

        assert isinstance(signature, str)
        assert signature.startswith("XYS_")
        assert isinstance(b3_id, str)
        assert len(b3_id) == 16
        assert isinstance(xray_id, str)
        assert len(xray_id) == 32

    def test_get_x_t(self):
        """测试 x-t header 生成"""
        import time

        client = Xhshow()

        # Test with default timestamp
        x_t1 = client.get_x_t()
        assert isinstance(x_t1, int)
        assert x_t1 > 0

        # Test with custom timestamp
        custom_ts = time.time()
        x_t2 = client.get_x_t(timestamp=custom_ts)
        assert isinstance(x_t2, int)
        assert x_t2 == int(custom_ts * 1000)

        # Test unified timestamp with all headers
        unified_ts = time.time()
        x_t = client.get_x_t(timestamp=unified_ts)
        signature = client.sign_xs_get(
            uri="/api/test", a1_value="test_a1", params={"key": "value"}, timestamp=unified_ts
        )
        b3_id = client.get_b3_trace_id()
        xray_id = client.get_xray_trace_id(timestamp=int(unified_ts * 1000))

        assert isinstance(x_t, int)
        assert x_t == int(unified_ts * 1000)
        assert isinstance(signature, str)
        assert isinstance(b3_id, str)
        assert isinstance(xray_id, str)

    def test_sign_headers(self):
        """测试统一 headers 生成"""
        import time

        client = Xhshow()

        # Test GET request headers with params
        cookies = {"a1": "test_a1_value", "web_session": "test_session"}
        headers = client.sign_headers(
            method="GET",
            uri="/api/sns/web/v1/user_posted",
            cookies=cookies,
            params={"num": "30", "cursor": "", "user_id": "123"},
        )

        assert isinstance(headers, dict)
        assert "x-s" in headers
        assert "x-s-common" in headers
        assert "x-t" in headers
        assert "x-b3-traceid" in headers
        assert "x-xray-traceid" in headers

        assert headers["x-s"].startswith("XYS_")
        assert headers["x-t"].isdigit()
        assert len(headers["x-b3-traceid"]) == 16
        assert len(headers["x-xray-traceid"]) == 32

        # Test POST request headers with payload
        headers_post = client.sign_headers(
            method="POST",
            uri="/api/sns/web/v1/login",
            cookies=cookies,
            payload={"username": "test", "password": "123456"},
        )

        assert isinstance(headers_post, dict)
        assert all(k in headers_post for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])

        # Test with custom timestamp
        custom_ts = time.time()
        headers_custom = client.sign_headers(
            method="GET",
            uri="/api/test",
            cookies=cookies,
            params={"key": "value"},
            timestamp=custom_ts,
        )

        assert isinstance(headers_custom, dict)
        assert headers_custom["x-t"] == str(int(custom_ts * 1000))

        # Test all values are strings
        assert all(isinstance(v, str) for v in headers.values())
        assert all(isinstance(v, str) for v in headers_post.values())
        assert all(isinstance(v, str) for v in headers_custom.values())

    def test_sign_headers_get(self):
        """测试 GET 请求 headers 便捷方法"""
        import time

        client = Xhshow()

        # Test basic usage
        cookies = {"a1": "test_a1_value", "web_session": "test_session"}
        headers = client.sign_headers_get(
            uri="/api/sns/web/v1/user_posted",
            cookies=cookies,
            params={"num": "30", "cursor": "", "user_id": "123"},
        )

        assert isinstance(headers, dict)
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])
        assert headers["x-s"].startswith("XYS_")
        assert all(isinstance(v, str) for v in headers.values())

        # Test with custom timestamp
        custom_ts = time.time()
        headers_ts = client.sign_headers_get(
            uri="/api/test", cookies=cookies, params={"key": "value"}, timestamp=custom_ts
        )

        assert headers_ts["x-t"] == str(int(custom_ts * 1000))

    def test_sign_headers_post(self):
        """测试 POST 请求 headers 便捷方法"""
        import time

        client = Xhshow()

        # Test basic usage
        cookies = {"a1": "test_a1_value", "web_session": "test_session"}
        headers = client.sign_headers_post(
            uri="/api/sns/web/v1/login",
            cookies=cookies,
            payload={"username": "test", "password": "123456"},
        )

        assert isinstance(headers, dict)
        assert all(k in headers for k in ["x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"])
        assert headers["x-s"].startswith("XYS_")
        assert all(isinstance(v, str) for v in headers.values())

        # Test with custom timestamp
        custom_ts = time.time()
        headers_ts = client.sign_headers_post(
            uri="/api/test", cookies=cookies, payload={"key": "value"}, timestamp=custom_ts
        )

        assert headers_ts["x-t"] == str(int(custom_ts * 1000))

    def test_sign_headers_parameter_validation(self):
        """测试 sign_headers 参数验证"""
        client = Xhshow()

        cookies = {"a1": "test_a1", "web_session": "test_session"}

        # Test GET request with payload should raise error
        with pytest.raises(ValueError, match="GET requests must use 'params', not 'payload'"):
            client.sign_headers(
                method="GET",
                uri="/api/test",
                cookies=cookies,
                payload={"key": "value"},
            )

        # Test POST request with params should raise error
        with pytest.raises(ValueError, match="POST requests must use 'payload', not 'params'"):
            client.sign_headers(
                method="POST",
                uri="/api/test",
                cookies=cookies,
                params={"key": "value"},
            )

        # Test unsupported method should raise error
        with pytest.raises(ValueError, match="Unsupported method"):
            client.sign_headers(
                method="PUT",  # type: ignore[arg-type]
                uri="/api/test",
                cookies=cookies,
                params={"key": "value"},
            )


class TestCRC32:
    """测试 CRC32 加密功能"""

    def test_crc32_js_int_basic(self):
        """测试基本的 CRC32 计算"""
        test_string = (
            "I38rHdgsjopgIvesdVwgIC+oIELmBZ5e3VwXLgFTIxS3bqwErFeexd0ekncAzMFYnqthIhJeSBMDKutRI3KsYorWHPtGrbV0P9W"
        )
        result = CRC32.crc32_js_int(test_string)

        assert isinstance(result, int)
        assert result == 679790455

    def test_crc32_signed_unsigned(self):
        """测试有符号和无符号结果"""
        test_data = "test_data"

        signed_result = CRC32.crc32_js_int(test_data, signed=True)
        unsigned_result = CRC32.crc32_js_int(test_data, signed=False)

        assert isinstance(signed_result, int)
        assert isinstance(unsigned_result, int)
        assert -2147483648 <= signed_result <= 2147483647
        assert 0 <= unsigned_result <= 0xFFFFFFFF

    def test_crc32_string_modes(self):
        """测试不同的字符串模式"""
        test_string = "测试中文"

        js_result = CRC32.crc32_js_int(test_string, string_mode="js")
        utf8_result = CRC32.crc32_js_int(test_string, string_mode="utf8")

        assert isinstance(js_result, int)
        assert isinstance(utf8_result, int)
        # JS mode 和 UTF8 mode 对中文的处理应该不同
        assert js_result != utf8_result

    def test_crc32_bytes_input(self):
        """测试字节输入"""
        test_bytes = b"test_bytes"
        result = CRC32.crc32_js_int(test_bytes)

        assert isinstance(result, int)

    def test_crc32_iterable_input(self):
        """测试可迭代输入"""
        test_list = [72, 101, 108, 108, 111]  # "Hello"
        result = CRC32.crc32_js_int(test_list)

        assert isinstance(result, int)
