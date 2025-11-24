import pytest

from xhshow import CryptoProcessor, Xhshow


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
