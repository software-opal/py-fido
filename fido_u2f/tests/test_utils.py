from .. import utils


def test_sha_256():
    assert utils.sha_256(
        b'') == (b'\xe3\xb0\xc4\x42\x98\xfc\x1c\x14'
                 b'\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24'
                 b'\x27\xae\x41\xe4\x64\x9b\x93\x4c'
                 b'\xa4\x95\x99\x1b\x78\x52\xb8\x55')
    assert utils.sha_256(
        b'fido') == (b'\x04\xb1\xff\x4c\x19\x33\x58\xf9'
                     b'\x24\xef\xfd\xb5\x4e\xb6\xd2\x37'
                     b'\xfb\x49\x55\xe9\xd1\x43\xd9\x82'
                     b'\xf1\xf8\x63\x20\x3f\x18\x3f\x63')


def test_pop_bytes():
    arr = bytearray(b'0123456789')
    assert utils.pop_bytes(arr, 1) == b'0'
    assert arr == b'123456789'


class Test_parse_tlv_encoded_length():

    def test_zero_length(self):
        arr = bytearray(b'f\x00')
        assert utils.parse_tlv_encoded_length(arr) == 2

    def test_zero_length_with_flag(self):
        arr = bytearray(b'f\x80')
        assert utils.parse_tlv_encoded_length(arr) == 2

    def test_length_short_form(self):
        arr = bytearray(b'f\x05')
        assert utils.parse_tlv_encoded_length(arr) == (2 + 5)

    def test_length_long_form(self):
        # 0x80 => Long form
        # 0x01 => length of bytes representing message length
        arr = bytearray(b'f\x81\x05')
        assert utils.parse_tlv_encoded_length(arr) == (2 + 1 + 5)
    def test_length_really_long_form(self):
        # 0x80 => Long form
        # 0x7f => length of bytes representing message length
        arr = bytearray(b'f\xff' + (b'\0' * 0x7e) + b'\x05')
        assert utils.parse_tlv_encoded_length(arr) == (2 + 0x7f + 5)
