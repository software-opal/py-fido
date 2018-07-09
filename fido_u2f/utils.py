from base64 import urlsafe_b64decode, urlsafe_b64encode
import json
import os
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from . import _typing as typ
from .constants import INVALID_YUBICO_CERT_SHASUMS
from .enums import RequestType
from .exceptions import U2FInvalidDataException

BASE64URL = re.compile(br'^[-_a-zA-Z0-9]*=*$')


def get_random_challenge() -> bytes:
    return os.urandom(64)


def standardise_client_data(raw_client_data: str) -> str:
    try:
        if '{' not in raw_client_data:
            # Assume base64 encoded JSON.
            return websafe_decode(raw_client_data).decode('ascii')
        else:
            # Assume JSON string.
            return raw_client_data
    except ValueError:
        raise U2FInvalidDataException('Client data was an invalid string')


def load_client_data(raw_client_data: str) -> typ.Mapping[str, typ.Any]:
    if isinstance(raw_client_data, str):
        try:
            return json.loads(standardise_client_data(raw_client_data))
        except ValueError:
            raise U2FInvalidDataException('Client data was an invalid string')
    else:
        raise U2FInvalidDataException(
            'Client data is an unsupported type{!r}.'.format(
                type(raw_client_data)))


def validate_client_data(
        raw_client_data: str,
        request_type: RequestType,
        app_id: str,
        expected_challenge: str,
) -> str:
    standardised_client_data = standardise_client_data(raw_client_data)
    client_data = load_client_data(standardised_client_data)
    if client_data.get('typ', None) != request_type.value:
        raise U2FInvalidDataException('Invalid or missing request type')
    if client_data.get('origin', None) != app_id:
        raise U2FInvalidDataException('Invalid or missing origin')
    if client_data.get('challenge', None) != expected_challenge:
        raise U2FInvalidDataException('Invalid or missing challenge')
    # Valid client data falls through.
    return standardised_client_data


def sha_256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()


def pop_bytes(data: bytearray, l: int) -> bytes:
    x = bytes(data[:l])
    del data[:l]
    return x


def fix_invalid_yubico_certs(der: bytes):
    # Some early certs have UNUSED BITS incorrectly set.
    # Fix only if they are one of the known bad
    if sha_256(der) in INVALID_YUBICO_CERT_SHASUMS:
        der = der[:-257] + b'\0' + der[-256:]
    return der


def parse_tlv_encoded_length(data: bytearray) -> int:
    # https://msdn.microsoft.com/en-us/library/windows/desktop/bb648641(v=vs.85).aspx
    # Starting at 1 because byte 0 is the 'tag'
    length = data[1] & 0x7f
    extended_length_flag = data[1] & 0x80
    if extended_length_flag:
        # The 7 low-bits of `length` indicate the number of bytes to read to
        #  determine the length
        true_length = 0
        # Offset at 2 because we started at 1; and we've already read the
        #  first byte.
        for byte in data[2:(2 + length)]:
            true_length = (true_length << 8) | byte
        # Return the length; plus the bytes we've already read.
        return 2 + length + true_length
    else:
        # High bit is unset; meaning the value in the lower 7 bits must be the
        #  length of the certicate.
        # Return that plus the 2 bytes we've already read.
        return 2 + length


def websafe_decode(data: typ.Union[bytes]) -> bytes:
    """Convert the URL Safe Base64 string into the bytes it represents."""
    if isinstance(data, str):
        data = data.encode('ascii')
    if not BASE64URL.match(data):
        raise ValueError('Invalid character(s)')
    data += b'=' * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data: typ.Union[bytes]) -> bytes:
    """Convert the given data into it's URL Safe Base64 representation."""
    if isinstance(data, str):
        data = data.encode('ascii')
    return urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class _AbstractAttribute():
    def __get__(self, obj, type):
        this_obj = obj if obj else type
        abc_class = None
        attr_name = None
        # Find ourselves in the MRO
        for cls in type.__mro__:
            for name, value in cls.__dict__.items():
                if value is self:
                    abc_class = cls
                    attr_name = name
        if abc_class is not None and attr_name is not None:
            raise NotImplementedError(
                '%r does not have the attribute %r (abstract from class %r)' %
                (this_obj, name, cls.__name__))
        else:
            raise NotImplementedError(
                '%r does not set the abstract attribute <unknown>' % this_obj)


def abstract_attribute() -> typ.Any:
    """
    An attribute that throws an error if it is not provided in a subclass.
    """
    # This function keeps MyPy happy
    return _AbstractAttribute()
