from enum import Enum, unique

from . import _typing as typ


@unique
class U2FTransport(Enum):
    BLUETOOTH_RADIO = (0x80, 'br')
    BLUETOOTH_LOW_ENERGY_RADIO = (0x40, 'ble')
    USB = (0x20, 'usb')
    NFC = (0x10, 'nfc')
    USB_INTERNAL = (0x08, 'usb-internal')

    # def __init__(self, value: int, internal_name: str) -> None:
    #     self.value = value
    #     self.internal_name = internal_name

    @property
    def value(self):
        return super().value[0]

    @property
    def internal_name(self):
        return super().value[1]

    @staticmethod
    def from_byte(byte: int) -> typ.Collection['U2FTransport']:
        return [t for t in U2FTransport if t.value & byte]

    @staticmethod
    def to_byte(transports: typ.Collection['U2FTransport']) -> int:
        value = 0
        for transport in transports:
            value |= transport.value
        return value

    @staticmethod
    def _to_internal_int(
        transports: typ.Optional[typ.Collection['U2FTransport']],
    ) -> int:
        if transports is None:
            return -1
        else:
            return U2FTransport.to_byte(transports)

    @staticmethod
    def _from_internal_int(
        transports: int,
    ) ->typ.Optional[typ.Collection['U2FTransport']]:
        if transports < 0:
            return None
        else:
            return U2FTransport.from_byte(transports)


U2FTransports = typ.Optional[typ.Collection[U2FTransport]]


@unique
class RequestType(Enum):
    REGISTER = 'navigator.id.finishEnrollment'
    SIGN = 'navigator.id.getAssertion'
