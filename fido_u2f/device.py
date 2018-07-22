from . import _typing as typ
from .utils import abstract_attribute, websafe_encode


class DeviceRegistration():

    version = abstract_attribute()  # type: str
    app_id = abstract_attribute()  # type: str
    key_handle = abstract_attribute()  # type: bytes
    public_key = abstract_attribute()  # type: bytes
    counter = abstract_attribute()  # type: int

    # U2FTransports
    u2f_transports = abstract_attribute()

    def device_as_client_dict(self) -> typ.Dict[str, typ.Any]:
        transports = self.u2f_transports
        if transports is not None:
            out_transports = sorted([
                t.internal_name for t in transports
            ])  # type: typ.Optional[typ.Collection[str]]
        else:
            out_transports = None
        return {
            'version': self.version,
            'appId': self.app_id,
            # keyHandle must be base64 encoded
            'keyHandle': websafe_encode(self.key_handle),
            'transports': out_transports,
        }
