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


def device_as_client_dict(device: DeviceRegistration) -> typ.Dict[str, typ.Any]:
    transports = device.u2f_transports
    if transports is not None:
        out_transports = sorted([
            t.internal_name for t in transports
        ])  # type: typ.Optional[typ.Collection[str]]
    else:
        out_transports = None
    return {
        'version': device.version,
        'appId': device.app_id,
        # keyHandle must be base64 encoded
        'keyHandle': websafe_encode(device.key_handle),
        'transports': out_transports,
    }


def filter_devices_by_app_id(
    registered_devices: typ.Collection[DeviceRegistration],
    app_id: str,
) -> typ.Iterable[DeviceRegistration]:
    return (
        device for device in registered_devices
        if device.app_id == app_id
    )
