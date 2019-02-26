from .enums import U2FTransports
from .utils import abstract_attribute, websafe_encode

from . import _typing as typ  # isort:skip


class DeviceRegistration:

    version = abstract_attribute()  # type: str
    app_id = abstract_attribute()  # type: str
    key_handle = abstract_attribute()  # type: bytes
    public_key = abstract_attribute()  # type: bytes
    counter = abstract_attribute()  # type: int
    u2f_transports = abstract_attribute()  # type: U2FTransports


def device_as_client_dict(device: DeviceRegistration) -> typ.Dict[str, typ.Any]:
    transports = device.u2f_transports
    out_transports = (
        None if transports is None else sorted([t.internal_name for t in transports])
    )
    return {
        "version": device.version,
        "appId": device.app_id,
        # keyHandle must be base64 encoded
        "keyHandle": websafe_encode(device.key_handle),
        "transports": out_transports,
    }


def filter_devices_by_app_id(
    registered_devices: typ.Iterable[DeviceRegistration], app_id: str
) -> typ.Iterator[DeviceRegistration]:
    return (device for device in registered_devices if device.app_id == app_id)
