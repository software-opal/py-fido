from . import _typing as typ
from .utils import websafe_encode


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
            # we did not find a match, should be rare, but prepare for it
            raise NotImplementedError(
                '%r does not set the abstract attribute <unknown>' % this_obj)


def abstract_attribute() -> typ.Any:
    """
    An attribute that throws an error if it is not provided in a subclass.
    """
    # This function keeps MyPy happy
    return _AbstractAttribute()


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
                t.internal_name
                for t in transports
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
