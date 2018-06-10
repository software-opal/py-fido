# import typing as typ
#
# from .enums import U2FTransport
# from .utils import websafe_encode, websafe_decode
#
#
# class DeviceRegistration():
#
#     """The U2F protocol version to use."""
#     version: str
#     """The appId used during registration."""
#     app_id: str
#     """The base64 encoded `keyHandle`."""
#     encoded_key_handle: str
#     """The base64 encoded `pubKey`."""
#     encoded_public_key: str
#     """An integer-encoded `U2FTransport`. Use `u2f_transports` instead."""
#     transports: int
#     """A 32-bit unsigned integer representing the last seen counter."""
#     counter: int
#
#     @property
#     def u2f_transports(self) -> typ.Optional[typ.Collection[U2FTransport]]:
#         if self._transports < 0:
#             return None
#         return U2FTransport._from_internal_int(self._transports)
#
#     @u2f_transports.setter
#     def u2f_transports(
#         self,
#         transports: typ.Optional[typ.Collection[U2FTransport]],
#     ):
#         self._transports = U2FTransport._to_internal_int(transports)
#
#     @property
#     def key_handle(self) -> bytes:
#         return websafe_decode(self.encoded_key_handle)
#
#     @property
#     def public_key(self) -> bytes:
#         return websafe_decode(self.encoded_public_key)
