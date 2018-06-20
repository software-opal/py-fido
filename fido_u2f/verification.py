import abc
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import _typing as typ
from .constants import PUB_KEY_DER_PREFIX
from .device import DeviceRegistration
from .enums import RequestType
from .exceptions import U2FInvalidDataException, U2FStateException
from .utils import get_random_challenge, pop_bytes, sha_256
from .utils import validate_client_data, websafe_decode, websafe_encode


class U2FSigningManager(abc.ABC):
    """
    An abstract class that handles verifying a user's U2F token.

    Implementers must override ``update_device_registration_counter`` to
    perform any neccessary operations for storing the last seen device counter
    in a persistant storage.

    This class has 2 externally useable API methods
    ``create_signing_challenge`` and ``process_signing_response`` which
    should be used to provide the U2F verification/signing flow for a user.
    """

    SIGNING_SESSION_KEY = 'u2f_signing_challenge'

    def __init__(self, app_id: str) -> None:
        """
        Create a signing manager.


        """
        self.app_id = app_id

    @abc.abstractmethod
    def update_device_registration_counter(
            self,
            device: DeviceRegistration,
            counter: int,
    ) -> DeviceRegistration:
        ...

    def filter_devices_by_app_id(
            self,
            registered_devices: typ.Collection[DeviceRegistration],
    ) -> typ.Collection[DeviceRegistration]:
        return [
            device for device in registered_devices
            if device.app_id == self.app_id
        ]

    def create_signing_challenge(
            self,
            session: typ.MutableMapping[str, typ.Any],
            registered_devices: typ.Collection[DeviceRegistration],
    ) -> typ.Mapping[str, typ.Any]:
        registered_devices = self.filter_devices_by_app_id(registered_devices)
        if not registered_devices:
            raise ValueError('Cannot issue a signing request with no keys.')
        challenge = websafe_encode(get_random_challenge())
        session[self.SIGNING_SESSION_KEY] = challenge
        return {
            'appId':
            self.app_id,
            'challenge':
            challenge,
            'registeredKeys':
            [key.device_as_client_dict() for key in registered_devices],
        }

    def process_signing_response(
            self,
            session: typ.MutableMapping[str, typ.Any],
            response_dict: typ.Mapping[str, str],
            registered_devices: typ.Collection[DeviceRegistration] = (),
    ) -> DeviceRegistration:
        registered_devices = self.filter_devices_by_app_id(registered_devices)
        key_handle = response_dict.get('keyHandle', '')
        challenge = session.get(self.SIGNING_SESSION_KEY, '')
        if not challenge:
            raise U2FStateException('Session missing required key.')
        device = self.get_key_by_handle(registered_devices, key_handle)
        signature_data = self.verify_signature_data(response_dict, challenge,
                                                    device)
        counter = signature_data.counter
        return self.update_device_registration_counter(device, counter)

    def get_key_by_handle(
            self,
            registered_keys: typ.Collection[DeviceRegistration],
            key_handle: str,
    ) -> DeviceRegistration:
        for key in registered_keys:
            if key.key_handle == key_handle:
                return key
        raise U2FInvalidDataException('Given key not found')

    def verify_signature_data(
            self,
            response_dict: typ.Mapping[str, str],
            challenge: str,
            device: DeviceRegistration,
    ) -> 'SignatureData':
        try:
            signature_data = SignatureData.from_base64(
                response_dict.get('signatureData', ''))
        except (ValueError, IndexError) as e:
            raise U2FInvalidDataException('Invalid signing data.') from e
        # Client data comes in as base64(usually?), so we standardise it
        #  into a decoded *string*. We then take the hash of that string
        #  for the verification step.
        client_data = validate_client_data(
            response_dict.get('clientData', ''),
            RequestType.REGISTER,
            self.app_id,
            challenge,
        )
        challenge_param = sha_256(client_data)
        app_param = sha_256(self.app_id.encode('idna'))
        signature_data.verify(
            app_param,
            challenge_param,
            websafe_decode(device.public_key),
        )
        return signature_data


class SignatureData():
    @classmethod
    def from_base64(
            cls,
            base64_data: typ.Union[str, bytes],
    ) -> 'SignatureData':
        return cls(websafe_decode(base64_data))  # type: ignore

    def __init__(self, data: bytes) -> None:
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf
        buf = bytearray(data)
        self.user_presence = buf.pop(0)
        self.counter = struct.unpack('>I', pop_bytes(buf, 4))[0]
        self.signature = bytes(buf)

    def verify(self, app_param: bytes, chal_param: bytes, der_pubkey: bytes):
        pubkey = load_der_public_key(PUB_KEY_DER_PREFIX + der_pubkey,
                                     default_backend())
        verifier = pubkey.verifier(self.signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(
            app_param + bytes([self.user_presence]) + struct.pack(
                '>I', self.counter) + chal_param, )
        try:
            verifier.verify()
        except InvalidSignature as e:
            raise U2FInvalidDataException(
                'Attestation signature is invalid') from e
