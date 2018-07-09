import abc

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import _typing as typ
from .constants import U2F_TRANSPORT_EXTENSION_OID, U2F_V2
from .device import DeviceRegistration
from .enums import RequestType, U2FTransport, U2FTransports
from .exceptions import U2FInvalidDataException, U2FStateException
from .utils import fix_invalid_yubico_certs, get_random_challenge, sha_256
from .utils import parse_tlv_encoded_length, pop_bytes, validate_client_data
from .utils import websafe_decode, websafe_encode


class U2FRegistrationManager(abc.ABC):

    REGISTRATION_SESSION_KEY = 'u2f_registration_challenge'

    def __init__(self, app_id: str) -> None:
        self.app_id = app_id

    @abc.abstractmethod
    def create_device_registration_model(
        self,
        version: str,
        app_id: str,
        key_handle: bytes,
        public_key: bytes,
        transports: U2FTransports,
    ) -> DeviceRegistration:
        ...

    def create_registration_challenge(
        self,
        session: typ.MutableMapping[str, typ.Any],
        registered_devices: typ.Collection[DeviceRegistration] = (),
    ) -> typ.Mapping[str, typ.Any]:
        """
        Generate a challenge and return information for the registration step.

        This will generate a secure random challenge, placing it in the session 
        object, and then return a JSON-safe object for use by the client to
        complete the challenge
        """
        challenge = websafe_encode(get_random_challenge())
        session[self.REGISTRATION_SESSION_KEY] = challenge
        return {
            'appId': self.app_id,
            'registerRequests': [{
                'version': U2F_V2,
                'challenge': challenge,
            }],
            'registeredKeys': [
                key.device_as_client_dict()
                for key in registered_devices
            ],
        }

    def process_registration_response(
        self,
        session: typ.MutableMapping[str, typ.Any],
        response_dict: typ.Mapping[str, str],
    ) -> DeviceRegistration:
        version = response_dict.get('version', '')
        challenge = session.pop(self.REGISTRATION_SESSION_KEY, None)
        if not challenge:
            raise U2FStateException('Session missing required key.')
        if version != U2F_V2:
            raise U2FInvalidDataException('Unsupported version given.')
        registration_data = self.verify_registration_data(
            response_dict, challenge)
        # We have now verified the registration request.
        return self.create_device_registration_model(
            version=version,
            app_id=self.app_id,
            key_handle=registration_data.key_handle,
            public_key=registration_data.public_key,
            transports=registration_data.get_supported_transports(),
        )

    def verify_registration_data(
        self,
        response_dict: typ.Mapping[str, str],
        challenge: str,
    ) -> 'RegistrationData':
        try:
            registration_data = RegistrationData.from_base64(
                response_dict.get('responseData', ''))
        except (ValueError, IndexError) as e:
            raise U2FInvalidDataException('Invalid registration data.') from e
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
        registration_data.verify(app_param, challenge_param)
        return registration_data


class RegistrationData():

    @classmethod
    def from_base64(
        cls,
        base64_data: typ.Union[str, bytes],
    ) -> 'RegistrationData':
        return cls(websafe_decode(base64_data))  # type: ignore

    def __init__(self, data: bytes) -> None:
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf
        buf = bytearray(data)
        if buf.pop(0) != 0x05:
            raise U2FInvalidDataException(
                'Registration data has invalid magic byte')
        self.public_key = pop_bytes(buf, 65)
        self.key_handle = pop_bytes(buf, buf.pop(0))
        cert_len = parse_tlv_encoded_length(buf)
        self.certificate = fix_invalid_yubico_certs(pop_bytes(buf, cert_len))
        self.signature = bytes(buf)

    def get_x509_certificate(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(
            self.certificate, default_backend())

    def verify(self, app_param: bytes, chal_param: bytes) -> None:
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf
        cert = self.get_x509_certificate()
        pubkey = cert.public_key()
        verifier = pubkey.verifier(self.signature, ec.ECDSA(hashes.SHA256()))

        verifier.update(
            b'\0'  # control byte
            + app_param
            + chal_param
            + self.key_handle
            + self.public_key,
        )
        try:
            verifier.verify()
        except InvalidSignature as e:
            raise U2FInvalidDataException(
                'Attestation signature is invalid') from e

    def get_supported_transports(
        self,
    ) -> U2FTransports:
        """Extract the transports this token supports from the certificate."""
        cert = self.get_x509_certificate()
        try:
            ext = cert.extensions.get_extension_for_oid(
                U2F_TRANSPORT_EXTENSION_OID)  # type: x509.Extension
        except x509.ExtensionNotFound:
            # Supported transports unknown. Spec indicates this must be `null`
            return None
        # Access the raw bytes in the extension field.
        transports_bitstring = ext.value.value
        # `transports_bitstring` is 4 bytes:
        assert transports_bitstring[0] == 0x03
        assert transports_bitstring[1] == 0x02
        unused_bits = transports_bitstring[2]
        transport_flags = transports_bitstring[3]
        # The last `unused_bits` should be unset. Make sure that they are
        transport_flags = (transport_flags >> unused_bits) << unused_bits
        return U2FTransport.from_byte(transport_flags)
