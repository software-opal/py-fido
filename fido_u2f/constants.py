
from cryptography import x509

U2F_V2 = 'U2F_V2'
U2F_TRANSPORT_EXTENSION_OID = x509.ObjectIdentifier('1.3.6.1.4.1.45724.2.1.1')


PUB_KEY_DER_PREFIX = bytes.fromhex(
    '3059301306072a8648ce3d020106082a8648ce3d030107034200')


INVALID_YUBICO_CERT_SHASUMS = [
    bytes.fromhex(
        '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8'),
    bytes.fromhex(
        'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f'),
    bytes.fromhex(
        '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae'),
    bytes.fromhex(
        'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb'),
    bytes.fromhex(
        '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897'),
    bytes.fromhex(
        'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511'),
]
