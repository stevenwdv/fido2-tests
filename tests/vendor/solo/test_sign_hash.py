import hashlib
import sys
import typing

import pytest
import fido2.cose as cose
from fido2.ctap2 import CtapError, AttestationObject, AttestedCredentialData
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialParameters, PublicKeyCredentialType, \
    PublicKeyCredentialDescriptor

from tests.conftest import TestDevice

try:
    from solo.client import SoloClient
except:
    from solo.devices.solo_v1 import Client as SoloClient

from tests.utils import FidoRequest


@pytest.fixture(scope="module", params=["u2f"])
def solo(request, device):
    sc = SoloClient()
    sc.find_device(device.dev)
    if request.param == "u2f":
        sc.use_u2f()
    else:
        sc.use_hid()
    return sc


IS_EXPERIMENTAL = "--experimental" in sys.argv


@pytest.mark.skipif(not IS_EXPERIMENTAL, reason="sign-hash is experimental")
class TestSignHash(object):
    def test_es256(self, solo, device):
        _test_sign_hash_impl(solo, device, cose.ES256.ALGORITHM, "sha256", False, None)

    def test_es256_comment(self, solo, device):
        with pytest.raises(CtapError) as e:
            _test_sign_hash_impl(solo, device, cose.ES256.ALGORITHM, "sha256", False, b"")
        assert e.value.code == CtapError.ERR.INVALID_OPTION

    def test_eddsa(self, solo, device):
        _test_sign_hash_impl(solo, device, cose.EdDSA.ALGORITHM, "blake2b", True, None)

    def test_eddsa_comment(self, solo, device):
        _test_sign_hash_impl(solo, device, cose.EdDSA.ALGORITHM, "blake2b", True, b"A" * 128)

    def test_eddsa_empty_comment(self, solo, device):
        _test_sign_hash_impl(solo, device, cose.EdDSA.ALGORITHM, "blake2b", True, b"")

    def test_eddsa_too_large_comment(self, solo, device):
        with pytest.raises(CtapError) as e:
            _test_sign_hash_impl(solo, device, cose.EdDSA.ALGORITHM, "blake2b", True, b"A" * 129)
        assert e.value.code == CtapError.ERR.LIMIT_EXCEEDED

    def test_invalid_credential(self, solo: SoloClient):
        with pytest.raises(CtapError) as e:
            solo.sign_hash(b"A" * 70, b"A" * 32, None, "solo-sign-hash:")
        assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL

    def test_custom_rp_id(self, solo, device):
        _test_sign_hash_impl(solo, device, cose.ES256.ALGORITHM, "sha256", False, None, "solo-sign-hash:abcd")

    def test_incorrect_rp_id(self, solo, device):
        incorrect_ids = [
            "example.com"
            "solo:"
            "solo-sign-hash"
            "solo-sign-hash.com"
            ":solo-sign-hash"
            "example.com:"
            ""
        ]

        for rp_id in incorrect_ids:
            with pytest.raises(CtapError) as e:
                _test_sign_hash_impl(solo, device, cose.ES256.ALGORITHM, "sha256", False, None, rp_id)
            assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL

    def test_sign_hash_rp_id_with_get_assertion(self, device: TestDevice):
        for rp_id in ["solo-sign-hash:", "solo-sign-hash:abcd"]:
            mc_req = FidoRequest(rp=PublicKeyCredentialRpEntity(rp_id, "Solo hash signing"))
            reg: AttestationObject = device.sendMC(*mc_req.toMC())
            credential: AttestedCredentialData = reg.auth_data.credential_data

            ga_req = FidoRequest(mc_req, allow_list=[
                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credential.credential_id)])
            with pytest.raises(CtapError) as e:
                device.sendGA(*ga_req.toGA())
            assert e.value.code == CtapError.ERR.INVALID_CREDENTIAL


def _test_sign_hash_impl(
        solo: SoloClient,
        device: TestDevice,
        alg: int,
        hash_alg: str,
        explicit_prehash: bool,
        trusted_comment: typing.Union[bytes, None] = None,
        rp_id: str = "solo-sign-hash:"
):
    req = FidoRequest(
        rp=PublicKeyCredentialRpEntity(rp_id, "Solo hash signing"),
        key_params=[PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)])

    reg: AttestationObject = device.sendMC(*req.toMC())
    credential: AttestedCredentialData = reg.auth_data.credential_data

    message = b"ABCD"
    digest = hashlib.new(hash_alg, message).digest()
    signatures = solo.sign_hash(credential.credential_id, digest, None, rp_id, trusted_comment)

    credential.public_key.verify(digest if explicit_prehash else message, signatures[1])
    if trusted_comment is not None:
        credential.public_key.verify(signatures[1] + trusted_comment, signatures[2])
