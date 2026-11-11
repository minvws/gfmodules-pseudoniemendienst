import base64
import hashlib
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from jwcrypto import jwk, jws

from app.services.hsm.client import HsmClient, HsmKeyNotFound
from app.services.jwt_signer import HsmJwtSigner
from tests.conftest import generate_rsa_keypair


def _b64url(data: bytes) -> str:
    """Helper to create base64url-encoded strings."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_hsm_signer_signs_ps256(hsm_client: HsmClient) -> None:
    """Test that HsmJwtSigner produces valid PS256 signatures."""
    # Create a test key
    private_key_pem, public_key_pem = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )

    # Pre-compute the signing input and signature
    header = b'{"alg":"PS256"}'
    payload_data = b'{"sub":"x"}'
    signing_input_str = _b64url(header) + "." + _b64url(payload_data)
    signing_input_bytes = signing_input_str.encode("ascii")

    # Compute digest (this is what HsmJwtSigner will do)
    digest = hashlib.sha256(signing_input_bytes).digest()

    # Sign the digest (using Prehashed to match HSM behavior)
    signature = private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        Prehashed(hashes.SHA256()),
    )

    with patch.object(hsm_client, "post") as mock_post:
        # Use side_effect with a list: first call returns public key, second returns signature
        mock_post.side_effect = [
            # First call: public_key_pem("prs-jwt-1")
            {"objects": [{"CLASS": "PUBLIC_KEY", "publickey": public_key_pem}]},
            # Second call: sign_rsa_pss_sha256("prs-jwt-1", digest)
            {"result": base64.b64encode(signature).decode("ascii")},
        ]

        # Create signer - this will make the first call (public_key_pem)
        signer = HsmJwtSigner(hsm_client, "prs-jwt-1")

        # Sign - this will make the second call (sign_rsa_pss_sha256)
        actual_signature = signer.sign(signing_input_bytes)

        # Build token
        token = signing_input_str + "." + _b64url(actual_signature)

        # Verify
        verifier = jws.JWS()
        verifier.deserialize(token)
        verifier.verify(jwk.JWK(**signer.public_jwk()), alg="PS256")
        assert verifier.payload == payload_data


def test_hsm_signer_sends_only_the_digest(hsm_client: HsmClient) -> None:
    """Test that HsmJwtSigner sends only the digest to HSM, not the full data."""
    # Create a test key for the public key response
    _, public_key_pem = generate_rsa_keypair()

    with patch.object(hsm_client, "post") as mock_post:
        # Use side_effect with a list of responses
        mock_post.side_effect = [
            # First call: public_key_pem("prs-jwt-1")
            {"objects": [{"CLASS": "PUBLIC_KEY", "publickey": public_key_pem}]},
            # Second call: sign_rsa_pss_sha256 - we don't care about the response for this test
            {"result": base64.b64encode(b"fake_signature").decode("ascii")},
        ]

        # Create signer
        signer = HsmJwtSigner(hsm_client, "prs-jwt-1")

        # Sign some data
        test_data = b"header.payload"
        signer.sign(test_data)

        # Verify the sign call was made with the digest
        assert mock_post.call_count == 2
        sign_call = mock_post.call_args_list[1]  # Second call is sign
        sign_path = sign_call[0][0]  # First positional arg is path
        sign_payload = sign_call[0][1]  # Second positional arg is payload

        assert sign_path == "/sign"
        assert (
            base64.b64decode(sign_payload["data"]) == hashlib.sha256(test_data).digest()
        )


def test_hsm_signer_missing_label(hsm_client: HsmClient) -> None:
    """Test that HsmJwtSigner raises HsmKeyNotFound when key doesn't exist."""
    with patch.object(hsm_client, "post") as mock_post:
        # Mock public_key_pem to return empty objects (key not found)
        mock_post.return_value = {"objects": []}

        # Should raise HsmKeyNotFound
        with pytest.raises(HsmKeyNotFound):
            HsmJwtSigner(hsm_client, "prs-jwt-missing")


def test_hsm_signer_rejects_short_key(hsm_client: HsmClient) -> None:
    """Test that HsmJwtSigner rejects keys shorter than 3072 bits."""
    # Create a short key (2048 bits)
    short_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = (
        short_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )

    with patch.object(hsm_client, "post") as mock_post:
        # Mock public_key_pem to return the short key
        mock_post.return_value = {
            "objects": [{"CLASS": "PUBLIC_KEY", "publickey": public_key_pem}]
        }

        # Should raise ValueError for short key
        with pytest.raises(ValueError, match="at least 3072 bits"):
            HsmJwtSigner(hsm_client, "short")
