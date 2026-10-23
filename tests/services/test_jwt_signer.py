import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from jwcrypto import jwk, jws

from app.config import ConfigJwtSigning
from app.services.hsm.client import HsmKeyNotFound
from app.services.jwt_signer import HsmJwtSigner, JwtSigningService, LocalJwtSigner
from tests.conftest import JWT_ISSUER, generate_rsa_keypair


def test_local_jwt_signer_should_create_with_valid_key() -> None:
    """Happy flow: Verify LocalJwtSigner created with valid key has correct properties."""
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    signer = LocalJwtSigner(private_key, "test-key")

    assert signer.alg == "PS256"
    assert signer.kid is not None
    assert len(signer.kid) > 0


def test_local_jwt_signer_should_sign_successfully() -> None:
    """Happy flow: Sign data and verify signature."""
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    signer = LocalJwtSigner(private_key, "test-key")

    signing_input: bytes = b"header.payload"

    # Sign
    signature = signer.sign(signing_input)

    # Verify using the public key
    public_key = private_key.public_key()
    public_key.verify(
        signature,
        signing_input,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )


def test_local_jwt_signer_should_have_correct_kid() -> None:
    """Happy flow: Verify kid is the thumbprint of the public key."""
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    signer = LocalJwtSigner(private_key, "test-key")

    expected_kid = jwk.JWK.from_pyca(private_key.public_key()).thumbprint()
    assert signer.kid == expected_kid


def test_local_jwt_signer_should_have_correct_public_jwk() -> None:
    """Happy flow: Verify public_jwk returns correct JWK format."""
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    signer = LocalJwtSigner(private_key, "test-key")

    jwk_dict = signer.public_jwk()

    assert jwk_dict["kty"] == "RSA"
    assert jwk_dict["use"] == "sig"
    assert jwk_dict["alg"] == "PS256"
    assert jwk_dict["kid"] == signer.kid


def test_local_jwt_signer_from_pem_file_should_work(tmp_path: Path) -> None:
    """Happy flow: Create from PEM file."""
    # Create a temporary PEM file
    private_key_pem, _ = generate_rsa_keypair()
    pem_path = tmp_path / "test_key.pem"
    pem_path.write_bytes(private_key_pem.encode("ascii"))

    # Load from file
    signer = LocalJwtSigner.from_pem_file(str(pem_path))

    assert signer.alg == "PS256"
    assert signer.kid is not None


def test_local_jwt_signer_should_raise_when_key_too_small() -> None:
    """Unhappy flow: Reject RSA key smaller than 3072 bits."""
    # Generate a 2048-bit key (too small) - can't use generate_rsa_keypair as it always uses 3072
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(ValueError, match="at least 3072 bits"):
        LocalJwtSigner(private_key, "test-key")


def test_local_jwt_signer_should_raise_when_not_rsa_key() -> None:
    """Unhappy flow: Reject non-RSA key type (EC)."""
    # Generate an EC key
    private_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(ValueError):
        LocalJwtSigner(private_key, "test-key")  # type: ignore


def test_local_jwt_signer_from_pem_file_should_raise_when_file_not_found() -> None:
    """Unhappy flow: File not found error."""
    with pytest.raises(FileNotFoundError, match="JWT signing key file not found"):
        LocalJwtSigner.from_pem_file("/nonexistent/path.pem")


def test_hsm_jwt_signer_should_create_with_valid_hsm(
    hsm_jwt_signer: HsmJwtSigner,
) -> None:
    """Happy flow: Verify HsmJwtSigner created with valid HSM has correct properties."""
    assert hsm_jwt_signer.alg == "PS256"
    assert hsm_jwt_signer.kid is not None
    assert len(hsm_jwt_signer.kid) > 0


def test_hsm_jwt_signer_should_have_correct_public_jwk(
    hsm_jwt_signer: HsmJwtSigner,
) -> None:
    """Happy flow: Verify public_jwk returns correct JWK format."""
    jwk_dict = hsm_jwt_signer.public_jwk()

    assert jwk_dict["kty"] == "RSA"
    assert jwk_dict["use"] == "sig"
    assert jwk_dict["alg"] == "PS256"
    assert jwk_dict["kid"] == hsm_jwt_signer.kid


def test_hsm_jwt_signer_should_raise_when_hsm_returns_non_rsa_key() -> None:
    """Unhappy flow: HSM returns non-RSA key."""
    # Create mock HSM client
    mock_hsm = MagicMock()
    # Return EC public key (not RSA)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_public_pem = (
        ec_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    mock_hsm.public_key_pem.return_value = ec_public_pem

    with pytest.raises(TypeError, match="not an RSA key"):
        HsmJwtSigner(mock_hsm, "test-label")


def test_hsm_jwt_signer_should_raise_when_hsm_key_not_found() -> None:
    """Unhappy flow: HSM key not found."""
    # Create mock HSM client
    mock_hsm = MagicMock()
    mock_hsm.public_key_pem.side_effect = HsmKeyNotFound("Key not found")

    with pytest.raises(HsmKeyNotFound):
        HsmJwtSigner(mock_hsm, "test-label")


def test_jwt_signing_service_should_sign_with_active_key(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Happy flow: Sign claims and verify it produces a valid JWS."""
    claims = {"sub": "test", "aud": "test-audience"}
    result = jwt_signing_service.sign(claims)

    # Verify it's a valid JWS
    assert "." in result
    parts = result.split(".")
    assert len(parts) == 3  # header.payload.signature


def test_jwt_signing_service_should_include_issuer_in_claims(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Happy flow: Verify the issuer is added to the signed JWT."""
    claims = {"sub": "test"}
    result = jwt_signing_service.sign(claims)

    # Decode the JWT to check issuer
    parts = result.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload["iss"] == JWT_ISSUER


def test_jwt_signing_service_should_return_public_jwks(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Happy flow: Verify JWKS contains all signers."""
    jwks = jwt_signing_service.public_jwks()

    assert isinstance(jwks, list)
    assert len(jwks) == 1  # We have one signer in the fixture
    assert jwks[0]["kty"] == "RSA"
    assert jwks[0]["use"] == "sig"
    assert jwks[0]["alg"] == "PS256"


def test_jwt_signing_service_from_config_should_raise_when_missing_issuer() -> None:
    """Unhappy flow: Missing issuer in config."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="",  # Empty issuer
        key_files=[],
        hsm_key_labels=[],
        active_key_file="",
        active_key_label="",
    )

    with pytest.raises(ValueError, match="jwt_signing.issuer is not configured"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_no_keys() -> None:
    """Unhappy flow: No keys configured."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=[],  # No key files
        hsm_key_labels=[],  # No HSM labels
        active_key_file="",
        active_key_label="",
    )

    with pytest.raises(
        ValueError, match="jwt_signing.key_files or jwt_signing.hsm_key_labels"
    ):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_active_key_not_in_list() -> (
    None
):
    """Unhappy flow: Active key not in configured keys."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=["key1.pem"],
        hsm_key_labels=[],
        active_key_file="key2.pem",  # Not in key_files
        active_key_label="",
    )

    with pytest.raises(ValueError, match="jwt_signing.active_key_file must be one of"):
        JwtSigningService.from_config(config, hsm=None)


def test_local_jwt_signer_should_produce_verifiable_signature(
    local_jwt_signer: LocalJwtSigner,
) -> None:
    """Happy flow: Verify LocalJwtSigner produces cryptographically valid PS256 signatures."""
    header = {"alg": local_jwt_signer.alg, "kid": local_jwt_signer.kid, "typ": "JWT"}
    payload = {"sub": "x"}

    # Create signing input (header.payload)
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode())
        .rstrip(b"=")
        .decode("ascii")
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .rstrip(b"=")
        .decode("ascii")
    )
    signing_input = f"{header_b64}.{payload_b64}"

    # Sign
    signature = local_jwt_signer.sign(signing_input.encode())
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    token = f"{signing_input}.{signature_b64}"

    # Verify using jwcrypto
    verifier = jws.JWS()
    verifier.deserialize(token)
    verifier.verify(jwk.JWK(**local_jwt_signer.public_jwk()), alg="PS256")

    assert verifier.payload == json.dumps(payload).encode()


def test_local_jwt_signer_should_not_expose_private_key_members(
    local_jwt_signer: LocalJwtSigner,
) -> None:
    """Happy flow: Verify public_jwk() doesn't expose RSA private key components."""
    public_jwk_dict = local_jwt_signer.public_jwk()

    # RSA private key components that should NOT be in public JWK
    private_members = {"d", "p", "q", "dp", "dq", "qi"}

    assert public_jwk_dict["kty"] == "RSA"
    assert public_jwk_dict["use"] == "sig"
    assert public_jwk_dict["alg"] == "PS256"
    assert not private_members & public_jwk_dict.keys()


def test_jwt_signing_service_should_use_active_key_and_publish_all_keys() -> None:
    """Happy flow: JwtSigningService uses active key for signing but publishes all keys in JWKS."""
    # Create two keys
    private_key_1_pem, _ = generate_rsa_keypair()
    private_key_2_pem, _ = generate_rsa_keypair()

    private_key_1 = serialization.load_pem_private_key(
        private_key_1_pem.encode("ascii"), password=None
    )
    private_key_2 = serialization.load_pem_private_key(
        private_key_2_pem.encode("ascii"), password=None
    )

    assert isinstance(private_key_1, rsa.RSAPrivateKey)
    signer_1 = LocalJwtSigner(private_key_1, "key-1")
    assert isinstance(private_key_2, rsa.RSAPrivateKey)
    signer_2 = LocalJwtSigner(private_key_2, "key-2")

    # Create service with key-2 as active
    service = JwtSigningService(
        issuer="test-issuer", active=signer_2, signers=(signer_1, signer_2)
    )

    # Verify active key is used for signing
    assert service.active == signer_2

    # Verify all keys are in JWKS
    jwks = service.public_jwks()
    assert len(jwks) == 2

    kids = {key["kid"] for key in jwks}
    assert signer_1.kid in kids
    assert signer_2.kid in kids


def test_jwt_signing_service_should_override_issuer_in_claims(
    jwt_signing_service: JwtSigningService,
) -> None:
    """Happy flow: JwtSigningService always sets its own issuer, overriding any user-provided issuer."""
    # Try to sign with a different issuer in claims
    claims = {"sub": "test", "iss": "user-issuer"}

    token = jwt_signing_service.sign(claims)

    # Decode the JWT to check the issuer
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

    assert payload["iss"] == JWT_ISSUER  # Overridden
    assert payload["sub"] == "test"


def test_jwt_signing_service_from_config_should_raise_when_exactly_one_active_key_not_specified() -> (
    None
):
    """Unhappy flow: Config must have exactly one active key."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=["key1.pem"],
        hsm_key_labels=["label1"],
        active_key_file="",  # No active key specified
        active_key_label="",
    )

    with pytest.raises(ValueError, match="exactly one of"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_active_key_not_in_key_files(
    tmp_path: Path,
) -> None:
    """Unhappy flow: Active key must be in key_files."""
    # Create a temporary PEM file
    private_key_pem, _ = generate_rsa_keypair()
    pem_path = tmp_path / "key.pem"
    pem_path.write_bytes(private_key_pem.encode("ascii"))

    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=[str(pem_path)],
        hsm_key_labels=[],
        active_key_file="different-key.pem",  # Not in key_files
        active_key_label="",
    )

    with pytest.raises(ValueError, match="active_key_file must be one of"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_active_label_not_in_hsm_key_labels() -> (
    None
):
    """Unhappy flow: Active HSM label must be in hsm_key_labels."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=[],
        hsm_key_labels=["label1", "label2"],
        active_key_file="",
        active_key_label="label3",  # Not in hsm_key_labels
    )

    with pytest.raises(ValueError, match="active_key_label must be one of"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_hsm_labels_need_hsm() -> (
    None
):
    """Unhappy flow: HSM labels require HSM client."""
    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=[],
        hsm_key_labels=["label1"],
        active_key_file="",
        active_key_label="label1",
    )

    with pytest.raises(ValueError, match="needs the HSM"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_raise_when_same_key_used_twice(
    tmp_path: Path,
) -> None:
    """Unhappy flow: Same key cannot be configured twice."""
    # Create a temporary PEM file
    private_key_pem, _ = generate_rsa_keypair()
    pem_path_1 = tmp_path / "key1.pem"
    pem_path_1.write_bytes(private_key_pem.encode("ascii"))
    pem_path_2 = tmp_path / "key2.pem"
    pem_path_2.write_bytes(private_key_pem.encode("ascii"))  # Same key

    config = ConfigJwtSigning(
        enabled=True,
        issuer="test-issuer",
        key_files=[str(pem_path_1), str(pem_path_2)],
        hsm_key_labels=[],
        active_key_file=str(pem_path_1),
        active_key_label="",
    )

    with pytest.raises(ValueError, match="configured more than once"):
        JwtSigningService.from_config(config, hsm=None)


def test_jwt_signing_service_from_config_should_publish_file_and_hsm_keys(
    tmp_path: Path,
) -> None:
    """Happy flow: JwtSigningService can publish both file and HSM keys."""
    # Create a temporary PEM file
    private_key_pem, _ = generate_rsa_keypair()
    pem_path = tmp_path / "key.pem"
    pem_path.write_bytes(private_key_pem.encode("ascii"))

    # Create a mock HSM signer with proper public_jwk
    mock_hsm_signer = MagicMock(spec=HsmJwtSigner)
    mock_hsm_signer.kid = "hsm-key-id"
    mock_hsm_signer.public_jwk.return_value = {
        "kty": "RSA",
        "use": "sig",
        "alg": "PS256",
        "kid": "hsm-key-id",
    }

    # Create a mock HSM client
    mock_hsm = MagicMock()
    mock_hsm.public_key_pem.return_value = private_key_pem

    # Patch HsmJwtSigner to return our mock
    with patch("app.services.jwt_signer.HsmJwtSigner", return_value=mock_hsm_signer):
        config = ConfigJwtSigning(
            enabled=True,
            issuer="test-issuer",
            key_files=[str(pem_path)],
            hsm_key_labels=["hsm-label"],
            active_key_file=str(pem_path),
            active_key_label="",
        )

        service = JwtSigningService.from_config(config, mock_hsm)

        # Verify both keys are in JWKS
        jwks = service.public_jwks()
        assert len(jwks) == 2  # One from file, one from HSM

        kids = {key["kid"] for key in jwks}
        assert "hsm-key-id" in kids
