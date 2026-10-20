from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.config import ConfigHsm, ConfigJwks
from app.services.hsm.client import HsmKeyNotFound, HsmUnsupportedKeyType
from app.services.http_service import HttpService
from app.services.jwks.keys import (
    JwksHsmKeysService,
    JwksKeysServiceFactory,
    JwksLocalKeysService,
)
from tests.conftest import generate_rsa_cert


@pytest.fixture()
def jwks_local_keys_service() -> JwksLocalKeysService:
    _, leaf_cert = generate_rsa_cert()
    intermediate_cert = leaf_cert
    return JwksLocalKeysService(
        active_signing_key_file=[[leaf_cert, intermediate_cert]]
    )


@pytest.fixture()
def jwks_hsm_keys_service() -> JwksHsmKeysService:
    mock_http_service = HttpService(
        endpoint="example.com",
        timeout=1.0,
    )
    return JwksHsmKeysService(
        http_service=mock_http_service, active_hsm_label=["example_label"]
    )


def test_from_config_should_succeed(tmp_path: Path) -> None:
    cert_pem, _ = generate_rsa_cert()
    cert_path = tmp_path / "test_cert.pem"
    cert_path.write_text(cert_pem)

    config = ConfigJwks(active_signing_key_files=[str(cert_path)])
    service = JwksLocalKeysService.from_config(config)

    assert len(service.active_signing_keys) == 1
    assert len(service.active_signing_keys[0]) == 1


def test_from_config_fails_on_invalid_pem(tmp_path: Path) -> None:
    invalid_pem_path = tmp_path / "invalid.pem"
    invalid_pem_path.write_text("invalid pem data")

    config = ConfigJwks(active_signing_key_files=[str(invalid_pem_path)])
    with pytest.raises(ValueError):
        JwksLocalKeysService.from_config(config)


def test_from_config_fails_on_empty_list() -> None:
    config = ConfigJwks(active_signing_key_files=[])
    with pytest.raises(
        ValueError, match="`active_signing_key_files` is missing from config"
    ):
        JwksLocalKeysService.from_config(config)


def test_get_jwks_should_succeed(jwks_local_keys_service: JwksLocalKeysService) -> None:
    jwks = jwks_local_keys_service.get_jwks()

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    for jwk in jwks["keys"]:
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "PS256"
        assert "kid" in jwk
        assert "x5c" in jwk
        assert len(jwk["x5c"]) == 2


def test_get_jwks_fails_on_empty_cert_chain() -> None:
    service = JwksLocalKeysService(active_signing_key_file=[[]])
    with pytest.raises(ValueError):
        service.get_jwks()


def test_get_jwks_fails_on_non_rsa_cert() -> None:
    ec_private_key = ec.generate_private_key(ec.SECP256R1())
    ec_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "NL")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "NL")]))
        .public_key(ec_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ec_private_key, hashes.SHA256())
    )

    service = JwksLocalKeysService(active_signing_key_file=[[ec_cert]])
    with pytest.raises(TypeError, match="Only RSAPublicKey type is supported"):
        service.get_jwks()


def test_from_config_fails_on_file_not_found() -> None:
    config = ConfigJwks(active_signing_key_files=["nonexistent.pem"])
    with patch("app.utils.certs.load_cert") as mock_load_cert:
        mock_load_cert.side_effect = FileNotFoundError("Cert file not found")
        with pytest.raises(FileNotFoundError):
            JwksLocalKeysService.from_config(config)


def test_get_jwks_should_succeed_for_hsm(
    jwks_hsm_keys_service: JwksHsmKeysService,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    with patch("app.services.jwks.keys.HsmClient") as mock_hsm_client_class:
        mock_hsm_client = Mock()
        mock_hsm_client.get_public_key_pem.return_value = public_key
        mock_hsm_client_class.return_value = mock_hsm_client

        jwks_hsm_keys_service.hsm_client = mock_hsm_client

        jwks = jwks_hsm_keys_service.get_jwks()

        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

        jwk = jwks["keys"][0]
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "PS256"
        assert "kid" in jwk


def test_get_jwks_fails_on_key_not_found(
    jwks_hsm_keys_service: JwksHsmKeysService,
) -> None:

    with patch("app.services.jwks.keys.HsmClient") as mock_hsm_client_class:
        mock_hsm_client = Mock()
        mock_hsm_client.get_public_key_pem.side_effect = HsmKeyNotFound("Key not found")
        mock_hsm_client_class.return_value = mock_hsm_client

        jwks_hsm_keys_service.hsm_client = mock_hsm_client

        with pytest.raises(HsmKeyNotFound):
            jwks_hsm_keys_service.get_jwks()


def test_get_jwks_fails_on_unsupported_key(
    jwks_hsm_keys_service: JwksHsmKeysService,
) -> None:
    with patch("app.services.jwks.keys.HsmClient") as mock_hsm_client_class:
        mock_hsm_client = Mock()
        mock_hsm_client.get_public_key_pem.side_effect = HsmUnsupportedKeyType()
        mock_hsm_client_class.return_value = mock_hsm_client

        jwks_hsm_keys_service.hsm_client = mock_hsm_client

        with pytest.raises(HsmUnsupportedKeyType):
            jwks_hsm_keys_service.get_jwks()


def test_get_jwks_fails_on_hsm_unreachable(
    jwks_hsm_keys_service: JwksHsmKeysService,
) -> None:
    with patch("app.services.jwks.keys.HsmClient") as mock_hsm_client_class:
        mock_hsm_client = Mock()
        mock_hsm_client.get_public_key_pem.side_effect = ConnectionError(
            "HSM unreachable"
        )
        mock_hsm_client_class.return_value = mock_hsm_client

        jwks_hsm_keys_service.hsm_client = mock_hsm_client

        with pytest.raises(ConnectionError):
            jwks_hsm_keys_service.get_jwks()


def test_make_jwk_should_succeed_for_hsm() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    jwk = JwksHsmKeysService.make_jwk(public_key, "sig", "PS256")

    jwk_dict = jwk.export_public(as_dict=True)
    assert jwk_dict["use"] == "sig"
    assert jwk_dict["alg"] == "PS256"
    assert "kid" in jwk_dict


def test_from_config_should_succeed_for_hsm() -> None:
    hsm_config = ConfigHsm(
        url="https://example.com",
        timeout=1.0,
        cert_file="dummy_cert.pem",
        key_file="dummy_key.pem",
    )
    jwks_config = ConfigJwks(active_hsm_key_labels=["example_label"])

    service = JwksHsmKeysService.from_config(hsm_config, jwks_config)

    assert service.active_hsm_label == ["example_label"]
    assert isinstance(service, JwksHsmKeysService)


def test_from_config_fails_on_missing_url_for_hsm() -> None:
    from app.config import ConfigHsm, ConfigJwks

    hsm_config = ConfigHsm(
        url=None,
        timeout=1.0,
        cert_file="dummy_cert.pem",
        key_file="dummy_key.pem",
    )
    jwks_config = ConfigJwks(active_hsm_key_labels=["example_label"])

    with pytest.raises(ValueError, match=r"Missing `url` in \[hsm\] config"):
        JwksHsmKeysService.from_config(hsm_config, jwks_config)


def test_from_config_fails_on_missing_labels_for_hsm() -> None:
    hsm_config = ConfigHsm(
        url="https://example.com",
        timeout=1.0,
        cert_file="dummy_cert.pem",
        key_file="dummy_key.pem",
    )
    jwks_config = ConfigJwks(active_hsm_key_labels=[])

    with pytest.raises(
        ValueError, match=r"Missing `active_hsm_key_labels` in \[jwks\] config"
    ):
        JwksHsmKeysService.from_config(hsm_config, jwks_config)


def test_factory_creates_hsm_service() -> None:
    hsm_config = ConfigHsm(
        url="https://example.com",
        timeout=1.0,
        cert_file="dummy_cert.pem",
        key_file="dummy_key.pem",
    )
    jwks_config = ConfigJwks(active_hsm_key_labels=["example_label"])

    service = JwksKeysServiceFactory.create(jwks_config, hsm_config)
    assert isinstance(service, JwksHsmKeysService)


def test_factory_creates_local_service(tmp_path: Path) -> None:
    cert_pem, _ = generate_rsa_cert()
    cert_path = tmp_path / "test_cert.pem"
    cert_path.write_text(cert_pem)

    hsm_config = ConfigHsm(
        timeout=1.0,
        cert_file="",
        key_file="",
    )
    jwks_config = ConfigJwks(active_signing_key_files=[str(cert_path)])

    service = JwksKeysServiceFactory.create(jwks_config, hsm_config)
    assert isinstance(service, JwksLocalKeysService)


def test_factory_fails_on_both_options() -> None:
    hsm_config = ConfigHsm(
        url="https://example.com",
        timeout=1.0,
        cert_file="dummy_cert.pem",
        key_file="dummy_key.pem",
    )
    jwks_config = ConfigJwks(
        active_hsm_key_labels=["example_label"], active_signing_key_files=["dummy.pem"]
    )

    with pytest.raises(ValueError, match="Cannot use both hsm and local options"):
        JwksKeysServiceFactory.create(jwks_config, hsm_config)


def test_factory_fails_on_no_options() -> None:
    hsm_config = ConfigHsm(
        timeout=1.0,
        cert_file="",
        key_file="",
    )
    jwks_config = ConfigJwks(active_signing_key_files=[])

    with pytest.raises(
        ValueError, match="`active_signing_key_files` is missing from config"
    ):
        JwksKeysServiceFactory.create(jwks_config, hsm_config)
