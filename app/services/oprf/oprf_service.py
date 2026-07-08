import base64
import logging
from dataclasses import dataclass

import pyoprf
import requests
from jwcrypto import jwk

from app.config import ConfigOprf
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.jwe_token import BlindJwe
from app.models.requests import BlindRequest

logger = logging.getLogger(__name__)


class OprfEvaluationError(ValueError):
    """
    Raised when an OPRF evaluation fails. The error_type matches the audit
    logging spec: invalid_blinded_input | secret_version_destroyed |
    crypto_evaluation_failure.
    """

    def __init__(
        self, message: str, error_type: str = "crypto_evaluation_failure"
    ) -> None:
        super().__init__(message)
        self.error_type = error_type


@dataclass(frozen=True)
class OprfEvalResult:
    jwe: str
    # OPRF secret key versions the blind was evaluated against
    key_versions: tuple[int, ...]


class HsmKeyLabel:
    def __init__(self, oin: Oin, version: int):
        self.oin = oin
        self.version = version

    def __str__(self) -> str:
        return f"oin-{self.oin}-v{self.version}"


class OprfService:
    def __init__(
        self,
        server_key: str | None,
        hsm_config: ConfigOprf | None = None,
        hsm_key_version_service: HsmKeyVersionService | None = None,
    ):
        self.__server_key = base64.urlsafe_b64decode(server_key) if server_key else None
        self.__hsm_config = hsm_config
        self.__hsm_key_version_service = hsm_key_version_service

        if hsm_config and hsm_config.hsm_url:
            logger.info("OPRF evaluation configured via HSM at %s", hsm_config.hsm_url)
        else:
            logger.info("OPRF evaluation configured with local key")

    @staticmethod
    def generate_server_key() -> str:
        """
        Returns a base64 encoded pyoprf server key for evaluation
        """
        return base64.urlsafe_b64encode(pyoprf.keygen()).decode("ascii")

    def eval_blind(self, req: BlindRequest, pub_key: jwk.JWK) -> OprfEvalResult:
        """
        Evaluate a blind and returns a JWE encrypted on the pubkey, plus the
        key versions the blind was evaluated against
        """
        try:
            bi = base64.urlsafe_b64decode(req.encryptedPersonalId)
        except Exception as e:
            logger.exception("unable to decode blinded input")
            raise OprfEvaluationError(
                f"unable to decode blinded input: {e}",
                error_type="invalid_blinded_input",
            )

        if self.__hsm_config and self.__hsm_config.hsm_url:
            try:
                evals = self._eval_via_hsm(req.recipientOrganization, bi)
            except OprfEvaluationError:
                raise
            except Exception as e:
                logger.exception("unable to evaluate blind")
                raise OprfEvaluationError(
                    f"unable to evaluate blind: {e}",
                    error_type="crypto_evaluation_failure",
                )
        else:
            try:
                evals = {1: pyoprf.evaluate(self.__server_key, bi)}
            except Exception as e:
                logger.exception("unable to evaluate blind")
                raise OprfEvaluationError(
                    f"unable to evaluate blind: {e}",
                    error_type="invalid_blinded_input",
                )

        # The subject always carries the latest key version in the original,
        # backwards-compatible format so existing clients keep working unchanged.
        latest = max(evals)
        subject = "pseudonym:eval:" + base64.urlsafe_b64encode(evals[latest]).decode(
            "utf-8"
        )

        # Any additional (older) key versions are stored as a separate claim, so
        # newer clients can detect and finalize against older versions as well.
        extra_versions = {
            str(version): base64.urlsafe_b64encode(eval_bytes).decode("utf-8")
            for version, eval_bytes in sorted(evals.items())
            if version != latest
        }

        jwe = BlindJwe.build(
            audience=str(req.recipientOrganization),
            scope=req.recipientScope,
            subject=subject,
            pub_key=pub_key,
            extra_claims={"extra_versions": extra_versions},
        )

        logger.info(
            "evaluated blind for recipient %r with scope %r",
            req.recipientOrganization,
            req.recipientScope,
        )
        return OprfEvalResult(jwe=jwe, key_versions=tuple(sorted(evals)))

    def _eval_via_hsm(
        self, recipient_org_oin: Oin, blinded_bytes: bytes
    ) -> dict[int, bytes]:
        cfg = self.__hsm_config
        if cfg is None:
            raise ValueError("HSM configuration not found")

        if self.__hsm_key_version_service is None:
            raise ValueError("HSM key version service not configured")
        # The active key versions are stored in the database, keyed by OIN number.
        active = self.__hsm_key_version_service.get_active_versions(
            oin=recipient_org_oin
        )
        versions = sorted({v.version for v in active})
        if not versions:
            raise OprfEvaluationError(
                f"no active key version for oin {recipient_org_oin}",
                error_type="secret_version_destroyed",
            )

        # Evaluate the blind against every active key version, so the result holds
        # one entry per version (e.g. during key rotation).
        ret: dict[int, bytes] = {}
        for version in versions:
            label = HsmKeyLabel(recipient_org_oin, version)
            if not self._label_exists(label):
                self._generate_key(label)

            ret[version] = self._evaluate_label(label, blinded_bytes)

        return ret

    def _generate_key(self, label: HsmKeyLabel) -> None:
        cfg = self.__hsm_config
        if cfg is None:
            raise ValueError("HSM configuration not found")

        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}/generate/oprf"
        response = requests.post(
            url,
            json={
                "label": str(label),
            },
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(
                (cfg.hsm_cert_file, cfg.hsm_key_file)
                if (cfg.hsm_cert_file and cfg.hsm_key_file)
                else None
            ),
        )
        response.raise_for_status()

        if "result" not in response.json():
            raise ValueError("HSM configuration not found")

    def _label_exists(self, label: HsmKeyLabel) -> bool:
        cfg = self.__hsm_config
        if cfg is None:
            raise ValueError("HSM configuration not found")

        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}"
        response = requests.post(
            url,
            json={
                "label": str(label),
                "objtype": "SECRET_KEY",
            },
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(
                (cfg.hsm_cert_file, cfg.hsm_key_file)
                if (cfg.hsm_cert_file and cfg.hsm_key_file)
                else None
            ),
        )
        response.raise_for_status()

        result = response.json()["objects"] or []
        return len(result) > 0

    def _evaluate_label(self, label: HsmKeyLabel, blinded_bytes: bytes) -> bytes:
        cfg = self.__hsm_config
        if cfg is None:
            raise ValueError("HSM configuration not found")

        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}/oprf/evaluate"
        response = requests.post(
            url,
            json={
                "label": str(label),
                "blinded_point": base64.b64encode(blinded_bytes).decode(),
            },
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(
                (cfg.hsm_cert_file, cfg.hsm_key_file)
                if (cfg.hsm_cert_file and cfg.hsm_key_file)
                else None
            ),
        )
        response.raise_for_status()
        return base64.b64decode(response.json()["result"])

    @staticmethod
    def blind_input(input: str) -> dict[str, str]:
        """
        Blind an input and returns the blind factor and the blinded input
        """
        blind_factor, blinded_input = pyoprf.blind(input.encode("utf-8"))
        return {
            "blind_factor": base64.urlsafe_b64encode(blind_factor).decode("ascii"),
            "blinded_input": base64.urlsafe_b64encode(blinded_input).decode("ascii"),
        }

    @staticmethod
    def finalize(blind_factor: str, eval: str) -> str:
        """
        Finalize the OPRF by unblinding the evaluated input with the blind factor
        """
        bf = base64.urlsafe_b64decode(blind_factor)
        ev = base64.urlsafe_b64decode(eval)
        final = pyoprf.unblind(bf, ev)
        return base64.urlsafe_b64encode(final).decode("ascii")
