import base64
import logging

import pyoprf
import requests
from jwcrypto import jwk

from app.config import ConfigOprf
from app.services.oprf.jwe_token import BlindJwe
from app.models.requests import BlindRequest

logger = logging.getLogger(__name__)


class OprfService:
    def __init__(self, server_key: str | None, hsm_config: ConfigOprf | None = None):
        self.__server_key = base64.urlsafe_b64decode(server_key) if server_key else None
        self.__hsm_config = hsm_config

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

    def eval_blind(self, req: BlindRequest, pub_key: jwk.JWK) -> str:
        """
        Evaluate a blind and returns a JWE encrypted on the pubkey
        """
        try:
            bi = base64.urlsafe_b64decode(req.encryptedPersonalId)
            if self.__hsm_config and self.__hsm_config.hsm_url:
                eval_bytes = self._eval_via_hsm(req.recipientOrganization, bi)
            else:
                eval_bytes = pyoprf.evaluate(self.__server_key, bi)
        except Exception as e:
            logger.exception("unable to evaluate blind")
            raise ValueError(f"unable to evaluate blind: {e}")

        subject = "pseudonym:eval:" + base64.urlsafe_b64encode(eval_bytes).decode(
            "utf-8"
        )
        jwe = BlindJwe.build(
            audience=req.recipientOrganization,
            scope=req.recipientScope,
            subject=subject,
            pub_key=pub_key,
        )

        logger.info(
            "evaluated blind for recipient %r with scope %r",
            req.recipientOrganization,
            req.recipientScope,
        )
        return jwe

    def _eval_via_hsm(self, recipient_org: str, blinded_bytes: bytes) -> bytes:
        cfg = self.__hsm_config
        if cfg is None:
            raise ValueError("HSM configuration not found")

        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}/oprf/evaluate"
        response = requests.post(
            url,
            json={
                "label": f"ura-{recipient_org}",
                "blinded_point": base64.b64encode(blinded_bytes).decode(),
            },
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(cfg.hsm_cert_file, cfg.hsm_key_file)
            if (cfg.hsm_cert_file and cfg.hsm_key_file)
            else None,
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
