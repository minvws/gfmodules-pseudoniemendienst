import base64
import pyoprf
from jwcrypto import jwk

from app.services.oprf.jwe_token import BlindJwe
from app.models.requests import BlindRequest
import logging

logger = logging.getLogger(__name__)


class OprfService:
    def __init__(self, server_key: str):
        self.__server_key = base64.urlsafe_b64decode(server_key)

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
            eval = pyoprf.evaluate(self.__server_key, bi)
        except Exception as e:
            logger.exception("unable to evaluate blind")
            raise ValueError(f"unable to evaluate blind: {e}")

        subject = "pseudonym:eval:" + base64.urlsafe_b64encode(eval).decode("utf-8")
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
