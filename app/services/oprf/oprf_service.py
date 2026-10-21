import base64
import binascii
import logging
from dataclasses import dataclass

import pyoprf
import pysodium
import requests
from jwcrypto import jwk

from app.exceptions.access import RecipientNotFoundError
from app.exceptions.pseudonym import (
    HsmOperationFailedError,
    HsmTimeoutError,
    HsmUnreachableError,
    InvalidBlindedInputError,
)
from app.models.requests.oprf import BlindRequest
from app.services.hsm.client import HsmKeyNotFound
from app.services.jwe_token import Jwe
from app.services.oprf.evaluators import OprfEvaluator

logger = logging.getLogger(__name__)

_RISTRETTO255_IDENTITY = bytes(pysodium.crypto_core_ristretto255_BYTES)

_HSM_REFUSALS = (requests.HTTPError, HsmKeyNotFound)


def _is_ristretto255_element(element: bytes) -> bool:
    return (
        len(element) == len(_RISTRETTO255_IDENTITY)
        and element != _RISTRETTO255_IDENTITY
        and bool(pysodium.crypto_core_ristretto255_is_valid_point(element))
    )


@dataclass(frozen=True)
class OprfEvalResult:
    jwe: str
    # OPRF secret key versions the blind was evaluated against
    key_versions: tuple[int, ...]


class OprfService:
    def __init__(self, evaluator: OprfEvaluator):
        self.__evaluator = evaluator

    @staticmethod
    def generate_server_key() -> str:
        """
        Returns a base64 encoded pyoprf server key for evaluation
        """
        return base64.urlsafe_b64encode(pyoprf.keygen()).decode("ascii")

    def eval_blind(
        self,
        req: BlindRequest,
        pub_key: jwk.JWK,
    ) -> OprfEvalResult:
        """
        Evaluate a blind and returns a JWE encrypted on the pubkey, plus the
        key versions the blind was evaluated against
        """
        try:
            bi = base64.urlsafe_b64decode(req.encryptedPersonalId)
        except binascii.Error as e:
            logger.exception("unable to decode blinded input")
            raise InvalidBlindedInputError() from e
        if not _is_ristretto255_element(bi):
            raise InvalidBlindedInputError()

        try:
            evals = self.__evaluator.evaluate(req.recipientOrganization, bi)
        except requests.ConnectionError as e:
            raise HsmUnreachableError() from e
        except requests.Timeout as e:
            raise HsmTimeoutError() from e
        except _HSM_REFUSALS as e:
            logger.exception("unable to evaluate blind")
            raise HsmOperationFailedError() from e

        if not evals:
            # The recipient has no active HSM key version. Reported like an
            # unknown recipient, as the reversible exchange does, so a caller
            # cannot tell the two apart.
            raise RecipientNotFoundError()

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

        jwe = Jwe.build(
            audience=str(req.recipientOrganization),
            scope=req.recipientScope,
            subject=subject,
            pub_key=pub_key,
            extra_claims={"extraVersions": extra_versions},
        )

        logger.info(
            "evaluated blind for recipient %r with scope %r",
            req.recipientOrganization,
            req.recipientScope,
        )
        return OprfEvalResult(jwe=jwe, key_versions=tuple(sorted(evals)))

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
