import base64
import logging
from dataclasses import dataclass

import pyoprf
from jwcrypto import jwk

from app.models.requests import BlindRequest
from app.services.oprf.jwe_token import BlindJwe
from app.services.oprf.evaluators import LocalOprfEvaluator, OprfEvaluator

logger = logging.getLogger(__name__)


class OprfEvaluationError(ValueError):
    """
    Raised when an OPRF evaluation fails. The error_type matches the audit
    logging values used by this service, such as invalid_blinded_input and
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
        self, req: BlindRequest, pub_key: jwk.JWK, pub_key_id: str | None
    ) -> OprfEvalResult:
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

        try:
            evals = self.__evaluator.evaluate(req.recipientOrganization, bi)
        except OprfEvaluationError:
            raise
        except Exception as e:
            logger.exception("unable to evaluate blind")
            raise OprfEvaluationError(
                f"unable to evaluate blind: {e}",
                error_type=(
                    "invalid_blinded_input"
                    if isinstance(self.__evaluator, LocalOprfEvaluator)
                    else "crypto_evaluation_failure"
                ),
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
            pub_key_id=pub_key_id,
            extra_claims={"extra_versions": extra_versions},
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
