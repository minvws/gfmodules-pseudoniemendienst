import logging

from app.db.entities.organization import Organization
from app.rid import USAGE_RANK, RidUsage

logger = logging.getLogger(__name__)


class ExchangeNotAuthorized(Exception):
    """Raised when one of the organizations lacks the authorization for an exchange."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _usage_rank(max_rid_usage: str) -> int:
    try:
        return USAGE_RANK[RidUsage(max_rid_usage).name]
    except ValueError:
        logger.warning("unknown max_rid_usage value: %r", max_rid_usage)
        return 0


def assert_may_provide_personal_id(sender: Organization) -> None:
    """The sender hands a personal ID to the PRS; it must be authorized to do so."""
    if not sender.may_provide_personal_id:
        raise ExchangeNotAuthorized(
            "sender_may_not_provide_personal_id",
            f"Organization '{sender.oin.value}' is not allowed to provide a personal ID",
        )


def assert_may_receive_reversible_pseudonym(recipient: Organization) -> None:
    """
    A reversible pseudonym can be turned back into the personal ID by the PRS, so
    the recipient must be registered for at least the reversible-pseudonym usage
    level.
    """
    required = USAGE_RANK[RidUsage.ReversiblePseudonym.name]
    if _usage_rank(recipient.max_rid_usage) < required:
        raise ExchangeNotAuthorized(
            "recipient_may_not_receive_reversible_pseudonym",
            f"Organization '{recipient.oin.value}' is not allowed to receive reversible pseudonyms",
        )
