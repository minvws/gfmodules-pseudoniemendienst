"""
The subject both the reversible and the irreversible pseudonym are computed over:

    subject = "<personal_id>|oin:<recipient oin>|<recipient scope>"
"""

from app.models.oin import RECIPIENT_ORGANIZATION_PREFIX, Oin
from app.models.personal_id import PersonalId

DELIMITER = "|"


def recipient_organization(recipient: Oin) -> str:
    return RECIPIENT_ORGANIZATION_PREFIX + recipient.value


def pseudonym_subject(
    personal_id: PersonalId, recipient: Oin, recipient_scope: str
) -> bytes:
    """Raises ValueError if the scope contains the delimiter, which would break
    splitting the subject."""
    if DELIMITER in recipient_scope:
        raise ValueError(f"recipient scope must not contain '{DELIMITER}'")
    return DELIMITER.join(
        (personal_id.as_str(), recipient_organization(recipient), recipient_scope)
    ).encode()
