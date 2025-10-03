from enum import Enum
from typing import Dict, Set

# Define which pseudonym types are allowed for each RID usage
ALLOWED_BY_RID_USAGE: Dict[str, Set[str]] = {
    "bsn": {"bsn", "rp", "irp"},
    "rp": {"rp", "irp"},
    "irp": {"irp"},
}

# Define the minimum RID usage required for each pseudonym type
REQUIRED_MIN_USAGE = {
    "bsn": "Bsn",
    "rp": "ReversiblePseudonym",
    "irp": "IrreversiblePseudonym",
}

# Mapping of RID usage to their rank (higher number can exchange lowr number)
USAGE_RANK = {
    "IrreversiblePseudonym": 1,
    "ReversiblePseudonym": 2,
    "Bsn": 3,
}

class RidUsage(str, Enum):
    Bsn = "bsn"
    ReversiblePseudonym = "rp"
    IrreversiblePseudonym = "irp"

    def __str__(self) -> str:
        return self.value
