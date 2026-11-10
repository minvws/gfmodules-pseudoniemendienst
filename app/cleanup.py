"""
Standalone HSM key cleanup program.

Removes expired HSM key versions from the HSM API and marks them as removed in
the database. Intended to be run periodically by a regular (system) cron job:

    python3 -m app.cleanup

It runs once and exits: 0 on success, 1 on failure.
"""

import logging
import sys

import gfmodules.logging as gflog

from app import application, container
from app.logging.events import Log

logger = logging.getLogger(__name__)


def main() -> int:
    application.application_init()

    service = container.get_hsm_key_cleanup_service()
    try:
        cleaned = service.cleanup_expired_keys()
    except Exception as e:  # noqa: BLE001
        gflog.emit(
            logger,
            Log.KEY_CLEANUP_FAILED,
            "HSM key cleanup failed",
            fields={"error_reason": type(e).__name__},
            exc_info=e,
        )
        return 1

    logger.info("HSM key cleanup finished: removed %d expired key version(s)", cleaned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
