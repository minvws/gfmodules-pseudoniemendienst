import logging

import gfmodules.logging as gflog

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.logging.events import (
    SLEUTELTYPE_IRREVERSIBLE_KEY,
    SLEUTELTYPE_OPRF_SECRET,
    SLEUTELTYPE_REVERSIBLE_KEY,
    Log,
)
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.key_destroyer import KeyDestroyer

logger = logging.getLogger(__name__)


class HsmKeyCleanupService:
    """
    Destroys the keys of expired key versions and marks the version as removed.
    """

    def __init__(
        self,
        oprf_keys: KeyDestroyer,
        irreversible_keys: KeyDestroyer,
        reversible_keys: KeyDestroyer,
        version_service: HsmKeyVersionService,
    ) -> None:
        self.__keys_by_sleuteltype = (
            (oprf_keys, SLEUTELTYPE_OPRF_SECRET),
            (irreversible_keys, SLEUTELTYPE_IRREVERSIBLE_KEY),
            (reversible_keys, SLEUTELTYPE_REVERSIBLE_KEY),
        )
        self.__version_service = version_service

    def cleanup_expired_keys(self) -> int:
        cleaned = 0
        failed = 0
        for version in self.__version_service.get_expired_versions():
            if self._cleanup_version(version):
                cleaned += 1
            else:
                failed += 1

        if cleaned:
            logger.info("cleaned up %d expired HSM key version(s)", cleaned)
        if failed:
            logger.warning("failed to clean up %d expired HSM key version(s)", failed)
        return cleaned

    def _cleanup_version(self, version: HsmKeyVersionEntity) -> bool:
        try:
            self._destroy_keys(version)
        except Exception as e:  # noqa: BLE001 - any HSM failure must not stop the run
            # Leave the version untouched so the next run retries it.
            gflog.emit(
                logger,
                Log.HSM_OPERATION_FAILED,
                "failed to destroy expired HSM keys",
                fields={
                    "operation_type": "destroy",
                    "error_reason": type(e).__name__,
                },
                exc_info=e,
            )
            return False

        self.__version_service.mark_removed(version.id)
        return True

    def _destroy_keys(self, version: HsmKeyVersionEntity) -> None:
        oin = version.organization.external_id
        for keys, sleuteltype in self.__keys_by_sleuteltype:
            if keys.destroy(oin, version.version):
                gflog.emit(
                    logger,
                    Log.KEY_VERSION_DESTROYED,
                    "expired HSM key version destroyed",
                    fields={
                        "sleuteltype": sleuteltype,
                        "organisatie_oin": oin.value,
                        "vernietigde_versie": version.version,
                    },
                )
