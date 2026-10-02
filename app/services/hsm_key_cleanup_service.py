import logging

import gfmodules.logging as gflog

from app.config import ConfigOprf
from app.logging.events import (
    SLEUTELTYPE_IRREVERSIBLE_KEY,
    SLEUTELTYPE_OPRF_SECRET,
    SLEUTELTYPE_REVERSIBLE_KEY,
    Log,
)
from app.services.hsm.client import HsmClient
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import IrreversibleKeyLabel
from app.services.oprf.evaluators import OprfHsmKeyLabel
from app.services.reversible.keys import reversible_key_labels

logger = logging.getLogger(__name__)


class HsmKeyCleanupService:
    """
    Destroys the HSM keys of expired key versions (the OPRF secret, the
    irreversible pseudonym secret and the reversible pseudonym AES/HMAC keys)
    and marks the version as removed.
    Keys are created on first use, so missing ones are skipped.
    """

    def __init__(
        self,
        hsm_config: ConfigOprf,
        version_service: HsmKeyVersionService,
    ) -> None:
        self.__hsm_config = hsm_config
        self.__version_service = version_service
        self.__client = HsmClient(hsm_config)

    def cleanup_expired_keys(self) -> int:
        """
        Destroy every expired HSM key in the HSM and mark it removed. Returns the
        number of key versions that were successfully cleaned up.
        """
        if not (self.__hsm_config and self.__hsm_config.hsm_url):
            logger.debug("HSM not configured, skipping expired key cleanup")
            return 0

        expired = self.__version_service.get_expired_versions()
        cleaned = 0
        for version in expired:
            try:
                oin = version.organization.external_id
                # (label, sleuteltype) of every key the version may have
                labels = [
                    (
                        str(OprfHsmKeyLabel(oin, version.version)),
                        SLEUTELTYPE_OPRF_SECRET,
                    ),
                    (
                        str(IrreversibleKeyLabel(oin, version.version)),
                        SLEUTELTYPE_IRREVERSIBLE_KEY,
                    ),
                ] + [
                    (str(label), SLEUTELTYPE_REVERSIBLE_KEY)
                    for label in reversible_key_labels(oin, version.version)
                ]
            except ValueError:
                logger.exception(
                    "Value %r is not a correct OIN number",
                    version.organization.external_id,
                )
                continue

            # Emit PRS-KEY-004 per destroyed key type, so a retry after a
            # failure does not log it twice.
            destroyed_types: set[str] = set()
            try:
                for label, sleuteltype in labels:
                    if not self._destroy_if_present(label):
                        continue
                    logger.info("removed expired HSM key %r", label)
                    if sleuteltype not in destroyed_types:
                        destroyed_types.add(sleuteltype)
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
                continue

            self.__version_service.mark_removed(version.id)
            cleaned += 1

        if cleaned:
            logger.info("cleaned up %d expired HSM key version(s)", cleaned)
        return cleaned

    def _destroy_if_present(self, label: str) -> bool:
        if not self.__client.label_exists(label):
            return False
        self.__client.destroy(label)
        return True
