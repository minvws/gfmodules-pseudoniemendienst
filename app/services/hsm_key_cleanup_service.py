import logging

from app.config import ConfigOprf
from app.services.hsm.client import HsmClient
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.evaluators import HsmKeyLabel
from app.services.reversible.keys import reversible_key_labels

logger = logging.getLogger(__name__)


class HsmKeyCleanupService:
    """
    Destroys the HSM keys of expired key versions (the OPRF secret and the
    reversible pseudonym AES/HMAC keys) and marks the version as removed.
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
                labels = [str(HsmKeyLabel(oin, version.version))] + [
                    str(label) for label in reversible_key_labels(oin, version.version)
                ]
            except ValueError:
                logger.exception(
                    "Value %r is not a correct OIN number",
                    version.organization.external_id,
                )
                continue

            try:
                for label in labels:
                    if self._destroy_if_present(label):
                        logger.info("removed expired HSM key %r", label)
            except Exception:
                # Leave the version untouched so the next run retries it.
                logger.exception(
                    "failed to destroy HSM keys for version %s", version.id
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
