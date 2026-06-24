import logging

import requests

from app.config import ConfigOprf
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.oprf_service import oprf_key_label

logger = logging.getLogger(__name__)


class HsmKeyCleanupService:
    """
    Periodically removes expired HSM key versions from the HSM. For every key
    version whose end date has passed (and which has not been removed yet), the
    corresponding key is destroyed in the HSM and the version is marked as removed
    in the database.
    """

    def __init__(
        self,
        hsm_config: ConfigOprf,
        version_service: HsmKeyVersionService,
    ) -> None:
        self.__hsm_config = hsm_config
        self.__version_service = version_service

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
            label = oprf_key_label(f"oin:{version.oin}", version.version)
            try:
                self._destroy_key(label)
            except Exception:
                # Leave the version untouched so the next run retries it.
                logger.exception("failed to destroy HSM key %r", label)
                continue

            self.__version_service.mark_removed(version.id)
            cleaned += 1
            logger.info("removed expired HSM key %r", label)

        if cleaned:
            logger.info("cleaned up %d expired HSM key version(s)", cleaned)
        return cleaned

    def _destroy_key(self, label: str) -> None:
        cfg = self.__hsm_config
        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}/destroy"
        response = requests.post(
            url,
            json={"label": label},
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(
                (cfg.hsm_cert_file, cfg.hsm_key_file)
                if (cfg.hsm_cert_file and cfg.hsm_key_file)
                else None
            ),
        )
        response.raise_for_status()
