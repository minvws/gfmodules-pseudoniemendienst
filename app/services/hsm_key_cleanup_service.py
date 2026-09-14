import logging

import requests

from app.config import ConfigOprf
from app.logging.context import correlation_headers
from app.logging.events import (
    HSM_OPERATION_FAILED,
    KEY_VERSION_DESTROYED,
    SLEUTELTYPE_OPRF_SECRET,
    log_event,
)
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.evaluators import HsmKeyLabel

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
            try:
                label = HsmKeyLabel(version.organization.external_id, version.version)
            except ValueError:
                logger.exception(
                    "Value %r is not a correct OIN number",
                    version.organization.external_id,
                )
                continue

            try:
                self._destroy_key(label)
            except Exception as e:  # noqa: BLE001 - any HSM failure must not stop the run
                log_event(
                    logger,
                    HSM_OPERATION_FAILED,
                    "failed to destroy expired HSM key",
                    operation_type="destroy",
                    error_reason=type(e).__name__,
                    exc_info=e,
                )
                continue

            self.__version_service.mark_removed(version.id)
            cleaned += 1
            log_event(
                logger,
                KEY_VERSION_DESTROYED,
                "expired HSM key version destroyed",
                sleuteltype=SLEUTELTYPE_OPRF_SECRET,
                organisatie_oin=label.oin.value,
                vernietigde_versie=label.version,
            )

        if cleaned:
            logger.info("cleaned up %d expired HSM key version(s)", cleaned)
        return cleaned

    def _destroy_key(self, label: HsmKeyLabel) -> None:
        cfg = self.__hsm_config
        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}/destroy"
        response = requests.post(
            url,
            json={"label": str(label)},
            headers=correlation_headers(),
            timeout=10,
            verify=cfg.hsm_ca_cert_file or True,
            cert=(
                (cfg.hsm_cert_file, cfg.hsm_key_file)
                if (cfg.hsm_cert_file and cfg.hsm_key_file)
                else None
            ),
        )
        response.raise_for_status()
