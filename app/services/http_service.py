from typing import Any, Literal

import requests
from gfmodules.logging import correlation_headers
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Sized to AnyIO's default worker thread limit, so every request thread of the
# synchronous FastAPI endpoints can hold a pooled connection.
_POOL_MAXSIZE = 40

_RETRY = Retry(
    total=3,
    connect=3,  # safe for every method, the request never reached the server
    read=0,  # each retry repeats the full timeout, so a slow upstream would hold
    # every worker thread and make the whole service unresponsive
    status=0,  # the server already answered
    other=0,
    backoff_factor=0.3,
    respect_retry_after_header=False,
    raise_on_status=False,
)

HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


class HttpService:
    def __init__(
        self,
        endpoint: str,
        timeout: float,
        mtls_cert: str | None = None,
        mtls_key: str | None = None,
        verify_ca: str | bool = True,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._cert = (mtls_cert, mtls_key) if mtls_cert and mtls_key else None
        self._verify_ca = verify_ca
        adapter = HTTPAdapter(pool_maxsize=_POOL_MAXSIZE, max_retries=_RETRY)
        self._session = requests.Session()
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def do_request(
        self,
        method: HttpMethod,
        path: str = "",
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        return self._session.request(
            method,
            f"{self._endpoint}{path}",
            json=json,
            params=params,
            headers={**(headers or {}), **correlation_headers()},
            timeout=self._timeout,
            cert=self._cert,
            verify=self._verify_ca,
        )
