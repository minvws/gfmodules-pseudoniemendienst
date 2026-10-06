from typing import Any, Literal

import requests
from gfmodules.logging import correlation_headers
from requests.adapters import HTTPAdapter

# Sized to AnyIO's default worker thread limit, so every request thread of the
# synchronous FastAPI endpoints can hold a pooled connection.
_POOL_MAXSIZE = 40

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
        adapter = HTTPAdapter(pool_maxsize=_POOL_MAXSIZE)
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
