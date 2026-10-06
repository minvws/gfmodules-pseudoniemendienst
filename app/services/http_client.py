import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def retrying_session() -> requests.Session:
    # status_forcelist stays empty: only connection/read failures are
    # retried, never an HTTP error response, so an expected 4xx/5xx from the
    # remote service still reaches the caller unchanged.
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.3,
            allowed_methods=frozenset({"POST"}),
        )
    )
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
