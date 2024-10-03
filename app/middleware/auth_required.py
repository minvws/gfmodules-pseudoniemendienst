from functools import wraps
from typing import Callable, Any, TypeVar

from fastapi import HTTPException
from starlette.requests import Request

from app.config import get_config
from app.container import get_authorization_service
from app.services.tls_service import CertAuthentication, CertAuthentications, CertAuthenticationException

T = TypeVar("T", bound=Callable[..., Any])

SSL_PROXY_HEADER = "ssl_client_cert"

def get_cert_from_request(request: Request) -> bytes:
    str_pem = request.headers.get(SSL_PROXY_HEADER, None)

    pem = bytes()
    if str_pem is not None:
        pem = str(str_pem).encode()

    # If the client certificate is not provided in the header, check if an override certificate is provided
    override_cert = get_config().auth.override_cert
    if override_cert is not None and override_cert != "":
        with open(override_cert, "r") as file:
            pem = file.read().encode()

    if pem is None:
        raise CertAuthenticationException("No client certificate provided")

    return pem

def auth_required(allowed_cert_types: list[CertAuthentication]) ->  Callable[[T], T]:
    """
    Decorator to check if the client certificate is valid.
    """
    def decorator(func) -> Any:    # type: ignore
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs) -> Any: # type: ignore
            auth_service = get_authorization_service()
            pem = get_cert_from_request(request)

            # Make sure the certificate is valid (technically, not expired, not revoked, etc.)
            try:
                auth_service.authorize(pem)
            except Exception as e:
                raise HTTPException(403, e)

            # Next, check if the certificate is actually allowed to access the endpoint
            cert_type = auth_service.get_certificate_type()
            if cert_type not in allowed_cert_types and CertAuthentications.AUTH_ALL not in allowed_cert_types:
                raise HTTPException(403, "Certificate not allowed")

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


