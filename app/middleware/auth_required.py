from functools import wraps
from typing import Callable, Any, TypeVar

from starlette.requests import Request

from app.config import get_config
from app.services.tls_service import CertAuthentication, CertAuthentications, CertAuthenticationException, TLSService

T = TypeVar("T", bound=Callable[..., Any])


def get_cert_from_request(request: Request) -> bytes:
    str_pem = request.headers.get("ssl_client_cert", None)

    pem = bytes()
    if str_pem is not None:
        pem = str(str_pem).encode()


    # If the client certificate is not provided in the header, check if an override certificate is provided
    override_cert = get_config().auth.override_cert
    if override_cert is not None:
        with open(override_cert, "r") as file:
            pem = file.read().encode()

    if pem is None:
        raise CertAuthenticationException("No client certificate provided")

    return pem

def auth_required(certs: list[CertAuthentication]) ->  Callable[[T], T]:
    """
    Decorator to check if the client certificate is valid.
    """
    def decorator(func) -> Any:    # type: ignore
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs) -> Any: # type: ignore
            try:
                pem = get_cert_from_request(request)

                tls_service = TLSService(get_config().auth.allowed_curves, get_config().auth.min_rsa_bitsize)
                cert_type = tls_service.get_certificate_type(pem)
            except CertAuthenticationException as e:
                return {"error": str(e)}, 403

            if cert_type not in certs and CertAuthentications.AUTH_ALL not in certs:
                return {"error": "No correct client certificate provided"}, 403

            if not tls_service.validate_cert(pem):
                return {"error": "Client certificate is not valid"}, 403

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


