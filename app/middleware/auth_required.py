from functools import wraps

from starlette.requests import Request

from app.services.tls_service import CertAuthentication, CertAuthentications, CertAuthenticationException, TLSService


def auth_required(certs: list[CertAuthentication]):
    """
    Decorator to check if the client certificate is valid.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            try:
                tls_service = TLSService()
                cert_type = tls_service.get_certificate_type(request)
            except CertAuthenticationException as e:
                return {"error": str(e)}, 403

            if cert_type not in certs and CertAuthentications.AUTH_ALL not in certs:
                return {"error": "No correct client certificate provided"}, 403

            return func(request, *args, **kwargs)

        return wrapper

    return decorator


