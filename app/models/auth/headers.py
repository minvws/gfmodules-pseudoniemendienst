from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field
from app.models.oin import Oin


AUTH_HEADER_X_GF_OIN: Final[str] = "x-gf-oin"
AUTH_HEADER_X_GF_AUDIENCE: Final[str] = "x-gf-audience"
AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT: Final[str] = "x-forwarded-tls-client-cert"


class AuthHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    oin: Annotated[
        Oin,
        Field(
            alias=AUTH_HEADER_X_GF_OIN,
            description=(
                "OIN of the calling organization as provided by the trusted "
                "proxy in production; can be provided directly in local "
                "development/testing."
            ),
        ),
    ]
    audience: Annotated[
        str,
        Field(
            alias=AUTH_HEADER_X_GF_AUDIENCE,
            description=(
                "Audience of this PRS service as provided by the trusted proxy "
                "in production; can be provided directly in local "
                "development/testing."
            ),
        ),
    ]


class MtlsHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    forwarded_tls_client_cert: Annotated[
        str,
        Field(
            alias=AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT,
            description=(
                "Client TLS certificate as provided by the trusted proxy in production; "
                "can be provided directly in local development/testing."
            ),
        ),
    ]

    
