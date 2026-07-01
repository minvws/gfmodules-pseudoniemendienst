# Trust model

This document describes how the Pseudoniemendienst (PRS) establishes *who* is
calling it, and — just as important — what it deliberately does **not** do
itself. Read this before deploying the PRS anywhere it can receive traffic.

## Summary

The PRS does **not** authenticate callers on its own. It has no independent
source of truth for organisation identities and performs **no cryptographic
verification** of the caller (no bearer-token signature check, no in-process
mTLS handshake termination).

Instead, caller authentication is delegated to a separate upstream system — the
**OIN-verifier** — which sits in front of the PRS as a reverse proxy. The
OIN-verifier authenticates the caller and injects the caller's verified identity
into the request as HTTP headers. The PRS trusts those headers.

This is an intentional separation of concerns:

    OIN-verifier   = authentication authority   ("is the caller really OIN X?")
    PRS            = policy enforcement point    ("may OIN X do this, and do it")

The PRS only checks whether the supplied OIN **exists** in its own database; it
does not, and cannot, re-verify that the OIN is authentic.

## Request flow

    ┌──────────┐        ┌──────────────┐        ┌──────────────┐
    │  Client  │──mTLS──▶│ OIN-verifier │──────▶│     PRS      │
    │ (org)    │        │  (proxy)     │        │ (this app)   │
    └──────────┘        └──────────────┘        └──────────────┘
                              │                        │
                              │ 1. authenticate caller │
                              │ 2. set trusted headers  │
                              │    x-gf-oin             │
                              │    x-gf-audience        │
                              │ 3. strip any client-    │
                              │    supplied copies      │
                              │                        │ 4. trust headers as-is
                              │                        │ 5. check OIN exists in DB
                              │                        │ 6. authorize + act

## Headers the PRS trusts

The PRS reads the caller identity from request headers that it assumes the
OIN-verifier has set and sanitised:

| Header                        | Meaning                                   | Read in |
|-------------------------------|-------------------------------------------|---------|
| `x-gf-oin`                    | Verified OIN of the calling organisation  | `app/models/auth/headers.py`, `app/auth.py` |
| `x-gf-audience`               | Intended audience; checked against a configured allowlist | `app/services/auth/header.py` |
| `X-Forwarded-Tls-Client-Cert` | The caller's client certificate (used to derive the source OIN for some endpoints) | `app/services/mtls_service.py` |

`x-gf-audience` is validated against `authorization_headers.expected_audiences`
from configuration. The `x-gf-oin` value itself is **taken as-is** — its
authenticity is the OIN-verifier's responsibility, not the PRS's.

## Deployment invariants

Because the PRS trusts these headers without verifying them, the following MUST
hold in any deployment. If any of them is violated, a client can impersonate an
arbitrary organisation and the PRS has no way to detect it.

- **MUST** — The PRS is never directly reachable by clients. All traffic transits
  the OIN-verifier. There is no network path that reaches the PRS while bypassing
  the verifier.
- **MUST** — The OIN-verifier strips or overwrites any client-supplied
  `x-gf-oin`, `x-gf-audience`, and `X-Forwarded-Tls-Client-Cert` headers on every
  inbound request, so a client can never pre-set them. (This is the classic
  failure mode of trusted-header architectures — the proxy setting the header is
  not enough; it must also remove the incoming one.)
- **SHOULD** — The hop between the OIN-verifier and the PRS is itself
  authenticated (network isolation, mutual TLS, or a shared secret), so that the
  PRS *fails closed* if a request somehow reaches it without passing through the
  verifier.

## What the OIN-verifier does NOT solve: authorization

The OIN-verifier guarantees the *authenticity* of `x-gf-oin` ("the caller really
is OIN X"). It does **not** guarantee *authorization* ("OIN X is allowed to act
on OIN Y's resources"). Authorization is entirely the PRS's responsibility and
must be enforced in the PRS code.

The correct pattern is to bind every action to the **verified header identity**,
not to an OIN supplied in the request body or path. For example, the key
update/delete endpoints compare the resource owner against the verified caller:

    if entry.organization.oin != auth_ctx.claims.oin.value:
        raise HTTPException(status_code=403)

Endpoints that instead take an OIN from the request body/path and act on it
**without** comparing it to `x-gf-oin` are an authorization gap that no upstream
proxy can close — a caller authenticated as OIN X can operate on OIN Y's data by
simply naming Y in the request. Such endpoints should be reviewed and made to
enforce the same "target OIN must match the verified caller" rule (except where a
cross-organisation operation is explicitly intended and separately authorized).

## Development bypass

For local development without a proxy, `development.override_mtls_cert` can be set to a
certificate file on disk. When set, `MtlsService` uses that certificate instead
of reading it from the request header. This bypass is for development only and
must never be configured in a deployed environment.

When a request also does not include an `x-gf-oin` header in local/developer
setups, set `development.override_authenticated_oin` to an OIN to continue authenticating as
that organization while still requiring the rest of the auth context (in
particular audience validation) to come from headers.
