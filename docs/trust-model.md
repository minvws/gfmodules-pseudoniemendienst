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
                              │    x-gf-sub, x-gf-act-* │
                              │    x-gf-audience        │
                              │    x-gf-scope           │
                              │ 3. strip any client-    │
                              │    supplied copies      │
                              │                        │ 4. trust headers as-is
                              │                        │ 5. check OIN exists in DB
                              │                        │ 6. authorize + act

## Headers the PRS trusts

The PRS reads the caller identity from request headers that it assumes the
OIN-verifier has set and sanitised:

| Header          | Meaning                                   | Read in |
|-----------------|-------------------------------------------|---------|
| `x-gf-sub`      | Verified OIN of the organisation on whose behalf the request is made (the token subject). All authorization decisions bind to this value. | `app/models/auth/headers.py`, `app/auth.py` |
| `x-gf-act-sub`  | Verified OIN of the acting client (the party that holds the token). Recorded in audit events as `handelende_oin`. | `app/models/auth/headers.py` |
| `x-gf-act-cn`   | Common name of the acting client's certificate | `app/models/auth/headers.py` |
| `x-gf-audience` | Intended audience; checked against a configured allowlist | `app/services/auth/header.py` |
| `x-gf-scope`    | Space-separated OAuth scopes from the validated token; enforced per route via `require_scopes` | `app/models/auth/headers.py`, `app/auth.py` |

All five headers are required; a request that lacks one, or whose `x-gf-scope`
holds no scope this service knows, is rejected with `403` before any route runs.
`x-gf-audience` is validated against `authorization_headers.expected_audiences`
from configuration. The OIN values themselves are **taken as-is** — their
authenticity is the OIN-verifier's responsibility, not the PRS's.

## Deployment invariants

Because the PRS trusts these headers without verifying them, the following MUST
hold in any deployment. If any of them is violated, a client can impersonate an
arbitrary organisation and the PRS has no way to detect it.

- **MUST** — The PRS is never directly reachable by clients. All traffic transits
  the OIN-verifier. There is no network path that reaches the PRS while bypassing
  the verifier.
- **MUST** — The OIN-verifier strips or overwrites any client-supplied
  `x-gf-*` headers on every inbound request, so a client can never pre-set
  them. (This is the classic failure mode of trusted-header architectures — the
  proxy setting the header is not enough; it must also remove the incoming one.)
- **SHOULD** — The hop between the OIN-verifier and the PRS is itself
  authenticated (network isolation, mutual TLS, or a shared secret), so that the
  PRS *fails closed* if a request somehow reaches it without passing through the
  verifier.

## What the OIN-verifier does NOT solve: authorization

The OIN-verifier guarantees the *authenticity* of `x-gf-sub` ("the caller really
acts for OIN X"). It does **not** guarantee *authorization* ("OIN X is allowed to
act on OIN Y's resources"). Authorization is entirely the PRS's responsibility and
must be enforced in the PRS code.

The correct pattern is to bind every action to the **verified header identity**,
not to an OIN supplied in the request body or path. The administration
endpoints therefore take no organisation from the request at all: the services
load the caller's organisation by `auth_ctx.claims.organization_id` and only
operate on that organisation's own keys and key versions. A key or key version
id that belongs to another organisation is simply not found.

The one place where a request names another organisation is `/oprf/eval`, which
carries the recipient in its body. That is an intended cross-organisation
operation and is authorized separately: the caller must be allowed to *request*
OPRF pseudonyms and the recipient must be allowed to *receive* them, both
administrative flags on the organisation record. The caller is not the one who
can decrypt the result; the response is encrypted to the recipient's registered
key.

Any new endpoint that takes an OIN from the request body/path and acts on it
**without** either comparing it to `x-gf-sub` or authorizing the
cross-organisation operation explicitly is an authorization gap that no
upstream proxy can close — a caller authenticated as OIN X could operate on
OIN Y's data by simply naming Y in the request.

## Development without a proxy

There is no bypass in the PRS itself. For local development without an
OIN-verifier, send the `x-gf-*` headers yourself; the README describes the
headers and the Swagger input fields for them. This only works because a
development instance is not reachable by anyone else — the deployment
invariants above still apply to every deployed environment.
