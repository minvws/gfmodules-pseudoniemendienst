# Log events

<!-- markdownlint-disable MD013 -->

Generated from `app.logging.events:Log` by `gfmodules.logging.event_overview`.
Do not edit by hand.

Each stream lists the events that reach it and the fields they carry there besides the context fields.
*any* means the event has no allow-list, so every field it is logged with reaches the stream.
*none* means the event carries only the context fields there.

## Context fields

Every event carries these on every stream, whenever the request context holds a value for them.

- `request_id`
- `ip`
- `user_agent`
- `client_trace_id`
- `correlation_id`
- `endpoint`
- `method`
- `scope`

## Stream `app`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `AUTHORIZATION_DENIED` | 200402 | WARNING | `handelende_oin`, `namens_oin`, `doel_oin`, `requested_operation` |
| `PSEUDONYM_REVERSIBLE_CREATED` | 220400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `domein`, `sleutel_versie` |
| `PSEUDONYM_IRREVERSIBLE_CREATED` | 220401 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `domein`, `sleutel_versie` |
| `PSEUDONYM_IRREVERSIBLE_DUAL_CREATED` | 220402 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `domein`, `sleutel_versie_oud`, `sleutel_versie_actueel` |
| `PSEUDONYM_CREATE_FAILED` | 220403 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `PERSONAL_ID_VALIDATION_FAILED` | 220404 | WARNING | `handelende_oin`, `namens_oin`, `validation_error` |
| `PERSONAL_ID_EXCHANGED` | 220405 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `domein`, `sleutel_versie`, `ontvanger_pubkey_id` |
| `PERSONAL_ID_EXCHANGE_FAILED` | 220406 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY` | 220407 | WARNING | `handelende_oin`, `namens_oin`, `doel_oin` |
| `OPRF_EVAL_OK` | 210400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `oprf_secret_versie`, `ontvanger_pubkey_id` |
| `OPRF_EVAL_FAILED` | 210402 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `OPRF_REFUSED_NO_ACTIVE_PUBKEY` | 210403 | WARNING | `handelende_oin`, `namens_oin`, `doel_oin` |
| `SAML_EXCHANGE_OK` | 230400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `domein`, `saml_decrypt_key_versie`, `sleutel_versie` |
| `SAML_EXCHANGE_FAILED` | 230401 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `KEY_GENERATED` | 250400 | INFO | `key_type`, `organisatie_oin`, `domein`, `secret_id`, `sleutel_versie` |
| `KEY_ROTATION_STARTED` | 250401 | WARNING | `key_type`, `organisatie_oin`, `domein`, `oude_versie`, `nieuwe_versie` |
| `KEY_GRACE_STARTED` | 250402 | INFO | `key_type`, `organisatie_oin`, `oude_versie`, `grace_start`, `grace_eind` |
| `KEY_VERSION_DESTROYED` | 250403 | WARNING | `key_type`, `organisatie_oin`, `vernietigde_versie` |
| `DECRYPT_PUBKEY_REGISTERED` | 250404 | INFO | `organisatie_oin`, `key_algoritme`, `key_lengte`, `key_versie` |
| `DECRYPT_PUBKEY_REJECTED` | 250405 | WARNING | `organisatie_oin`, `key_algoritme`, `rejection_reason` |
| `HSM_OPERATION_FAILED` | 250406 | ERROR | `operation_type`, `error_reason`, `retry_attempt` |
| `HEALTH_UNHEALTHY` | 270400 | ERROR | `component`, `status`, `error_detail` |
| `SYS_APP_STARTED` | 270401 | INFO | `version`, `config_path`, `oauth_enabled`, `pseudoniem_api_enabled` |
| `SYS_APP_STOPPED` | 270402 | INFO | `shutdown_reason`, `last_exception_type` |
| `SYS_APP_CRASHED` | 270402 | CRITICAL | `shutdown_reason`, `last_exception_type` |
| `SYS_UNHANDLED_EXCEPTION` | 270404 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_MISSING_CORRELATION_ID` | 270407 | ERROR | `endpoint`, `method` |
| `SYS_DB_CONNECTION_FAILED` | 270403 | ERROR | `datastore`, `error_type`, `retry_attempt`, `backoff_seconds` |
| `SYS_HSM_UNREACHABLE` | 270406 | CRITICAL | `error_reason`, `retry_attempt` |
| `ACCESS_REQUEST` | 100 | INFO | `endpoint`, `method`, `status_code`, `status_code_missing`, `duration_ms`, `body`, `body_truncated` |

## Stream `siem`

| Event | Id | Level | Fields |
| --- | --- | --- | --- |
| `AUTHORIZATION_DENIED` | 200402 | WARNING | `handelende_oin`, `namens_oin`, `doel_oin`, `requested_operation` |
| `PSEUDONYM_REVERSIBLE_CREATED` | 220400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin` |
| `PSEUDONYM_IRREVERSIBLE_CREATED` | 220401 | INFO | `handelende_oin`, `namens_oin`, `doel_oin` |
| `PSEUDONYM_IRREVERSIBLE_DUAL_CREATED` | 220402 | INFO | `handelende_oin`, `namens_oin`, `doel_oin`, `sleutel_versie_oud`, `sleutel_versie_actueel` |
| `PSEUDONYM_CREATE_FAILED` | 220403 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `PERSONAL_ID_VALIDATION_FAILED` | 220404 | WARNING | `handelende_oin`, `validation_error` |
| `PERSONAL_ID_EXCHANGED` | 220405 | INFO | `handelende_oin`, `namens_oin`, `doel_oin` |
| `PERSONAL_ID_EXCHANGE_FAILED` | 220406 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY` | 220407 | WARNING | `handelende_oin`, `doel_oin` |
| `OPRF_EVAL_OK` | 210400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin` |
| `OPRF_EVAL_FAILED` | 210402 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `OPRF_REFUSED_NO_ACTIVE_PUBKEY` | 210403 | WARNING | `handelende_oin`, `doel_oin` |
| `SAML_EXCHANGE_OK` | 230400 | INFO | `handelende_oin`, `namens_oin`, `doel_oin` |
| `SAML_EXCHANGE_FAILED` | 230401 | ERROR | `handelende_oin`, `namens_oin`, `doel_oin`, `error_type` |
| `KEY_GENERATED` | 250400 | INFO | `key_type`, `organisatie_oin` |
| `KEY_ROTATION_STARTED` | 250401 | WARNING | `key_type`, `organisatie_oin`, `oude_versie`, `nieuwe_versie` |
| `KEY_GRACE_STARTED` | 250402 | INFO | `key_type`, `organisatie_oin`, `oude_versie` |
| `KEY_VERSION_DESTROYED` | 250403 | WARNING | `key_type`, `organisatie_oin`, `vernietigde_versie` |
| `DECRYPT_PUBKEY_REGISTERED` | 250404 | INFO | `organisatie_oin`, `key_algoritme` |
| `DECRYPT_PUBKEY_REJECTED` | 250405 | WARNING | `organisatie_oin`, `key_algoritme`, `rejection_reason` |
| `HSM_OPERATION_FAILED` | 250406 | ERROR | `operation_type`, `error_reason` |
| `HEALTH_UNHEALTHY` | 270400 | ERROR | `component`, `status` |
| `SYS_APP_STOPPED` | 270402 | INFO | `shutdown_reason` |
| `SYS_APP_CRASHED` | 270402 | CRITICAL | `shutdown_reason` |
| `SYS_UNHANDLED_EXCEPTION` | 270404 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_DB_CONNECTION_FAILED` | 270403 | ERROR | `datastore`, `error_type` |
| `SYS_HSM_UNREACHABLE` | 270406 | CRITICAL | `error_reason` |
