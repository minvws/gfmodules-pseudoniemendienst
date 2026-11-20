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
| `AUTHORIZATION_DENIED` | 200402 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `requested_operation` |
| `PSEUDONYM_REVERSIBLE_CREATED` | 220400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `domain`, `key_version` |
| `PSEUDONYM_IRREVERSIBLE_CREATED` | 220401 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `domain`, `key_version` |
| `PSEUDONYM_IRREVERSIBLE_DUAL_CREATED` | 220402 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `domain`, `previous_key_version`, `current_key_version` |
| `PSEUDONYM_CREATE_FAILED` | 220403 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `PERSONAL_ID_VALIDATION_FAILED` | 220404 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `validation_error` |
| `EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY` | 220407 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `PERSONAL_ID_EXCHANGED` | 240400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `source_artifact_type`, `artifact_version`, `key_version`, `domain`, `recipient_pubkey_id` |
| `PERSONAL_ID_EXCHANGE_REFUSED` | 240401 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `missing_flag` |
| `PERSONAL_ID_EXCHANGE_FAILED` | 240402 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type`, `artifact_version` |
| `PERSONAL_ID_EXCHANGED_FROM_GRACE_VERSION` | 240403 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `artifact_version`, `key_version` |
| `OPRF_EVAL_OK` | 210400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `oprf_secret_version`, `previous_oprf_secret_version`, `recipient_pubkey_id` |
| `OPRF_EVAL_FAILED` | 210402 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `OPRF_REFUSED_NO_ACTIVE_PUBKEY` | 210403 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `SAML_EXCHANGE_OK` | 230400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `domain`, `saml_decrypt_key_version`, `key_version` |
| `SAML_EXCHANGE_FAILED` | 230401 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `KEY_GENERATED` | 250400 | INFO | `key_type`, `organization_identifier`, `domain`, `secret_id`, `key_version` |
| `KEY_ROTATION_STARTED` | 250401 | WARNING | `key_type`, `organization_identifier`, `domain`, `previous_version`, `new_version` |
| `KEY_GRACE_STARTED` | 250402 | INFO | `key_type`, `organization_identifier`, `previous_version`, `grace_start`, `grace_end` |
| `KEY_VERSION_DESTROYED` | 250403 | WARNING | `key_type`, `organization_identifier`, `destroyed_version` |
| `DECRYPT_PUBKEY_REGISTERED` | 250404 | INFO | `organization_identifier`, `key_algorithm`, `key_length`, `key_version` |
| `DECRYPT_PUBKEY_REJECTED` | 250405 | WARNING | `organization_identifier`, `key_algorithm`, `rejection_reason` |
| `HSM_OPERATION_FAILED` | 250406 | ERROR | `operation_type`, `error_reason`, `retry_attempt` |
| `HEALTH_UNHEALTHY` | 270400 | ERROR | `component`, `status`, `error_detail` |
| `SYS_APP_STARTED` | 270401 | INFO | `version`, `config_path`, `oauth_enabled`, `pseudonym_api_enabled` |
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
| `AUTHORIZATION_DENIED` | 200402 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `requested_operation` |
| `PSEUDONYM_REVERSIBLE_CREATED` | 220400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `PSEUDONYM_IRREVERSIBLE_CREATED` | 220401 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `PSEUDONYM_IRREVERSIBLE_DUAL_CREATED` | 220402 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `previous_key_version`, `current_key_version` |
| `PSEUDONYM_CREATE_FAILED` | 220403 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `PERSONAL_ID_VALIDATION_FAILED` | 220404 | WARNING | `acting_organization_identifier`, `validation_error` |
| `EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY` | 220407 | WARNING | `acting_organization_identifier`, `recipient_organization_identifier` |
| `PERSONAL_ID_EXCHANGED` | 240400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `source_artifact_type` |
| `PERSONAL_ID_EXCHANGE_REFUSED` | 240401 | WARNING | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `missing_flag` |
| `PERSONAL_ID_EXCHANGE_FAILED` | 240402 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `PERSONAL_ID_EXCHANGED_FROM_GRACE_VERSION` | 240403 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `artifact_version` |
| `OPRF_EVAL_OK` | 210400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `OPRF_EVAL_FAILED` | 210402 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `OPRF_REFUSED_NO_ACTIVE_PUBKEY` | 210403 | WARNING | `acting_organization_identifier`, `recipient_organization_identifier` |
| `SAML_EXCHANGE_OK` | 230400 | INFO | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier` |
| `SAML_EXCHANGE_FAILED` | 230401 | ERROR | `acting_organization_identifier`, `represented_organization_identifier`, `recipient_organization_identifier`, `error_type` |
| `KEY_GENERATED` | 250400 | INFO | `key_type`, `organization_identifier` |
| `KEY_ROTATION_STARTED` | 250401 | WARNING | `key_type`, `organization_identifier`, `previous_version`, `new_version` |
| `KEY_GRACE_STARTED` | 250402 | INFO | `key_type`, `organization_identifier`, `previous_version` |
| `KEY_VERSION_DESTROYED` | 250403 | WARNING | `key_type`, `organization_identifier`, `destroyed_version` |
| `DECRYPT_PUBKEY_REGISTERED` | 250404 | INFO | `organization_identifier`, `key_algorithm` |
| `DECRYPT_PUBKEY_REJECTED` | 250405 | WARNING | `organization_identifier`, `key_algorithm`, `rejection_reason` |
| `HSM_OPERATION_FAILED` | 250406 | ERROR | `operation_type`, `error_reason` |
| `HEALTH_UNHEALTHY` | 270400 | ERROR | `component`, `status` |
| `SYS_APP_STOPPED` | 270402 | INFO | `shutdown_reason` |
| `SYS_APP_CRASHED` | 270402 | CRITICAL | `shutdown_reason` |
| `SYS_UNHANDLED_EXCEPTION` | 270404 | ERROR | `exception_type`, `endpoint`, `method` |
| `SYS_DB_CONNECTION_FAILED` | 270403 | ERROR | `datastore`, `error_type` |
| `SYS_HSM_UNREACHABLE` | 270406 | CRITICAL | `error_reason` |
