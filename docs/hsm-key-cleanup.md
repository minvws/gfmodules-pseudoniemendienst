# Expired HSM key cleanup

HSM key versions are stored in the `hsm_key_version` table with an optional
`until_dt` (end date). When a version's `until_dt` is in the past it is no longer
used for [OPRF evaluation](./oprf-eval-flow.md), but the key still physically
exists in the HSM. A standalone cleanup program removes those expired keys.

## What it does

For every key version that has expired (`until_dt` set and in the past) and is
not yet marked `removed`, the program:

1. Destroys the corresponding key in the HSM via
   `POST {hsm_url}/hsm/{module}/{slot}/destroy` with the key's label
   (`oin-<oin>-v<version>` — the same label used during evaluation).
2. Marks the version as `removed` in the database.

If the HSM call fails for a version, that version is left untouched so the next
run retries it. When the HSM is not configured (`oprf.hsm_url` unset) the program
does nothing and exits successfully.

## Running it

It is a one-shot program (it runs once and exits) meant to be scheduled by a
regular system cron job:

```sh
python3 -m app.cleanup
# or, via the Makefile:
make cleanup
```

Exit code `0` means success, `1` means the run failed (see the logs).

### Example crontab

```cron
# Every night at 03:00, remove expired HSM keys
0 3 * * * cd /path/to/gfmodules-pseudoniemendienst && \
  FASTAPI_CONFIG_PATH=./app.conf python3 -m app.cleanup >> /var/log/prs-hsm-cleanup.log 2>&1
```
