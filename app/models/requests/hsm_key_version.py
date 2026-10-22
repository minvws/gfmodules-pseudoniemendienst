from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.utils.datetime import now_utc


class HsmKeyVersionRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "x-temporal-constraints": [
                "from_dt may lie in the past; when omitted the server uses the current UTC timestamp",
                "until_dt must be later than now and later than from_dt",
                "timezone offset is required for from_dt and until_dt (RFC3339 date-time format)",
            ],
            "x-supported-timezones": "Any RFC3339 timezone offset (for example: +01:00, -05:00, or Z)",
            "examples": [
                {
                    "from_dt": "2026-01-01T00:00:00+02:00",
                    "until_dt": "2027-01-01T00:00:00+01:00",
                },
                {
                    "from_dt": "2026-01-01T00:00:00Z",
                    "until_dt": None,
                },
            ],
        },
        extra="forbid",
    )

    from_dt: datetime | None = Field(
        default=None,
        description=(
            "Start of the key validity window as an ISO-8601 datetime. May lie in "
            "the past; if omitted, the server sets it to now."
            " Values must include an explicit timezone offset (RFC3339 date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2026-01-01T00:00:00+02:00",
                "2026-01-01T00:00:00Z",
            ]
        },
    )
    until_dt: datetime | None = Field(
        default=None,
        description=(
            "End of the key validity window as an ISO-8601 datetime. If provided, "
            "it must be later than the current UTC time and "
            "later than `from_dt`. An explicit timezone offset is required (RFC3339"
            " date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2027-01-01T00:00:00+01:00",
                "2027-01-01T00:00:00Z",
                None,
            ]
        },
    )

    @field_validator("from_dt", "until_dt")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("datetime values must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_temporal_window(self) -> "HsmKeyVersionRequest":
        now = now_utc()

        if self.until_dt and self.until_dt <= now:
            raise ValueError("until_dt must be later than now")

        if self.until_dt and self.from_dt and self.until_dt <= self.from_dt:
            raise ValueError("until_dt must be later than from_dt")

        return self


class HsmKeyVersionUpdateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "x-temporal-constraints": [
                "until_dt must be later than now and include an explicit timezone offset",
            ],
            "examples": [
                {"until_dt": "2027-01-01T00:00:00+03:00"},
                {"until_dt": None},
            ],
        },
    )

    until_dt: datetime | None = Field(
        default=None,
        description=(
            "New end datetime for the key version as an ISO-8601 timestamp, or null "
            "to clear the existing value. If provided, it must be later than the current "
            "UTC time and include an explicit timezone offset (RFC3339 date-time)."
        ),
        json_schema_extra={
            "examples": [
                "2027-01-01T00:00:00+03:00",
                "2027-01-01T00:00:00Z",
                None,
            ]
        },
    )

    @field_validator("until_dt")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("datetime values must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_temporal_window(self) -> "HsmKeyVersionUpdateRequest":
        if self.until_dt and self.until_dt <= now_utc():
            raise ValueError("until_dt must be later than now")

        return self
