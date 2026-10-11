from collections.abc import Iterator
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, Literal

from ansible.errors import AnsibleFilterError
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

# Helper functions


def _to_plain(value: Any) -> Any:
    """Recursively convert Ansible containers/strings into plain Python types."""
    if isinstance(value, dict):
        return {str(k): _to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain(v) for v in value]
    if isinstance(value, str):
        return str(value)
    return value


def _check_ip(value: str) -> str:
    """Check ip address. Raises an Error if value is not the right format."""
    ip_address(value)
    return value


def _iter_users(config: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (db, user, user_config) for every user in a validated config."""
    for db, db_config in config.items():
        for user, user_config in db_config["users"].items():
            yield db, user, user_config


def _iter_user_addresses(config: dict[str, Any]) -> Iterator[tuple[str, str, str]]:
    """Yield (db, user, address); users without addresses yield nothing."""
    for db, user, user_config in _iter_users(config):
        addresses = user_config.get("addresses") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        for address in addresses:
            yield db, user, address


def _format_errors(exc: ValidationError) -> str:
    """Error formatting helper function."""
    return "\n  - ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
        for err in exc.errors()
    )


# Configuration validation models

IPAddress = Annotated[str, AfterValidator(_check_ip)]


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["intern", "extern"] = "extern"


class PermissionProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_database: list[Literal["CONNECT", "CREATE", "TEMPORARY", "ALL"]] = []
    on_schema: list[Literal["USAGE", "CREATE", "ALL"]] = []
    on_tables: list[
        Literal[
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
            "ALL",
        ]
    ] = []
    on_sequences: list[Literal["USAGE", "SELECT", "UPDATE", "ALL"]] = []


class DatabaseUserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permissions: str
    owner: StrictBool = False
    local: StrictBool = False
    addresses: Annotated[list[IPAddress], Field(min_length=1)] | None = None
    comment: str | None = None

    @field_validator("permissions")
    @classmethod
    def _known_profile(cls, value: str, info: ValidationInfo) -> str:
        profiles = (info.context or {}).get("profiles")
        if profiles is not None and value not in profiles:
            raise ValueError(
                f"unknown permission profile {value!r}, expected one of {sorted(profiles)}"
            )
        return value

    @field_validator("addresses", mode="before")
    @classmethod
    def _addresses_to_list(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [str(value)]
        return value

    @model_validator(mode="after")
    def _needs_access(self):
        if not self.local and not self.addresses:
            raise ValueError("set `local: true` and/or at least one address")
        return self


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: Annotated[dict[str, DatabaseUserConfig], Field(min_length=1)]

    @model_validator(mode="after")
    def _single_owner(self):
        if len([e for e in self.users.values() if e.owner]) > 1:
            raise ValueError("A database cannot have multiple owners")
        return self


# Define adapters for validations

_USER_ADAPTER = TypeAdapter(Annotated[dict[str, UserConfig], Field(min_length=1)])
_PROFILES_ADAPTER = TypeAdapter(
    Annotated[dict[str, PermissionProfile], Field(min_length=1)]
)
_CONFIG_ADAPTER = TypeAdapter(Annotated[dict[str, DatabaseConfig], Field(min_length=1)])

# Jinja filters

## Jinja validation filters


def validate_users(users: Any) -> dict[str, Any]:
    plain = _to_plain(users)
    try:
        _USER_ADAPTER.validate_python(plain)
    except ValidationError as exc:
        raise AnsibleFilterError(
            "Invalid postgresql_users_config:\n  - " + _format_errors(exc)
        ) from None
    return plain


def validate_profiles(profiles: Any) -> dict[str, Any]:
    plain = _to_plain(profiles)
    try:
        _PROFILES_ADAPTER.validate_python(plain)
    except ValidationError as exc:
        raise AnsibleFilterError(
            "Invalid postgresql_permission_profiles:\n  - " + _format_errors(exc)
        ) from None
    return plain


def validate_config(config: Any, profiles: Any) -> dict[str, Any]:
    profiles = validate_profiles(profiles)
    plain = _to_plain(config)
    try:
        _CONFIG_ADAPTER.validate_python(plain, context={"profiles": profiles})
    except ValidationError as exc:
        raise AnsibleFilterError(
            "Invalid postgresql_databases_config:\n  - " + _format_errors(exc)
        ) from None
    return plain


## Jinja parsing filters


def to_ipset(config: dict[str, Any]) -> list[str]:
    addresses = {
        str(ip_address(address)) for _, _, address in _iter_user_addresses(config)
    }
    return sorted(addresses, key=ip_address)


def to_pg_hba(config: dict[str, Any]) -> list[dict[str, str]]:
    local_entries = [
        {"contype": "local", "databases": db, "users": user}
        for db, user, user_config in _iter_users(config)
        if user_config.get("local", False)
    ]
    host_entries = [
        {
            "contype": "host",
            "databases": db,
            "users": user,
            "address": str(ip_network(address)),
        }
        for db, user, address in _iter_user_addresses(config)
    ]
    return local_entries + host_entries


# Jinja filter declaration


class FilterModule:
    def filters(self):
        return {
            "to_ipset": to_ipset,
            "to_pg_hba": to_pg_hba,
            "validate_config": validate_config,
            "validate_profiles": validate_profiles,
            "validate_users": validate_users,
        }
