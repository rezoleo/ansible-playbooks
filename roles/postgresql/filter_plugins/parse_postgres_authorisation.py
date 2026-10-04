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
    field_validator,
    model_validator,
)

# Helper functions

def _normalize_addresses(value: Any) -> Any:
    """Turn Ansible string subclasses into plain str and wrap a single value in a list."""
    if isinstance(value, str):
        return [str(value)]
    if isinstance(value, (list, tuple)):
        return [str(v) if isinstance(v, str) else v for v in value]
    return value

def _check_ip(value: str) -> str:
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

# Configuration models

IPAddress = Annotated[str, AfterValidator(_check_ip)]

class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permissions: Literal["all", "read-only"]
    local: StrictBool = False
    addresses: Annotated[list[IPAddress], Field(min_length=1)] | None = None
    comment: str | None = None

    @field_validator("addresses", mode="before")
    @classmethod
    def _addresses_to_list(cls, value: Any) -> Any:
        return _normalize_addresses(value)

    @model_validator(mode="after")
    def _needs_access(self):
        if not self.local and not self.addresses:
            raise ValueError("set `local: true` and/or at least one address")
        return self

class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: Annotated[dict[str, UserConfig], Field(min_length=1)]

_CONFIG_ADAPTER = TypeAdapter(Annotated[dict[str, DatabaseConfig], Field(min_length=1)])

# Jinja filters

def validate_config(config: Any) -> dict[str, Any]:
    """Return `config` unchanged if valid, otherwise raise AnsibleFilterError."""
    try:
        _CONFIG_ADAPTER.validate_python(config)
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        ]
        raise AnsibleFilterError(
            "Invalid postgresql_databases_config:\n  - " + "\n  - ".join(errors)
        ) from None

    return config


def to_ipset(config: dict[str, Any]) -> list[str]:
    addresses = {str(ip_address(address)) for _, _, address in _iter_user_addresses(config)}
    return sorted(addresses, key=ip_address)


def to_pg_hba(config: dict[str, Any]) -> list[dict[str, str]]:
    local_entries = [
        {"contype": "local", "databases": db, "users": user}
        for db, user, user_config in _iter_users(config)
        if user_config.get("local", False)
    ]
    host_entries = [
        {"contype": "host", "databases": db, "users": user, "address": str(ip_network(address))}
        for db, user, address in _iter_user_addresses(config)
    ]
    return local_entries + host_entries

class FilterModule:
    def filters(self):
        return {
            "to_ipset": to_ipset,
            "to_pg_hba": to_pg_hba,
            "validate_config": validate_config
        }
