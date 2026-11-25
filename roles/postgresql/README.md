# PostgreSQL role

Installs and configures a PostgreSQL instance and ensures databases, users, privileges are consistent with the declarative configuration.

The configuration is the source of truth. Privileges that are no longer declared are revoked, and roles that are no longer declared are removed (their objects are handed over to the admin user first).

## Features

- Installs PostgreSQL and applies the listen address and optional tuning parameters.
- Generates `pg_hba.conf` from the base rules plus the addresses and `local` flags of the configuration.
- Creates the declared databases.
- Creates the declared users.
  - **internal users**: the password is stored in Vault, and generated and pushed there if missing.
  - **external users**: the password is generated only when the role is created and displayed once at the end of the run. It is stored nowhere else.
- Grants privileges per database according to named **permission profiles**, including default privileges so that future tables and sequences are covered.
- Revokes any privilege a declared user holds beyond what its profile allows.
- Removes roles that are not declared (and not protected), after reassigning everything they own to the admin.

## Limitations

- IP addresses only for clients (no hostnames, no CIDR ranges).
- Single schema (`public`).
- Revoking privileges from a role that owns objects removes its own access to them.
- When a user is deleted, owned objects (when applicable) are not transferred to the database owner but to the admin role.
- `PUBLIC` keeps the default `CONNECT` and `TEMPORARY` on new databases, so revoking those from a role does not remove effective access.

## Requirements

- Ansible with the collections `community.postgresql` and `community.hashi_vault`.
- The Python package `pydantic` (v2) on the Ansible controller. It is used by the role's filter plugins to validate the configuration.
- A reachable Vault with a KV v2 engine for internal users, writable by the logged user to create missing passwords. Authentication uses the usual `VAULT_ADDR` / `VAULT_TOKEN` settings.

## Quick start

Example

```yaml
- hosts: databases
  roles:
    - role: postgresql
      vars:
        postgresql_hostname: pg.example.com
        postgresql_listen_interfaces: "*"
        postgresql_vault_path: path/to/databases/secrets
        postgresql_users:
          app:   { kind: internal }
          audit: { kind: external }
        postgresql_databases_config:
          shop:
            users:
              app:
                permissions: all
                addresses: 10.0.1.10
              audit:
                permissions: read-only
                addresses: 10.0.2.20
```

## Mandatory options

These have no usable default and must be set in `group_vars` or `host_vars` for each instance.

### `postgresql_listen_interfaces`

Interfaces PostgreSQL listens on, passed to `listen_addresses`. It decides whether the server is reachable from the network. By default, this is set to `localhost` for security purposes.

```yaml
postgresql_listen_interfaces: "*localhost,10.0.0.5*"
```

### `postgresql_hostname`

Hostname of the instance, for example `pg.example.com`. It is used to build the Vault secret name of internal users.

### `postgresql_vault_path`

Vault path under which the secrets are stored. The password of an internal user is read from and written to `<postgresql_vault_path>/<user>@<postgresql_hostname>`.

### `postgresql_users`

Declares every account the role manages, with its kind. Keys are user names.

| Field  | Values                 | Meaning |
|--------|------------------------|---------|
| `kind` | `internal`, `external` | `internal`: password kept in Vault and enforced on every run. `external`: password generated once at creation and displayed at the end of the run, then never checked again. |

```yaml
postgresql_users:
  usera: { kind: internal }
  userd: { kind: external }
```

A user must be declared here to be used in `postgresql_databases_config`.

### `postgresql_databases_config`

Maps each database to the users allowed on it. Databases listed here are created.

| Field (per user)      | Required | Description |
|-----------------------|----------|-------------|
| `permissions`         | yes      | Name of a profile from `postgresql_permission_profiles` (`all` and `read-only` are provided by default, see [Advanced options](#advanced-options) for additional information). |
| `addresses`           | no       | One IP address or a list of them. Each produces a `host` line in `pg_hba.conf` (as `/32` or `/128`). Hostnames and CIDR ranges are not accepted. |
| `local`               | no       | `true` adds a `local` (Unix socket) line for the user. Defaults to `false`. |
| `comment`             | no       | Free text, for documentation only. |
| `owner`               | no       | See [Database ownership](#database-ownership). |

A user needs `addresses`, `local: true`, or both to be able to connect.

```yaml
postgresql_databases_config:
  dba:
    users:
      usera:
        permissions: all
        addresses:
          - 10.12.0.56
          - 10.12.2.15
        comment: Application account
      userb:
        permissions: read-only
        addresses: 10.12.0.1
  dbb:
    users:
      userg:
        permissions: read-only
        local: true
```

The configuration is validated before anything is changed. All errors are reported at once.

## Advanced options

These have sensible defaults. Override them only when needed.

### `postgresql_permission_profiles`

Named sets of privileges that users reference through `permissions`. You can add your own profiles; any key can then be used in `postgresql_databases_config`.

Default:

```yaml
postgresql_permission_profiles:
  all:
    database: [ALL]
    schema_: [ALL]
    tables: [ALL]
    sequences: [ALL]
  read-only:
    database: [CONNECT]
    schema_: [USAGE]
    tables: [SELECT]
    sequences: [SELECT]
```

Allowed privileges per object type:

| Key            | Allowed values |
|----------------|----------------|
| `database`  | `CONNECT`, `CREATE`, `TEMPORARY`, `ALL` |
| `schema_`    | `USAGE`, `CREATE`, `ALL` |
| `tables`    | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, `MAINTAIN`, `ALL` |
| `sequences` | `USAGE`, `SELECT`, `UPDATE`, `ALL` |

`ALL` expands to every concrete privilege of that type. Empty or omitted lists grant nothing. Example of an additional profile:

```yaml
postgresql_permission_profiles:
  read-write:
    database: [CONNECT]
    schema_: [USAGE]
    tables: [SELECT, INSERT, UPDATE, DELETE]
    sequences: [USAGE, SELECT, UPDATE]
```

Defining `postgresql_permission_profiles` replaces the whole default mapping, so repeat `all` and `read-only` if you still use them.

### `postgresql_hba_base_rules`

Rules always written to `pg_hba.conf`, before the rules generated from `postgresql_databases_config`.

```yaml
postgresql_hba_base_rules:
  - contype: local
    databases: all
    users: postgres
    method: peer
```

### `postgresql_protected_roles`

Roles that must never be removed even though they are not in `postgresql_users`. Default: `[]`. Add monitoring, backup or application roles managed outside this role.

```yaml
postgresql_protected_roles: [monitoring, backup]
```

### `postgresql_pgtune`

Optional tuning parameters written to the PostgreSQL configuration. Values can be generated at <https://pgtune.leopard.in.ua/>. Not set by default.

```yaml
postgresql_pgtune:
  max_connections: "200"
  shared_buffers: "256GB"
  effective_cache_size: "768GB"
  maintenance_work_mem: "8GB"
  checkpoint_completion_target: "0.9"
  wal_buffers: "16MB"
  default_statistics_target: "100"
  random_page_cost: "1.1"
  effective_io_concurrency: "200"
  work_mem: "1161499kB"
  huge_pages: "try"
  jit: "off"
  wal_compression: "lz4"
  autovacuum_work_mem: "2GB"
  min_wal_size: "1GB"
  max_wal_size: "4GB"
```

## How privileges are reconciled

On every run, for each declared user and each configured database, the role computes what the profile grants and what it does not.

- Granted privileges are applied.
- Privileges of the same type that the profile does not grant are revoked.
- A declared user that has no entry for a database gets everything revoked there.

Both operations are idempotent, so a run with no drift reports no change, and changing a profile or removing a user results in changes only for the difference.

**Future objects.** Besides existing tables and sequences, the role sets default privileges. They apply to objects created by the admin and by every user whose profile allows `CREATE` on the schema.

**Scope.** Only the `public` schema is handled. Roles that are not declared in `postgresql_users` are never touched by the privilege tasks.

## Database ownership

The role manage the ownership of databases. the `owner` key should be set to `true` for only one user for a given database.

## Removal of undeclared roles

Roles that are not in `postgresql_users` are removed, except:

- `pg_*` system roles, superusers and replication roles,
- the admin user (`postgres`),
- roles listed in `postgresql_protected_roles`.

Before a role is dropped, everything it owns is reassigned to the admin in every database that accepts connections, then its remaining privileges are removed. If the reassignment fails, the role is not dropped.

**Review `postgresql_protected_roles` before the first run.** Any other non-superuser role on the server, including those used by other applications, will be removed.

## Secrets

| User kind  | Behaviour |
|------------|-----------|
| `internal` | Read from Vault at `<postgresql_vault_path>/<user>@<postgresql_hostname>`. If missing, a password is generated and written there. The password in PostgreSQL is set from Vault on every run. |
| `external` | If the role exists, nothing is checked or changed. If it does not exist, a password is generated, set, and displayed at the end of the run. Save it then: it is not stored anywhere. |
