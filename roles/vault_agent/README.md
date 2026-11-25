# vault_agent

Deploys TLS certificates on servers from HashiCorp Vault and keeps them fresh:

* a host certificate issued by Vault PKI for this server only (short-lived, 7 days by default);
* optionally the wildcard certificate (Let's Encrypt) stored in Vault KV v2;
* the CA certificate, on every server;
* a hook system so that other roles can read the keys and get their service reloaded when a certificate changes.

## Features

* **Per-host toggles**: each host chooses the host certificate, the wildcard, both, or neither (CA only).
* **Strictly bound host certificate**: the SANs are `<hostname>.<domain>`, the host IPs and the optional `vault_agent_extra_dns_sans`. This is enforced by a per-host Vault policy (`common_name`, `ip_sans` and `alt_names` are pinned, `uri_sans` and `other_sans` are denied), not only by the agent configuration.
* **One Vault identity per host**: a single AppRole (one `role_id` / `secret_id` pair) carrying the policies of the certificates enabled on that host. Its secret_id and tokens are bound to the host IPs (`vault_agent_approle_bound_cidrs`).
* **One global wildcard policy**: read-only on the KV path, shared by every host that enables the wildcard.
* **One Vault Agent per host**: a single `vault-agent` systemd unit renders every certificate and renews it before expiry. The unit is sandboxed and keeps its state in `/var/lib/vault-agent`.
* **Least-privilege file access**: each certificate type has its own directory (`0750 root:<group>`) and key file (`0640 root:<group>`). Only members of `ssl-host-cert` / `ssl-wildcard-cert` can read the keys.
* **Reload hooks** with a declarative registration (`register_service.yml`), run by the agent on every rotation and once at the end of a play.
* **Pinned Vault package** installed from the HashiCorp apt repository, with the GPG key checked against a checksum.
* **Tags**: `vault_agent` plus `package`, `ca`, `configuration`, `identity`, `service`, `hooks`, `users`.

## Requirements

### Ansible controller

* ansible-core 2.21 (Ansible 14): the role uses register projections.
* Collections `community.hashi_vault` and `ansible.utils` (for the `ipaddr` filter used by `vault_agent_approle_bound_cidrs`).
* Python libraries `hvac` and `netaddr`.
* A Vault token with enough rights. It must be allowed to:

  | Path | Capability |
  |---|---|
  | `sys/policies/acl/*` | create, update |
  | `auth/<approle mount>/role/*` | create, update |
  | `auth/<approle mount>/role/*/role-id` | read |
  | `auth/<approle mount>/role/*/secret-id` | update |
  | `<pki mount>/roles/<pki role>` | create, update |
  | `<pki mount>/cert/ca_chain` | read |

### Vault

* A PKI secrets engine with a CA at `vault_agent_pki_mount`.
* The AppRole auth method enabled at `vault_agent_approle_mount`.
* For the wildcard: a KV v2 secret at `<vault_agent_wildcard_kv_mount>/<vault_agent_wildcard_kv_path>` holding the full chain in `fullchain` and the private key in `privkey`.
* If Vault sits behind a reverse proxy, Vault must trust its `X-Forwarded-For` header (`x_forwarded_for_authorized_addrs` on the listener). Otherwise the AppRole IP binding sees the proxy address and authentication fails.

### Variables to supply

They are commented out in `defaults/main.yml` on purpose; the role stops at its first tasks if one is missing.

| Variable | Needed on | Example |
|---|---|---|
| `vault_agent_vault_addr` | every host | `https://vault.example.com` (scheme required) |
| `vault_agent_pki_mount` | every host | `pki_int` |
| `vault_agent_domain` | hosts with a certificate | `example.com` |
| `vault_agent_wildcard_kv_path` | hosts with the wildcard | `letsencrypt/wildcard.example.com` |

## Limitations

* **Switching a host to CA only** does not stop the agent nor remove its certificates, AppRole or policies.
* When removing a role from needing certificate, the **group is not removed from the user's groups**.

## Improvements possible

* Address limitations;
* Use `x509_certificate_info` module to retrieve the CA common name instead of specifying `vault_agent_domain`.

## Usage: configuring a server

### Inventory

```yaml
vault_agent_vault_addr: https://vault.example.com
vault_agent_pki_mount: pki_int
vault_agent_domain: example.com
vault_agent_wildcard_kv_path: letsencrypt/wildcard.example.com
```

Per host, choose what is deployed:

```yaml
# host_vars/web.yml  -> host certificate + wildcard
vault_agent_wildcard_enabled: true

# host_vars/db.yml   -> host certificate only, with an extra name
vault_agent_extra_dns_sans: [pg.example.com]

# host_vars/bastion.yml -> CA only
vault_agent_host_cert_enabled: false
```

For other optional parameters, look at `defaults/main.yml`.

### What ends up on the host

| Path (defaults) | Content |
|---|---|
| `/opt/certificates/host/fullchain.pem` and `privkey.pem` | host certificate and key (`0644` / `0640 root:ssl-host-cert`) |
| `/opt/certificates/wildcard/fullchain.pem` and `privkey.pem` | wildcard certificate and key (`0644` / `0640 root:ssl-wildcard-cert`) |
| `vault_agent_ca_file` | CA chain |
| `/etc/vault-agent/` | `agent.hcl`, `role_id`, `secret_id` (`0400`), one `.ctmpl` per certificate |
| `/etc/vault-agent/hooks/<host\|wildcard>/` | reload hooks, root only |
| `/etc/systemd/system/vault-agent.service` | hardened unit |
| `/var/lib/vault-agent` | agent state (`$HOME` of the agent) |

### Operations

* Rotate the secret_id of the hosts: run with `-e vault_agent_rotate_secret_id=true`; the agent is restarted.
* Run part of the role with its tags, for example `--tags ca`.

## Usage in other roles (`register_service.yml`)

Any role whose service needs a private key, or must be reloaded when a certificate changes, declares itself with `register_service.yml`. `vault_agent` must have run earlier in the play, the service user must already exist, and the call must be made on every run.

```yaml
- name: Declare nginx to vault_agent
  ansible.builtin.include_role:
    name: vault_agent
    tasks_from: register_service.yml
  vars:
    vault_agent_service_name: nginx
    vault_agent_service_certs: [wildcard]
    vault_agent_service_user: www-data
    vault_agent_service_reload_command: systemctl try-reload-or-restart nginx
```

| Variable | Required | Meaning |
|---|---|---|
| `vault_agent_service_name` | yes | Name of the hook file. Only `A-Z a-z 0-9 _ -` (`run-parts` rule). |
| `vault_agent_service_certs` | yes | `host`, `wildcard` or both. They must be enabled on the host, otherwise the task fails. |
| `vault_agent_service_user` | no | User added to the group of each requested certificate, so it can read the keys. |
| `vault_agent_service_reload_command` | no | Command run when a requested certificate changes. Without it the role only grants file access. |

What it does:

1. Adds `vault_agent_service_user` to the groups of the requested certificates (group membership is appended, nothing else is changed).
2. Installs `/etc/vault-agent/hooks/<cert>/<vault_agent_service_name>` for each requested certificate. The agent runs every hook of a certificate (`run-parts`) whenever that certificate is rotated; a failing hook does not stop the others.
3. Registers the hook for `post_tasks.yml`, which at the end of the play **removes every hook that was not registered during that play** and **triggers each registered hook once**. A freshly added service therefore picks up its new group membership and the current certificate, once its own role has finished configuring it. These triggers are reported as unchanged.

The certificate paths are available to the calling role because `vault_agent` ran earlier in the same play, so its templates can use them:

```nginx
# templates/nginx-site.conf.j2
ssl_certificate     {{ vault_agent_wildcard_cert_dir }}/{{ vault_agent_fullchain_filename }};
ssl_certificate_key {{ vault_agent_wildcard_cert_dir }}/{{ vault_agent_privkey_filename }};
```

A database using only the host certificate (the `pg.example.com` name comes from `vault_agent_extra_dns_sans` in the host's variables):

```yaml
vars:
  vault_agent_service_name: postgresql
  vault_agent_service_certs: [host]
  vault_agent_service_user: postgres
  vault_agent_service_reload_command: systemctl try-reload-or-restart postgresql
```

A service reading both certificates sets `vault_agent_service_certs: [host, wildcard]`: its user gets both groups and it gets one hook file per certificate, but it is triggered only once at the end of the play.
