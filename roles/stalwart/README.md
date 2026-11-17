# Stalwart

Installs the [Stalwart](https://stalw.art) mail server on `yam`: pinned binary + systemd unit,
data in PostgreSQL (`pg.rezoleo.fr`), mails on the local disk, TLS certificate from the `vault_agent` role.

```sh
just playbook-deploy-infra --limit yam
```

## How the configuration works

Stalwart only keeps the data store in `/etc/stalwart/config.json`. Everything else (domains, listeners, certificate,
SSO, mailing lists...) lives in the database and is described by `/etc/stalwart/plan.ndjson`, applied with
`stalwart-cli apply` on the running server with the API key of `_ansible`, then the service is restarted (listeners only
change on restart). The plan is idempotent and can be applied by hand with the same command.

**What is in this role is changed in git only**, never in the web UI: domains, listeners, certificate, SSO, admins,
groups and mailing lists. After a database wipe, delete `/etc/stalwart/plan.ndjson` so that the next run applies the
whole plan again.

## Before the first run

- Create the `stalwart_db_name` database and user on `stalwart_db_host`.
- Vault:
    - put `stalwart_database_vault_path`/`stalwart_db_name`@`stalwart_db_host` (key `password`) in Vault.
    - put `stalwart_vault_path`/`dkim_rsa` and `stalwart_vault_path`/`dkim_ed25519` (PEM private keys) in Vault.
    - PEM private keys shared by all the domains, e.g. `openssl genpkey -algorithm ed25519`. The role adds `api_key`.
- Zitadel, in one project (its ID goes in `stalwart_oidc_accepted_audiences`):
    - a public web application (PKCE) for the web UI, its client ID goes in `stalwart_oidc_web_client_id`, and
      in `stalwart_oidc_accepted_audiences` as well.
    - machine users for the apps that send mail through XOAUTH2, with the access token type set to **JWT**.
- Add the server to the `[mail]` group of the inventory and set its parameters in `host_vars/<host>.yml` (the
  commented ones in `defaults/main.yml`, the role checks them). `vars/main.yml` holds the internals.

## API key of the role

The role applies the plan as `_ansible@rezoleo.fr`, an internal administrator account with no password, whose API key
only works from `127.0.0.1`. When Vault has no `api_key` (first install, or delete it to get a new
key), the role creates the key and stores it in Vault: internal accounts only accept a password while OIDC is off, so
the role switches to the internal directory then the plan switches it back.

If the key no longer works, delete `api_key` in Vault and run the playbook.

## Authentication

All accounts live in Zitadel (`Authentication.directoryId` points to the OIDC directory):

- People sign in to the web UI (`/admin`, `/account`) through SSO.
- Mail clients and machine users authenticate with XOAUTH2/OAUTHBEARER and a Zitadel access token.
- The login name comes from `stalwart_oidc_claim_username` (+ `stalwart_oidc_username_domain` when it has no `@`).
- An account only exists in Stalwart after its first sign-in, mail sent to it before is rejected.
- The web UI needs the full address (`david@rezoleo.fr`) on its login page: the domain tells it to redirect to
  Zitadel. Zitadel only pre-fills it if it is a valid login name (`rezoleo.fr` as primary domain of the organization).
- Zitadel applications and machine users must issue **JWT** access tokens, Stalwart rejects opaque tokens.
- Machine users (apps sending mail, e.g. Zitadel's own SMTP provider): one service user per app, its username is the
  account and the only allowed sender (`<username>@rezoleo.fr`). Token: `client_credentials` grant on
  `https://sso.rezoleo.fr/oauth/v2/token` with the scopes
  `openid profile email urn:zitadel:iam:org:project:id:<project ID>:aud`.
- App passwords (created in `/account`) work for every account, e.g. for a mail client without XOAUTH2. Internal
  accounts **cannot** sign in with a password while the OIDC directory is active.

## Shared mailboxes (groups)

`stalwart_groups` creates group accounts, e.g. `contact@`: mail sent to the group lands in its own mailbox, which its
members see as a shared folder (Thunderbird: right-click the account > *Subscribe…* > `Shared Folders`).

- Members can send as the group, other accounts are refused. Members must be `@rezoleo.fr` accounts.
- Flags are shared: everyone sees that a mail was read or answered.
- Stalwart only saves a reply in the Sent folder of its author. A hook (`files/group-sent-hook.py`, service
  `stalwart-group-sent-hook`) copies every mail sent as a group over SMTP into the group's Sent Items, as
  `_groupsent@rezoleo.fr` (member of every group, app password only valid from `127.0.0.1`). A failed copy doesn't block the mail, it is logged (`journalctl -u stalwart-group-sent-hook`).
- Memberships are reconciled on every run (not by the plan): git is the source of truth, a member removed from
  `members` loses access to the group at the next run, and memberships added in the web UI are removed too.

## Mail from servers and appliances

Servers and appliances send through one internal account, `_servers@rezoleo.fr`, each one as `<name>@servers.rezoleo.fr`
(an
alias of `_servers`, the only addresses it can send from) with its own app password, only valid from its IP.

- Inventory hosts outside `[mail]`: `roles/mail_relay` (Postfix relaying to `yam.rezoleo.fr:465`), nothing to do.
- Appliances (TrueNAS, Synology...): add them to `stalwart_relay_appliances`, run the playbook, then type in their
  SMTP settings: server `yam.rezoleo.fr`, port 465 (SSL/TLS), user `_servers@rezoleo.fr`, the password from Vault
  `<stalwart_app_password_vault_path>/<name>`, sender `<name>@servers.rezoleo.fr`.
- Revoke one: delete its app password (description `<name>`) on `_servers` in the web UI **and** its Vault secret,
  the next run creates a new one. Deleting only the Vault secret leaves the old password valid.
- The price of one shared account: a compromised server can bypass its Postfix and send as any other server's
  address, or read the `_servers` mailbox (bounces, replies). Its password still only works from its own IP.
