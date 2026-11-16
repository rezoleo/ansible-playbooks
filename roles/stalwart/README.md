# Stalwart

Installs the [Stalwart](https://stalw.art) mail server on `yam`: pinned binary + systemd unit,
data in PostgreSQL (`pg.rezoleo.fr`), mails on the local disk, TLS certificate from the `vault_agent` role.

```sh
just playbook-deploy-infra --limit yam
```

## How the configuration works

Stalwart only keeps the data store in `/etc/stalwart/config.json`. Everything else (domains, listeners, certificate,
SSO, mailing lists...) lives in the database and is described by `/etc/stalwart/plan.ndjson`, applied with
`stalwart-cli apply` on the running server with the API key of `_ansible`, then the service is restarted
(listeners only change on restart). The plan is idempotent and can be applied by hand with the same command.

**What is in this role is changed in git only**, never in the web UI: domains, listeners, certificate, SSO, admins
and mailing lists. Most objects are upserted, so a change made by hand stays until the plan sets the same field again,
silently. Mailing lists are reconciled: a list created in the web UI is deleted by the next deployment. The web UI
is for the rest (app passwords, reports, logs, queues). After a database wipe, delete `/etc/stalwart/plan.ndjson`
so that the next run applies the whole plan again.

## Before the first run (manual)

- Create the `stalwart` database and user on `pg.rezoleo.fr`.
- Vault: `databases/stalwart@pg.rezoleo.fr` (key `password`), `services/stalwart` (keys `dkim_rsa` and `dkim_ed25519`,
  PEM private keys shared by all the domains, e.g. `openssl genpkey -algorithm ed25519`). The role adds `api_key`.
- Zitadel, in one project (its ID goes in `stalwart_oidc_accepted_audiences`):
  - a public web application (PKCE) for the web UI, its client ID goes in `stalwart_oidc_web_client_id`,
  - machine users for the apps that send mail, with the access token type set to **JWT**.
- Add `yam` to the `[mail]` group of the inventory (see `hosts.example`).

## API key of the role

The role applies the plan as `_ansible@rezoleo.fr`, an internal administrator account with no password, whose API key
only works from `127.0.0.1`. It keeps the mail permissions of a user: an account cannot grant permissions it lacks,
so without them it could not create accounts. When Vault has no `api_key` (first install, or delete it to get a new key), the role creates the key and
stores it in Vault: internal accounts only accept a password while OIDC is off, so the role switches to the internal
directory for about a minute (SSO logins fail, mail keeps flowing), then the plan switches it back.

If the key no longer works (401/403), delete `api_key` in Vault and run the playbook.

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
  `openid profile email urn:zitadel:iam:org:project:id:<project ID>:aud`. Without `profile`, Stalwart cannot find the
  username and rejects the token (535).
- Stalwart's internal accounts (password, app passwords) **cannot** sign in while the OIDC directory is active (tested
  with v1.1.0). API keys and the recovery administrator still work.
