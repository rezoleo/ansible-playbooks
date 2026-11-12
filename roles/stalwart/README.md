# Stalwart

Installs the [Stalwart](https://stalw.art) mail server on `yam` (a CT, so no containers): pinned binary + systemd unit,
data in PostgreSQL (`pg.rezoleo.fr`), mails on the local disk, TLS certificate from the `vault_agent` role.

```sh
just playbook-deploy-infra --limit yam
```

## How the configuration works

Stalwart only keeps the data store in `/etc/stalwart/config.json`. Everything else (domains, listeners, certificate,
SSO, mailing lists...) lives in the database and is described by `/etc/stalwart/plan.ndjson`, applied with
`stalwart-cli apply` while the server runs in recovery mode. The service is therefore stopped for a few seconds whenever
the plan changes. The plan is idempotent and can be applied by hand with the same command.

## Before the first run (manual)

- Create the `stalwart` database and user on `pg.rezoleo.fr`.
- Vault: `databases/stalwart@pg.rezoleo.fr` (key `password`).
- Zitadel, in one project (its ID goes in `stalwart_oidc_accepted_audiences`):
  - a public web application (PKCE) for the web UI, its client ID goes in `stalwart_oidc_web_client_id`,
  - machine users for the apps that send mail, with the access token type set to **JWT**.
- Add `yam` to the `[mail]` group of the inventory (see `hosts.example`).

## DNS and network (manual, not managed here)

- lantern: `mailtest A 141.255.147.84` while testing (spare public IP), `mail A 141.255.147.86` is already there.
- pfSense: NAT `.84` 25/465/587/993 to `10.12.1.9` for testing. For the cutover, point `.86:25` to `10.12.1.9` and add
  465/587/993 on `.86`. Rollback = point them back to `10.12.1.6`.
- SPF (`@ TXT "v=spf1 ip4:141.255.147.86 -all"`), DKIM (key shown in the Stalwart admin > Domains), DMARC (`_dmarc`).
- PTR of `141.255.147.86` must be `mail.rezoleo.fr` (ask the ISP).
- Equestria (10.12.2.2): reverse proxy of `webmail.rezoleo.fr` to `http://10.12.1.9:8080`. For now `webmail` only
  exists on the internal DNS (doublediamond), add `webmail A 141.255.147.86` on lantern to open it publicly.

## Migration

Per user, from the old server (`10.12.1.6`): `imapsync`. Not automated.

## Authentication

All accounts live in Zitadel (`Authentication.directoryId` points to the OIDC directory):

- People sign in to the web UI (`/admin`, `/account`) through SSO.
- Mail clients and machine users authenticate with XOAUTH2/OAUTHBEARER and a Zitadel access token.
- The login name comes from `stalwart_oidc_claim_username` (+ `stalwart_oidc_username_domain` when it has no `@`).
  Stalwart cannot rewrite it, so the `-` -> `.` mapping of usernames must be done in Zitadel (an Action adding a claim
  to access tokens, then point `stalwart_oidc_claim_username` to it).
- An account only exists in Stalwart after its first sign-in, mail sent to it before is rejected.
- Administrators are listed in `stalwart_admins` (sign in once through SSO first, then run the playbook).
- The web UI needs the full address (`david@rezoleo.fr`) on its login page: the domain tells it to redirect to
  Zitadel. Zitadel only pre-fills it if it is a valid login name (`rezoleo.fr` as primary domain of the organization).
- Zitadel applications and machine users must issue **JWT** access tokens, Stalwart rejects opaque tokens.
- To debug authentication, set the tracer level to `debug` in `templates/plan.ndjson.j2` and run the playbook,
  then read `journalctl -u stalwart`.
- Stalwart's internal accounts (password, app passwords) **cannot** sign in while the OIDC directory is active (tested
  with v1.1.0). The recovery administrator still works, it is how this role applies the plan.

## To test on yam

1. Sign in to the web UI with Zitadel, and give the admin role to the right people.
2. Send a mail over SMTP with XOAUTH2 using a machine user token (`client_credentials` grant).
3. ~~App password on an account created through OIDC~~: works (tested over IMAP). Apps that do not speak XOAUTH2
   get their own app password (in `/account` > Credentials), no relay needed.
