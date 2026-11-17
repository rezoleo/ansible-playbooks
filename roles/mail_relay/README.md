# Mail relay

Configures Postfix so that local mail (cron, unattended-upgrades, `sendmail`, SMTP on `127.0.0.1:25`) is relayed through
the mail server (`roles/stalwart`). Applied to every host outside `[mail]`, after the mail server.

- Every mail leaves as `<mail_relay_name>@<mail_relay_domain>` (the hostname of the server and the relay domain of the
  mail server), whatever its sender.
- Mail to local users (for example `root`) goes to `mail_relay_root_recipient`, by default `postmaster@` the main domain
  of the
  mail server (a group, see roles/stalwart).
- The app password is created on the first run and kept in Vault
  (`<stalwart_app_password_vault_path>/<mail_relay_name>`, see `roles/stalwart_app_password`), it only works from
  `mail_relay_ip`.
