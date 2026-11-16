# Mail relay

Configures Postfix so that local mail (cron, unattended-upgrades, `sendmail`, SMTP on `127.0.0.1:25`) is relayed through
the mail server (`roles/stalwart`). Applied to every host outside `[mail]`, after the mail server.

- Every mail leaves as `<short hostname>@servers.rezoleo.fr`, whatever its sender.
- Mail to local users (`root`...) goes to `mail_relay_root_recipient`.
- The app password is created on the first run and kept in Vault (`services/stalwart-app-passwords/<short hostname>`, see `roles/stalwart_app_password`), it only works from `mail_relay_ip`.
