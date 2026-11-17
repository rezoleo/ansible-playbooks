# Stalwart app password

Creates an app password on an account of the mail server (`roles/stalwart`), only valid from one IP, and keeps it in
Vault (`<stalwart_app_password_vault_path>/<name>`, keys `password` and `allowed_ip`). Runs once: the next runs read
Vault.
Sets the fact `stalwart_app_password_secret`.

```yaml
- name: Get the app password
  ansible.builtin.include_role:
    name: stalwart_app_password
  vars:
    stalwart_app_password_name: yam
    stalwart_app_password_account: _servers@rezoleo.fr
    stalwart_app_password_ip: 10.12.1.9
```

The creation runs on the mail server whatever the host: the API key of `_ansible` only works from `127.0.0.1` there.
Stalwart only shows the password once, so to revoke it delete it in the web UI (description `<name>`, on the account)
**and** its Vault secret: the next run creates a new one. Deleting only the Vault secret leaves the old one valid.
