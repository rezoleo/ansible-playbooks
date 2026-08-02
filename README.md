# Ansible playbooks

## Prerequisites

On the computer running the playbooks:
  - A Python virtualenv with the [requirements](./pyproject.toml) installed
  - `figlet` and `lolcat-c` installed, to generate the ASCII art used in the MOTD banner

On the managed servers:
  - An `ansible` user account with passwordless sudo (run the
    [`create-ansible-user`](./playbooks/create-ansible-user.yml) playbook for this)

To develop on your computer:
  - A Python virtualenv with the [requirements](./pyproject.toml) installed
  - Recommended: the [`just`][just-manual] command runner, to simplify running commands (see [Usage](#usage) below)
  - Recommended: Visual Studio Code with the [`Ansible` extension][ansible-vscode-extension] (you should be prompted to install it when opening the project in VSCode)
  - Recommended : the Vault CLI [installed](https://developer.hashicorp.com/vault/install).

## Usage

A `justfile` is provided, to help you run the most common commands. Once you have [installed just][just-installation], you can run the following:
  - `just` (with no arguments): list all recipes/commands available
  - `just playbook-deploy-infra`: run the playbook (you can add any argument and they will be passed to the underlying `ansible-playbook` command)
  - `just lint`: run [ansible-lint][ansible-lint] to check the playbooks and roles for errors and bad practices
  - `just todo`: search all files for `# TODO` and `# noqa` comments (they silence linter errors)
  - `just vault <username>`: login to Vault using the `userpass` method
  - `just venv`: create a local virtualenv using the currently available Python (in [`.venv`](./venv)) and install dependencies using `pip`
  - ...and more, see `just` for the updated list

If you want to run a playbook manually, you will need to:
1. Export the Vault URL: `export VAULT_ADDR=https://<vault URL>`
2. Login to Vault: `vault login -method=userpass username=<username>` (you can use any other method)
3. Retrieve the SSH private key from Vault and save it as `id_ed25519_ansible`
4. Execute a playbook: `ansible-playbook --inventory hosts playbooks/deploy-server.yml`

## Continuous Integration (CI)

A [GitHub Actions workflow](./.github/workflows/test.yml) is run on all push and pull requests to check any alerts from [`ansible-lint`][ansible-lint].

## How to create the inventory

TODO: still useful?

## Helpful links

  - [Ansible docs][ansible-docs]
  - [List of all Ansible modules][ansible-list-of-modules]
  - [Ansible-lint][ansible-lint]

[ansible-docs]: https://docs.ansible.com/ansible/latest/index.html
[ansible-list-of-modules]: https://docs.ansible.com/ansible/latest/collections/all_plugins.html
[ansible-cmdb]: https://github.com/fboender/ansible-cmdb
[ansible-lint]: https://ansible.readthedocs.io/projects/lint/
[ansible-vscode-extension]: https://marketplace.visualstudio.com/items?itemName=redhat.ansible
[just-installation]: https://just.systems/man/en/packages.html
[just-manual]: https://just.systems/man/en/
