venv := ".venv"
venv_path := absolute_path(venv)
venv_bin := venv_path / "bin"
inventory := "hosts"

export VIRTUAL_ENV := absolute_path(venv_path)
export VAULT_ADDR := "https://vault.rezoleo.fr/"
export PATH := venv_bin + ":" + env('PATH')

uv_path := which("uv")
poetry_path := which("poetry")
venv_command := if uv_path != "" {
    "uv venv --prompt rezoleo-ansible-playbooks"
} else {
    "python -m venv .venv --prompt rezoleo-ansible-playbooks"
}
install_command := if uv_path != "" {
    "uv sync --locked"
} else if poetry_path != "" {
    "poetry install --no-root"
} else {
    f"{{venv_bin}}/pip install --upgrade pip && {{venv_bin}}/pip install . --group dev"
}

set unstable

[private]
default:
    @just --list --justfile {{justfile()}}

[private]
run_playbook playbook *ARGS: venv
    {{venv_bin}}/ansible-playbook --inventory {{inventory}} {{playbook}} {{ARGS}}


# Create the ansible user used for all other playbooks
[group('playbooks')]
playbook-create-ansible-user *ARGS: (run_playbook "playbooks/create-ansible-user.yml" ARGS)

# Run the main playbook that configures our infrastructure
[group('playbooks')]
playbook-deploy-infra *ARGS: (run_playbook "playbooks/deploy-server.yml" ARGS)


# Login to Vault
[group('tooling')]
vault username:
    vault login -method=userpass username={{username}}

# Setup a virtualenv and install dependencies
[group('tooling')]
venv:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d .venv ]]; then
      {{ venv_command }}
      {{ install_command }}
    fi

# Run ruff and ansible-lint
[group('tooling')]
lint *ARGS:
    {{venv_bin}}/ruff check
    {{venv_bin}}/ansible-lint {{ARGS}}

# Find TODOs and comments silencing lints
[group('tooling')]
todo:
    grep --recursive --extended-regexp --ignore-case --line-number --color=always 'noqa|todo' --exclude-dir {{venv}}
