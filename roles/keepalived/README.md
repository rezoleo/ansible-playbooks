# keepalived

Keeps a DNS (or any service) reachable when a server goes down. Two or more servers share one virtual IP (VIP). One of them holds it. If it dies, another one takes over.

## How it works

- Each VIP has a `master`, the server that should normally hold it.
- The role compares each server's `inventory_hostname` with that `master`. A match makes it the master. Everyone else is a backup.
- Servers talk to each other directly (unicast), using their `ansible_host`.
- Optionally, a small script checks that your service still answers. If it keeps failing, the server gives up the VIP.

## What you must set

```yaml
keepalived_peer_group: dns_resolvers   # inventory group with all the servers
keepalived_auth_pass: "changeme"       # same on every server, 8 characters max, you can set it yourself or create a random password using ansible.builtin.password,the password is stocked in vault 
keepalived_vips:
  - vip: 10.12.0.53/24                 # the shared address
    master: Joe                       # must match the inventory hostname
    router_id: 53                      # unique per VIP on the network
```

Each host also needs `ansible_host` in the inventory.

## What you can change

| Variable | Default | What it does |
|---|---|---|
| `keepalived_interface` | `eth0` | Interface that carries the VIP |
| `keepalived_priority_master` | `150` | Priority of the master |
| `keepalived_priority_backup` | `100` | Priority of the backups |
| `keepalived_advert_int` | `1` | Seconds between "I'm alive" messages |
| `keepalived_check_script` | empty | Script content. Leave empty for no health check |
| `keepalived_check_interval` | `2` | Seconds between checks |
| `keepalived_check_fall` | `2` | Failed checks before giving up the VIP |
| `keepalived_check_rise` | `2` | Good checks before taking it back |

## Health check example

```yaml
keepalived_check_script: |
  #!/bin/sh
  dig +time=1 +tries=1 @127.0.0.1 . NS > /dev/null
```