# TODO

## Garage

- [ ] **Binary never upgraded / not verified** (`tasks/install_garage.yaml`): `get_url` skips the download once
  `/usr/local/bin/garage` exists, so bumping `garage_version` does nothing and the restart handler is never
  notified. The download is not checksum-verified either. Add a `checksum:` (from the Garage release page) and
  download to a versioned path (or use `force`) so a version change triggers a new download + restart.
- [ ] Choose what to do with `[s3_web]` (`templates/garage.toml.j2`)
- [ ] **Nextcloud bucket never created**: Nextcloud uses `OBJECTSTORE_S3_AUTOCREATE=false` and reads its keys from
  Vault (`buckets/nextcloud`), but nothing creates the `nextcloud` bucket and key in Garage (layout assignment,
  `garage bucket create`, `garage key create`, `garage bucket allow`). The Nextcloud install will fail until this is
  done, manually or through a task.
