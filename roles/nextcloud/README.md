# Nextcloud

Nextcloud is a robust, open-source and self-hosted(able) drive.

It offers a complete suite for cloud storage, calendar...

The documentation is on the [poly](https://poly.rezoleo.fr/doku.php?id=private:projet:nextcloud).

## Structure

This role deploys Nextcloud and a local Redis instance using the official [`nextcloud.admin` Ansible collection](https://github.com/nextcloud/ansible-collection-nextcloud-admin).

It relies on an existing mail server, reverse proxy, IdP, database (PostgreSQL), and S3 object storage (Garage).
