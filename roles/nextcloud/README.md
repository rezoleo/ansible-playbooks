# Nextcloud

Nextcloud is a robust, open-source and self-hosted(able) drive.

It offers a complete suite for cloud storage, calendar...

The documentation is on the [poly](https://poly.rezoleo.fr/doku.php?id=private:projet:nextcloud).

## Structure

This project deploys using Podman a Nextcloud with a Redis alongside. For online document editing, a Collabora Online Development Edition (CODE) is also installed on the same host.
But don't be afraid by the `Development Edition`, it should be understood as follows :

> If you are familiar with Linux, then CODE would be like our Fedora or openSUSE version - rather than RHEL or SLES, and lots of people use it.

(from the [CODE FAQ](https://sdk.collaboraonline.com/docs/faq.html#what-is-code-are-there-non-development-editions-too))

It relies on an existing mail server, reverse proxy, IdP, database (Postgres), and object storage.
