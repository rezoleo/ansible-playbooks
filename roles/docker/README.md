# Docker

Ce playbook install Docker selon les les instructions pour Debian.

Il installe également `docker-compose` et crée un utilisateur `docker` avec l'UID 1001 comme
l'id 1000 est utilisé par l'utilisateur `ansible`.

Attention, ce playbook ne supporte que amd64 (*hardcoded* dans [le fichier](./tasks/main.yml)).