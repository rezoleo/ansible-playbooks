# Docker

Ce playbook install Docker selon les instructions pour Debian.

Il installe également `docker-compose` et crée un utilisateur `docker` avec l'UID 1001 comme
l'id 1000 est utilisé par l'utilisateur `ansible`.

Attention, ce playbook ne supporte que amd64 (*hardcoded* dans [le fichier](./tasks/main.yml)).

## A vérifier

Avant d'utiliser ce playbook, vérifiez que vous avez bien configuré votre `compose.yml` avec :

1. Vous avez donné un nom à votre conteneur dans le fichier :
```yaml
    container_name: bentopdf
```
2. L'utilisateur `docker` est mappé dans le conteneur :
```yaml
    user: "1001:1001"
```