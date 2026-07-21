# Hestia

## Description

Hestia is meant to be a fully ansibled VM for mananging containers.

The underlying architecture is built around a rootless podman.

## Services

The following services run on Hestia :

- https://index.rezoleo.fr (port 3000)
- https://pdf.rezoleo.fr (port 3001)
- https://vanadis.rezoleo.fr (port 3002)

A description of the services is written below, more information in [our internal documentation is available]().

### Index

Nouvelle entrée dans la sage *Rézoléo remplace le BDE*, et idée piquée au [Rezel](https://index.rezel.net), ce
service vise à référencer les sites utiles à la communauté centralienne.

Ce projet est basé sur [GetHomepage](https://gethomepage.dev/).

### BentOkae

BentOkae[^1] est un éditeur de PDF, il s'agit d'un déploiement de BentoPDF :

> BentoPDF is a powerful, privacy-first, client-side PDF toolkit that is self hostable and allows you to manipulate, edit, merge, and process PDF files directly in your browser. No server-side processing is required, ensuring your files remain secure and private.

Le code source est disponible sur [GitHub](https://github.com/alam00000/bentopdf#-run-with-docker-compose--podman-compose-recommended).

### Vanadis

Vanadis[^3] est basé sur Paperless-NGX[^2]. Ce projet a d'abord été porté par Baptiste en 2024, qui a voulu faire un postgres managé. Le postgres managé a été fait (Babar).

Puis en 2026, a été proposé de manière indépendante de le faire. Il aura fallu que deux ans pour finir ce projet.

> Paperless-ngx is a document management system that transforms your physical documents into a searchable online archive so you can keep, well, less paper.

Pour plus d'information sur les features, consultez [la documentation](https://docs.paperless-ngx.com/#features).

[^1]: Le bureau de cette année, et ma liste était très nippophile.
[^2]: Il y avait au début Paperless et Paperless-NG, puis les deux projets ont fussionés pour donner Paperless-NGX mais la fusion est trop ancienne pour que la nuance subsiste dans le langage. Paperless désigne presque toujours Paperless-NGX dans la "communauté" de l'auto-hébergement
[^3]: En référence à [*86 - Eigthy Six*](https://86-eighty-six.fandom.com/wiki/Vanadis).
