# ParkApp

**Une application de gestion de parking automobile**

---

## Table des matières

- [Présentation](#présentation)
- [Stack technique](#stack-technique)
- [Fonctionnalités principales](#fonctionnalités-principales)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Déploiement](#déploiement)
- [Architecture du projet](#architecture-du-projet)
- [Documentation API](#documentation-api)
- [Contribuer](#contribuer)
- [Changelog](#changelog)
- [Licence](#licence)
- [Contact](#contact)

---

## Présentation

ParkApp est une application web de gestion de parking automobile. Elle permet de suivre, gérer et optimiser l’utilisation des places de stationnement, avec un back-end robuste basé sur Django REST Framework.

---

## Stack technique

- **Langage principal** : Python 3.10
- **Framework backend** : Django, Django REST Framework
- **Base de données** : PostgreSQL
- **Conteneurisation** : Docker
- **CI/CD** : GitHub Actions
- **Outils de sécurité** : Bandit
- **Qualité de code** : Ruff, Black, Flake8
- **Déploiement** : Railway

---

## Fonctionnalités principales

- Gestion des utilisateurs et authentification (incluant OAuth via GitHub)
- Création, modification et suppression de parkings
- Suivi des disponibilités en temps réel
- Documentation interactive de l’API (Swagger)
- Sécurité et contrôle d’accès
- Intégration continue et déploiement automatisé

---

## Prérequis

- Python 3.10+
- Docker & Docker Compose (optionnel mais recommandé)
- PostgreSQL (si non utilisé via Docker)
- Accès aux variables d’environnement (voir [Configuration](#configuration))

---

## Installation

### 1. Clone du dépôt

```bash
git clone https://github.com/SteveElouga/parkapp.git
cd parkapp
```

### 2. Installation des dépendances

Via pip :

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Ou via Docker (recommandé pour un environnement reproductible) :

```bash
docker build -t parkapp .
```

---

## Configuration

Créez un fichier `.env` à la racine du projet avec le contenu suivant :

```env
DATABASE_URL=postgres://parking_user:<password>@localhost:5432/parking_db
DJANGO_SETTINGS_MODULE=core.settings
SECRET_KEY=<votre_secret_key>
DEBUG=1
GITHUB_CLIENT_ID=<client_id_github>
GITHUB_CLIENT_SECRET=<client_secret_github>
GITHUB_REDIRECT_URI=http://localhost:8000/auth/github/callback/
POSTGRES_DB=parking_db
POSTGRES_USER=parking_user
POSTGRES_PASSWORD=<password>
POSTGRES_HOST=localhost
```

Remplacez `<password>` et autres valeurs sensibles par vos propres secrets.

---

## Utilisation

### Démarrer en local

```bash
python manage.py migrate
python manage.py runserver
```

Ou via Docker :

```bash
docker-compose up --build
```

L’application sera accessible sur [http://localhost:8000/](http://localhost:8000/)

---

## Tests

Lancez les tests avec :

```bash
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh
```

Ou :

```bash
pytest
```

Des outils de qualité de code (Ruff, Black, Flake8) et d’analyse de sécurité (Bandit) sont intégrés en CI.

---

## Déploiement

Le workflow CI/CD utilise GitHub Actions :

- **Lint & Security** : vérification du code et analyse de sécurité à chaque push/PR
- **Tests** : exécution automatique des tests avec base de données Postgres en service
- **Build & Push Docker** : image Docker générée et poussée sur DockerHub
- **Déploiement** : automatisé sur Railway (`main`), modifiable selon vos besoins

Pour un déploiement manuel :

```bash
docker build -t parkapp .
docker run --env-file .env -p 8000:8000 parkapp
```

---

## Architecture du projet

```
parkapp/
│
├── core/                # Logiciel principal Django (settings, urls, wsgi)
├── app/                 # Applications métiers (models, views, serializers)
├── scripts/             # Scripts utilitaires (tests, migrations, etc.)
├── requirements.txt     # Dépendances Python
├── Dockerfile           # Image Docker du projet
├── .github/workflows/   # Configurations CI/CD
├── README.md            # Ce document
└── ...
```

---

## Documentation API

- L’API REST est documentée via Swagger/Redoc :  
  [http://localhost:8000/api/docs/swagger/](http://localhost:8000/api/docs/swagger/)

---

## Contribuer

Merci de lire [CONTRIBUTING.md](CONTRIBUTING.md) pour les règles de contribution :

- Ouvrir une issue avant une PR
- Respecter les conventions de nommage et le code style (Black, Ruff, Flake8)
- Écrire des tests pour toute nouvelle fonctionnalité

---

## Changelog

Voir l’historique des commits sur [GitHub](https://github.com/SteveElouga/parkapp/commits)

---

## Licence

Ce projet est sous licence MIT (ou à spécifier).

---

## Contact

- Développeur principal : [SteveElouga](https://github.com/SteveElouga)
- Issues : [https://github.com/SteveElouga/parkapp/issues](https://github.com/SteveElouga/parkapp/issues)

---