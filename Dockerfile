# Étape 1 : Build des dépendances
FROM python:3.10-slim AS builder

WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Installer pipenv ou poetry si besoin, sinon requirements.txt
COPY requirements.txt .
RUN pip install --upgrade pip && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Étape 2 : Image finale légère
FROM python:3.10-slim

WORKDIR /app

# Installer les dépendances système nécessaires à l'exécution
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev tini && \
    rm -rf /var/lib/apt/lists/*

# Copier les dépendances Python pré-construites
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

# Copier le code de l'application
COPY . .

# Créer un utilisateur non-root
RUN useradd -m appuser
USER appuser

# Collecte des fichiers statiques (si utilisé)
RUN python manage.py collectstatic --noinput || true

# Port d'écoute (adapter si besoin)
EXPOSE 8000

# Utiliser tini pour le PID 1
ENTRYPOINT ["/usr/bin/tini", "--"]

# Commande de lancement de l’API (adapter si besoin)
CMD ["gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000"]