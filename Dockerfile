FROM python:3.10-slim AS builder

WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Étape 2 : Image finale légère
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

COPY . .

# Créer le dossier logs avec les bonnes permissions (avant USER)
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Collecte des fichiers statiques (si utilisé)
RUN python manage.py collectstatic --noinput || true

# Créer un utilisateur non-root
RUN useradd -m appuser

USER appuser

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000"]