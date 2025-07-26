#!/bin/bash

# Se placer dans le dossier racine du projet (1 niveau au-dessus du dossier scripts)
cd "$(dirname "$0")/.." || exit 1

echo "📦 Lancement des tests avec couverture..."

pytest authentication/ \
  --ds=core.settings \
  --cov=authentication \
  --cov-report=term-missing \
  --cov-report=html
