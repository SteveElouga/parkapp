#!/bin/bash
echo "🛑 Arrêt des services PostgreSQL + pgAdmin..."
docker-compose --env-file ../.env down
echo "✅ Services arrêtés avec succès."