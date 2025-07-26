#!/bin/bash
echo "🚀 Lancement des services PostgreSQL + pgAdmin..."
docker-compose --env-file ../.env up -d
