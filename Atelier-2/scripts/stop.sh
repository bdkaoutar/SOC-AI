#!/bin/bash

echo "╔════════════════════════════════════════════════════════╗"
echo "║  🛑 ARRÊT DE L'ATELIER B                              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# 1. Arrêter les processus Python
echo "[1/4] Arrêt des processus Python..."

pkill -f log_tailer.py && echo "   ✅ Log Tailer arrêté" || echo "   ℹ️  Log Tailer non actif"
pkill -f collector.py && echo "   ✅ Collector arrêté" || echo "   ℹ️  Collector non actif"
pkill -f analyzer.py && echo "   ✅ Analyzer arrêté" || echo "   ℹ️  Analyzer non actif"
pkill -f kafka_bridge.py && echo "   ✅ Bridge arrêté" || echo "   ℹ️  Bridge non actif"
pkill -f supervisor.py && echo "   ✅ Supervisor arrêté" || echo "   ℹ️  Supervisor non actif"
sudo pkill -f responder.py && echo "   ✅ Responder arrêté" || echo "   ℹ️  Responder non actif"

sleep 3
echo ""

# 2. Arrêter docker-compose
echo "[2/4] Arrêt via docker-compose..."

cd ~/soc-unifie/atelier_b
docker-compose down > /dev/null 2>&1
echo "   ✅ docker-compose down exécuté"
echo ""

# 3. Forcer la suppression de TOUS les conteneurs SOC
echo "[3/4] Suppression forcée des conteneurs..."

docker rm -f soc-kafka soc-zookeeper soc-kafka-ui 2>/dev/null

if [ $? -eq 0 ]; then
    echo "   ✅ Tous les conteneurs SOC supprimés"
else
    echo "   ℹ️  Conteneurs déjà supprimés"
fi

sleep 2
echo ""

# 4. Vérification
echo "[4/4] Vérification..."

PORTS=(6000 6001 6002 6003 6005 6011 9092 2181 8081)
STILL_ACTIVE=0

for port in "${PORTS[@]}"; do
    if sudo lsof -i :$port > /dev/null 2>&1; then
        echo "   ⚠️  Port $port encore actif"
        STILL_ACTIVE=$((STILL_ACTIVE + 1))
    fi
done

# Vérifier les conteneurs Docker
DOCKER_STOPPED=$(docker ps -a | grep -E "soc-kafka|soc-zookeeper|soc-kafka-ui" | wc -l)

if [ $DOCKER_STOPPED -gt 0 ]; then
    echo "   ⚠️  $DOCKER_STOPPED conteneur(s) Docker SOC encore présent(s)"
    STILL_ACTIVE=$((STILL_ACTIVE + 1))
fi

echo ""

if [ $STILL_ACTIVE -eq 0 ]; then
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  ✅ ATELIER B COMPLÈTEMENT ARRÊTÉ                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  ARRÊT PARTIEL ($STILL_ACTIVE PROBLÈME(S))                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Pour un nettoyage complet:"
    echo "   ~/cleanup_docker_soc.sh"
    exit 1
fi
