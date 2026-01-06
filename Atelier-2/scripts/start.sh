#!/bin/bash

echo "╔════════════════════════════════════════════════════════╗"
echo "║  🚀 ATELIER B - DÉMARRAGE COMPLET                     ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

SKIP_KAFKA_WAIT=${1:-false}
OPEN_DASHBOARDS=${2:-true}

cd ~/soc-unifie

# ============================================================================
# PHASE 0 : NETTOYAGE
# ============================================================================
echo "[0/8] 🧹 Nettoyage des processus existants..."

pkill -f log_tailer.py 2>/dev/null
pkill -f collector.py 2>/dev/null
pkill -f analyzer.py 2>/dev/null
pkill -f kafka_bridge.py 2>/dev/null
pkill -f supervisor.py 2>/dev/null
sudo pkill -f responder.py 2>/dev/null

# Supprimer TOUS les conteneurs SOC (y compris Kafka UI)
docker rm -f soc-kafka soc-zookeeper soc-kafka-ui 2>/dev/null

sleep 3
echo "   ✅ Processus et conteneurs nettoyés"
echo ""

# ============================================================================
# PHASE 1 : PRÉPARATION
# ============================================================================
echo "[1/8] 📁 Préparation des répertoires..."

mkdir -p logs atelier_b

REQUIRED_FILES=(
    "base/log_tailer.py"
    "base/collector.py"
    "base/analyzer.py"
    "base/responder.py"
    "base/config.py"
    "atelier_b/kafka_bridge.py"
    "atelier_b/supervisor.py"
    "atelier_b/docker-compose.yml"
)

MISSING=0
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "   ❌ Fichier manquant: $file"
        MISSING=$((MISSING + 1))
    fi
done

if [ $MISSING -gt 0 ]; then
    echo ""
    echo "❌ $MISSING fichier(s) manquant(s)."
    exit 1
fi

echo "   ✅ Tous les fichiers présents"
echo ""

# ============================================================================
# PHASE 2 : KAFKA & ZOOKEEPER (SANS KAFKA UI)
# ============================================================================
echo "[2/8] 🐳 Démarrage de Kafka & Zookeeper..."

cd atelier_b

# Démarrer uniquement Kafka et Zookeeper (pas Kafka UI)
docker-compose up -d kafka zookeeper 2>/dev/null

# Vérifier le résultat
if docker ps | grep -q "soc-kafka"; then
    echo "   ✅ Kafka démarré"
else
    echo "   ❌ Erreur Kafka"
    docker ps -a | grep soc-kafka
    exit 1
fi

if docker ps | grep -q "soc-zookeeper"; then
    echo "   ✅ Zookeeper démarré"
else
    echo "   ⚠️  Zookeeper problème (peut fonctionner quand même)"
fi

# Optionnel : Démarrer Kafka UI (non bloquant)
echo "   📊 Tentative de démarrage Kafka UI..."
docker-compose up -d kafka-ui 2>/dev/null
if docker ps | grep -q "soc-kafka-ui"; then
    echo "   ✅ Kafka UI démarré (http://localhost:8081)"
else
    echo "   ℹ️  Kafka UI non démarré (optionnel, pas critique)"
fi

if [ "$SKIP_KAFKA_WAIT" = "false" ]; then
    echo "   ⏳ Attente de 60 secondes pour initialisation..."
    for i in {60..1}; do
        printf "\r      Temps restant: %2d secondes" $i
        sleep 1
    done
    echo ""
else
    echo "   ⏳ Attente rapide (15 secondes)..."
    sleep 15
fi

echo ""

# ============================================================================
# PHASE 3 : VÉRIFICATION KAFKA
# ============================================================================
echo "[3/8] 🔍 Vérification de Kafka..."

KAFKA_RETRIES=10
KAFKA_OK=false

for i in $(seq 1 $KAFKA_RETRIES); do
    if docker exec soc-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        echo "   ✅ Kafka accessible"
        KAFKA_OK=true
        break
    else
        if [ $i -lt $KAFKA_RETRIES ]; then
            printf "\r   ⏳ Attente Kafka... ($i/$KAFKA_RETRIES)"
            sleep 3
        fi
    fi
done

echo ""

if [ "$KAFKA_OK" = "false" ]; then
    echo "   ❌ Kafka inaccessible"
    docker logs soc-kafka --tail 20
    exit 1
fi

# Créer les topics
echo "   📋 Création des topics..."

TOPICS=("soc.events.raw" "soc.events.analyze" "soc.decisions")

for topic in "${TOPICS[@]}"; do
    docker exec soc-kafka kafka-topics --create \
        --bootstrap-server localhost:9092 \
        --topic $topic \
        --partitions 1 \
        --replication-factor 1 \
        --if-not-exists > /dev/null 2>&1
    
    echo "      ✅ $topic"
done

echo ""

# ============================================================================
# PHASE 4 : KAFKA BRIDGE
# ============================================================================
echo "[4/8] 🌉 Démarrage du Kafka Bridge..."

cd ~/soc-unifie
python3 -u atelier_b/kafka_bridge.py > logs/bridge.log 2>&1 &
BRIDGE_PID=$!

sleep 8

if ps -p $BRIDGE_PID > /dev/null 2>&1; then
    echo "   ✅ Bridge démarré (PID: $BRIDGE_PID)"
else
    echo "   ❌ Bridge échec"
    tail -20 logs/bridge.log
    exit 1
fi

echo ""

# ============================================================================
# PHASE 5 : AGENTS
# ============================================================================
echo "[5/8] 🤖 Démarrage des agents..."

sudo python3 base/log_tailer.py > logs/log_tailer.log 2>&1 &
sleep 4
sudo lsof -i :6000 > /dev/null 2>&1 && echo "   ✅ Log Tailer" || echo "   ❌ Log Tailer"

python3 base/collector.py > logs/collector.log 2>&1 &
sleep 3
sudo lsof -i :6001 > /dev/null 2>&1 && echo "   ✅ Collector" || echo "   ❌ Collector"

python3 base/analyzer.py > logs/analyzer.log 2>&1 &
sleep 3
sudo lsof -i :6002 > /dev/null 2>&1 && echo "   ✅ Analyzer" || echo "   ❌ Analyzer"

sudo python3 base/responder.py > logs/responder.log 2>&1 &
sleep 4
sudo lsof -i :6003 > /dev/null 2>&1 && echo "   ✅ Responder" || echo "   ❌ Responder"

echo ""

# ============================================================================
# PHASE 6 : SUPERVISOR
# ============================================================================
echo "[6/8] 🎛️  Démarrage du Supervisor..."

python3 atelier_b/supervisor.py > logs/supervisor.log 2>&1 &
sleep 6

sudo lsof -i :6005 > /dev/null 2>&1 && echo "   ✅ Supervisor" || echo "   ⚠️  Supervisor"

echo ""

# ============================================================================
# PHASE 7 : VÉRIFICATION
# ============================================================================
echo "[7/8] ✅ Vérification..."

SERVICES=(
    "6000:Log Tailer"
    "6001:Collector"
    "6002:Analyzer"
    "6003:Responder"
    "6005:Supervisor"
    "6011:Bridge"
    "9092:Kafka"
    "2181:Zookeeper"
)

ACTIVE=0
for service in "${SERVICES[@]}"; do
    IFS=':' read -r port name <<< "$service"
    if sudo lsof -i :$port > /dev/null 2>&1; then
        echo "   ✅ $name"
        ((ACTIVE++))
    else
        echo "   ❌ $name"
    fi
done

echo ""

# ============================================================================
# PHASE 8 : RÉSUMÉ
# ============================================================================
echo "[8/8] 📊 Résumé..."

if [ $ACTIVE -eq ${#SERVICES[@]} ]; then
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  ✅ ATELIER B COMPLÈTEMENT DÉMARRÉ ! (${ACTIVE}/${#SERVICES[@]})          ║"
    echo "╚════════════════════════════════════════════════════════╝"
    EXIT_CODE=0
elif [ $ACTIVE -ge 6 ]; then
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  ✅ ATELIER B OPÉRATIONNEL (${ACTIVE}/${#SERVICES[@]} services)           ║"
    echo "╚════════════════════════════════════════════════════════╝"
    EXIT_CODE=0
else
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  DÉMARRAGE PARTIEL (${ACTIVE}/${#SERVICES[@]} services)               ║"
    echo "╚════════════════════════════════════════════════════════╝"
    EXIT_CODE=1
fi

echo ""
echo "📊 Dashboards:"
echo "   http://localhost:6005  (Supervisor)"
echo "   http://localhost:6003  (Responder)"
echo "   http://localhost:6000  (Sensor)"
echo ""

if docker ps | grep -q "soc-kafka-ui"; then
    echo "   http://localhost:8081  (Kafka UI) ✅"
else
    echo "   http://localhost:8081  (Kafka UI) ❌ non disponible"
fi

echo ""

if [ "$OPEN_DASHBOARDS" = "true" ] && [ $EXIT_CODE -eq 0 ]; then
    chromium-browser --explicitly-allowed-ports=6000,6003,6005 \
        http://localhost:6005 \
        http://localhost:6003 \
        > /dev/null 2>&1 &
fi

exit $EXIT_CODE
