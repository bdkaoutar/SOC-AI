# 🛡️ Atelier B - SOC Unifié avec Architecture Kafka

## 📋 Description
**Atelier B** : Extension du SOC Unifié avec architecture distribuée Apache Kafka.

> **Note** : Utilise la base commune située dans `/base/` à la racine du repository.

## 🏗️ Architecture Atelier B
```
../base/log_tailer.py → Kafka Topic (soc.events.raw)
         ↓
    kafka_bridge.py (Port 6011)
         ↓
../base/collector.py → Kafka Topic (soc.events.analyze)
         ↓
    kafka_bridge.py
         ↓
../base/analyzer.py → Kafka Topic (soc.decisions)
         ↓
    kafka_bridge.py
         ↓
../base/responder.py → UFW
         ↓
    supervisor.py (Port 6005)
```

## 🚀 Installation

### Prérequis
- Ubuntu 24.04
- Python 3.10+
- Docker & Docker Compose
- Accès sudo

### Démarrage rapide
```bash
# 1. Cloner
git clone https://github.com/bdkaoutar/SOC-AI.git
cd SOC-AI/Atelier-2

# 2. Installer dépendances
pip install -r requirements.txt

# 3. Configurer
nano ../base/config.py
# Modifier : API_KEY, KAFKA_ENABLED = True

# 4. Démarrer Kafka
docker-compose up -d

# 5. Démarrer le SOC
./scripts/start.sh
```

## 📊 Composants Atelier B

### À la racine de Atelier-2/
- `kafka_bridge.py` - Pont Kafka ↔ Agents (port 6011)
- `supervisor.py` - Monitoring centralisé (port 6005)
- `docker-compose.yml` - Infrastructure Kafka/Zookeeper
- `requirements.txt` - Dépendances Kafka

### Scripts (scripts/)
- `start.sh` - Démarrage complet
- `stop.sh` - Arrêt propre

### Base commune (../base/)
- `log_tailer.py` - Détecteur (port 6000)
- `collector.py` - Collecteur (port 6001)
- `analyzer.py` - Analyseur (port 6002)
- `responder.py` - Répondeur (port 6003)
- `config.py` - Configuration globale
- `event_schema.py` - Schéma événements
- `lm_client.py` - Client LM Studio

## 🌐 Dashboards

- **Supervisor** : http://localhost:6005
- **Responder** : http://localhost:6003
- **Log Tailer** : http://localhost:6000
- **Kafka UI** : http://localhost:8081

## 🔧 Configuration

Dans `../base/config.py` :
```python
API_KEY = "CHANGEZ-MOI"
KAFKA_ENABLED = True
KAFKA_BOOTSTRAP_SERVERS = ['localhost:9092']
DRY_RUN = True  # False pour production

SUPERVISOR_PORT = 6005  # Atelier B
BRIDGE_PORT = 6011      # Atelier B
```

## 🛑 Arrêt
```bash
./scripts/stop.sh
```

## 📚 Structure
```
Atelier-2/               (Atelier B - Kafka)
├── kafka_bridge.py      Pont Kafka
├── supervisor.py        Monitoring
├── docker-compose.yml   Infrastructure
├── requirements.txt     Dépendances
├── scripts/
│   ├── start.sh
│   └── stop.sh
├── README.md
└── .gitignore
```

**Base commune** : `../base/`

## 🔗 Autres ateliers

- **Base** : `../base/` (commune)
- **Atelier A** : `../Atelier-1/`
- **Atelier B** : Ici ⭐
- **Atelier C** : `../Atelier-3/`
- **Atelier D** : `../Atelier-4/`

## 📝 Licence
Projet académique - Formation SOC
