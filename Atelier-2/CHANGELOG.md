# Changelog - Atelier B

## [1.0.0] - 2025-12-29

### Ajouts
- **kafka_bridge.py** - Pont entre Kafka et les agents HTTP
- **supervisor.py** - Agent de monitoring centralisé
- **docker-compose.yml** - Infrastructure Kafka + Zookeeper
- **scripts/start.sh** - Script de démarrage automatisé
- **scripts/stop.sh** - Script d'arrêt propre
- **README.md** - Documentation complète
- **.gitignore** - Configuration des exclusions
- **requirements.txt** - Dépendances Python

### Modifications dans ../base/
- **responder.py** - Ajout de la fonction `kafka_consumer_loop()`
  - Consommation asynchrone du topic Kafka 'soc.decisions'
  - Traitement automatique des décisions (block_ip, create_ticket, ignore)
  - Exécution des commandes de blocage UFW
  - Support du mode dual (HTTP + Kafka)
  - Thread dédié pour la consommation Kafka
  
### Architecture
```
Log Tailer → Kafka (soc.events.raw)
    ↓
Kafka Bridge → Collector → Kafka (soc.events.analyze)
    ↓
Kafka Bridge → Analyzer → Kafka (soc.decisions)
    ↓
Kafka Bridge → Responder (kafka_consumer_loop) → UFW
    ↓
Supervisor (Monitoring)
```

### Technologies
- Apache Kafka 7.5.0
- Python 3.10+
- Docker & Docker Compose
- Flask
- UFW
