#!/usr/bin/env python3
"""
Kafka Bridge pour Atelier B
Intercepte les communications HTTP et les redirige via Kafka
SANS modifier les agents de base
"""

import sys
import os
import json
import time
import threading
import requests
from kafka import KafkaProducer, KafkaConsumer
from flask import Flask, request, jsonify

# Importer la configuration unifiée
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'base'))
from config import (KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPICS,
                   COLLECTOR_PORT, ANALYZER_PORT, RESPONDER_PORT)

# URLs des agents de base (inchangés)
COLLECTOR_URL = f"http://localhost:{COLLECTOR_PORT}/event"
ANALYZER_URL = f"http://localhost:{ANALYZER_PORT}/analyze"
RESPONDER_URL = f"http://localhost:{RESPONDER_PORT}/respond"

# Port du bridge (intercepteur)
BRIDGE_PORT = 6011

# Kafka Producer
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

print("[Bridge] Kafka Bridge démarré")
print(f"[Bridge] Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
print(f"[Bridge] Topics: {KAFKA_TOPICS}")
print("[Bridge] Mode: Intercepteur HTTP ↔ Kafka")

# =============================================================================
# BRIDGE 1 : Log Tailer → Kafka → Collector
# =============================================================================
app_sensor_bridge = Flask("sensor_bridge")

@app_sensor_bridge.route('/event', methods=['POST'])
def sensor_bridge():
    """Intercepte les événements du Log Tailer"""
    event = request.json
    event_id = event.get('id', event.get('event_id', 'unknown'))
    
    print(f"[Bridge] 📨 Event reçu du Log Tailer: {event_id}")
    
    # Publier sur Kafka
    producer.send(KAFKA_TOPICS["events_raw"], event)
    producer.flush()
    print(f"[Bridge] ✅ Publié sur Kafka: {KAFKA_TOPICS['events_raw']}")
    
    return jsonify({"status": "ok", "kafka": True, "event_id": event_id}), 200

@app_sensor_bridge.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "kafka_bridge"}), 200

def sensor_bridge_thread():
    """Lance le bridge pour le sensor"""
    print(f"[Bridge] Starting sensor bridge on port {BRIDGE_PORT}")
    app_sensor_bridge.run(host='0.0.0.0', port=BRIDGE_PORT, debug=False)

# =============================================================================
# BRIDGE 2 : Kafka → Collector → Kafka
# =============================================================================
def collector_bridge():
    """Consomme de Kafka, envoie au Collector, republie"""
    consumer = KafkaConsumer(
        KAFKA_TOPICS["events_raw"],
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        group_id='collector-bridge',
        auto_offset_reset='earliest'  # ← IMPORTANT: lire depuis le début
    )
    
    print("[Bridge] Collector bridge démarré")
    
    for message in consumer:
        event = message.value
        event_id = event.get('id', event.get('event_id', 'unknown'))
        
        print(f"[Bridge] 📨 Kafka → Collector: {event_id}")
        
        try:
            # Envoyer au Collector (base inchangée)
            response = requests.post(COLLECTOR_URL, json=event, timeout=5)
            
            if response.status_code == 200:
                # Republier pour l'Analyzer
                producer.send(KAFKA_TOPICS["events_to_analyze"], event)
                producer.flush()
                print(f"[Bridge] ✅ Collector → Kafka: {KAFKA_TOPICS['events_to_analyze']}")
            else:
                print(f"[Bridge] ⚠️  Collector returned {response.status_code}")
        except Exception as e:
            print(f"[Bridge] ❌ Erreur Collector: {e}")

# =============================================================================
# BRIDGE 3 : Kafka → Analyzer → Kafka
# =============================================================================
def analyzer_bridge():
    """Consomme de Kafka, envoie à l'Analyzer, republie"""
    consumer = KafkaConsumer(
        KAFKA_TOPICS["events_to_analyze"],
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        group_id='analyzer-bridge',
        auto_offset_reset='earliest'
    )
    
    print("[Bridge] Analyzer bridge démarré")
    
    for message in consumer:
        event = message.value
        event_id = event.get('id', event.get('event_id', 'unknown'))
        
        print(f"[Bridge] 📨 Kafka → Analyzer: {event_id}")
        
        try:
            # Envoyer à l'Analyzer (base inchangée)
            response = requests.post(ANALYZER_URL, json=event, timeout=10)
            
            if response.status_code == 200:
                analysis = response.json()
                decision = {
                    "event": event,
                    "analysis": analysis,
                    "event_id": event_id
                }
                # Republier pour le Responder
                producer.send(KAFKA_TOPICS["decisions"], decision)
                producer.flush()
                print(f"[Bridge] ✅ Analyzer → Kafka: {KAFKA_TOPICS['decisions']}")
            else:
                print(f"[Bridge] ⚠️  Analyzer returned {response.status_code}")
        except Exception as e:
            print(f"[Bridge] ❌ Erreur Analyzer: {e}")

# =============================================================================
# BRIDGE 4 : Kafka → Responder
# =============================================================================
def responder_bridge():
    """Consomme de Kafka, envoie au Responder"""
    consumer = KafkaConsumer(
        KAFKA_TOPICS["decisions"],
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        group_id='responder-bridge',
        auto_offset_reset='earliest'
    )
    
    print("[Bridge] Responder bridge démarré")
    
    for message in consumer:
        decision = message.value
        event_id = decision.get('event_id', 'unknown')
        
        print(f"[Bridge] 📨 Kafka → Responder: {event_id}")
        
        try:
            # Envoyer au Responder (base inchangée)
            response = requests.post(RESPONDER_URL, json=decision, timeout=5)
            
            if response.status_code == 200:
                print(f"[Bridge] ✅ Responder a traité: {event_id}")
            else:
                print(f"[Bridge] ⚠️  Responder returned {response.status_code}")
        except Exception as e:
            print(f"[Bridge] ❌ Erreur Responder: {e}")

# =============================================================================
# MAIN - UN SEUL BLOC !
# =============================================================================
if __name__ == "__main__":
    print("\n" + "="*80)
    print("🌉 KAFKA BRIDGE STARTING")
    print("="*80)
    print("Mode: Wrapper autour des agents de base (HTTP)")
    print("La base reste inchangée!")
    print(f"Bridge port: {BRIDGE_PORT}")
    print(f"Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print("="*80 + "\n")
    
    # Lancer tous les bridges en parallèle
    print("[Bridge] Lancement des threads...")
    
    threading.Thread(target=sensor_bridge_thread, daemon=True).start()
    print("  ✅ Sensor bridge thread lancé")
    time.sleep(2)
    
    threading.Thread(target=collector_bridge, daemon=True).start()
    print("  ✅ Collector bridge thread lancé")
    time.sleep(1)
    
    threading.Thread(target=analyzer_bridge, daemon=True).start()
    print("  ✅ Analyzer bridge thread lancé")
    time.sleep(1)
    
    threading.Thread(target=responder_bridge, daemon=True).start()
    print("  ✅ Responder bridge thread lancé")
    
    print("\n[Bridge] ✅ Tous les bridges actifs")
    print(f"[Bridge] Sensor bridge sur port {BRIDGE_PORT}")
    print("[Bridge] En attente des événements...\n")
    
    # Garder le programme actif
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Bridge] Arrêt du bridge")
        producer.close()
