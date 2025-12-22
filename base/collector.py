#!/usr/bin/env python3
# collector.py - Core Collection Agent (DO NOT MODIFY)
# Receives events and forwards to analyzer

from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime

from config import (AUTH_TOKEN, ANALYZER_URL, COLLECTOR_PORT, KAFKA_ENABLED,
                   ENABLE_ANOMALY_DETECTION, ANOMALY_DETECTOR_URL)
from event_schema import SecurityEvent, validate_event

# Optional Kafka support
if KAFKA_ENABLED:
    try:
        from kafka import KafkaConsumer, KafkaProducer
        import json
        import threading
        
        consumer = KafkaConsumer(
            'soc.events.raw',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        
        print("[Collector] Kafka consumer/producer initialized")
    except ImportError:
        print("[Collector] Kafka not available")
        KAFKA_ENABLED = False

app = Flask(__name__)
events_storage = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Collector Dashboard</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        h1 { color: #667eea; font-size: 2.5em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .events-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .event-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        .event-type {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Event Collector</h1>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-events">0</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="ssh-failed">0</div>
                <div class="stat-label">SSH Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="port-scans">0</div>
                <div class="stat-label">Port Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="web-fuzz">0</div>
                <div class="stat-label">Web Fuzz</div>
            </div>
        </div>
        
        <div class="events-container">
            <div style="display:flex;justify-content:space-between;margin-bottom:20px;">
                <h2>Recent Events</h2>
                <button class="refresh-btn" onclick="loadEvents()">🔄 Refresh</button>
            </div>
            <div id="events-list"></div>
        </div>
    </div>

    <script>
        function loadEvents() {
            fetch('/api/events')
                .then(response => response.json())
                .then(data => {
                    const events = data.events;
                    document.getElementById('total-events').textContent = events.length;
                    document.getElementById('ssh-failed').textContent = events.filter(e => e.kind === 'ssh_failed').length;
                    document.getElementById('port-scans').textContent = events.filter(e => e.kind === 'port_scan').length;
                    document.getElementById('web-fuzz').textContent = events.filter(e => e.kind === 'web_fuzz').length;
                    
                    const eventsList = document.getElementById('events-list');
                    if (events.length === 0) {
                        eventsList.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No events yet...</div>';
                        return;
                    }
                    
                    eventsList.innerHTML = events.slice().reverse().map(event => `
                        <div class="event-card">
                            <span class="event-type">${event.kind}</span>
                            <div><strong>IP:</strong> ${event.src_ip}</div>
                            <div><strong>Time:</strong> ${event.ts}</div>
                        </div>
                    `).join('');
                });
        }
        loadEvents();
        setInterval(loadEvents, 5000);
    </script>
</body>
</html>
"""

def forward_to_analyzer(event: dict):
    """Forward event to analyzer (with optional anomaly detection)"""
    
    # Optional: Atelier C - Anomaly Detection
    if ENABLE_ANOMALY_DETECTION:
        try:
            headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
            response = requests.post(ANOMALY_DETECTOR_URL, json=event, headers=headers, timeout=5)
            if response.status_code == 200:
                event = response.json()  # Event enriched with anomaly score
        except Exception as e:
            print(f"[Collector] Anomaly detector error: {e}")
    
    # Forward to analyzer (HTTP or Kafka)
    if KAFKA_ENABLED:
        try:
            producer.send('soc.events.analyze', event)
            producer.flush()
            print(f"[Collector] Forwarded to Kafka: {event['id']}")
            return True
        except Exception as e:
            print(f"[Collector] Kafka forward error: {e}")
            return False
    else:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {AUTH_TOKEN}"}
        try:
            response = requests.post(ANALYZER_URL, json=event, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[Collector] Forward error: {e}")
            return False

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/events', methods=['GET'])
def get_events():
    return jsonify({"events": events_storage})

@app.route('/event', methods=['POST'])
def receive_event():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    event = request.json
    if not event or not validate_event(event):
        return jsonify({"error": "Invalid event"}), 400
    
    events_storage.append(event)
    print(f"[Collector] Received: {event.get('id')} ({event.get('kind')})")
    
    # Keep memory bounded
    if len(events_storage) > 100:
        events_storage.pop(0)
    
    # Forward to analyzer
    success = forward_to_analyzer(event)
    
    if success:
        return jsonify({"status": "collected_and_forwarded"}), 200
    else:
        return jsonify({"error": "forward_failed"}), 500

def kafka_consumer_loop():
    """Kafka consumer loop for Atelier B"""
    print("[Collector] Starting Kafka consumer...")
    for message in consumer:
        event = message.value
        events_storage.append(event)
        print(f"[Collector] Received from Kafka: {event.get('id')}")
        
        if len(events_storage) > 100:
            events_storage.pop(0)
        
        forward_to_analyzer(event)

if __name__ == "__main__":
    print("\n" + "="*80)
    print("📥 COLLECTOR AGENT STARTING")
    print("="*80)
    print(f"🔌 Mode: {'Kafka' if KAFKA_ENABLED else 'HTTP'}")
    print(f"🌐 Port: {COLLECTOR_PORT}")
    print(f"🔬 Anomaly Detection: {'Enabled' if ENABLE_ANOMALY_DETECTION else 'Disabled'}")
    print("="*80 + "\n")
    
    if KAFKA_ENABLED:
        import threading
        kafka_thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
        kafka_thread.start()
    
    app.run(host='0.0.0.0', port=COLLECTOR_PORT)