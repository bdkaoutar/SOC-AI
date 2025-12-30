#!/usr/bin/env python3
# collector.py - Security Event Collector with Anomaly Detection Integration
# Receives events from sensors and forwards to analyzer (via anomaly detector if enabled)

from flask import Flask, request, jsonify, render_template_string
import requests
import json
from datetime import datetime
from collections import defaultdict
import sys
import os

# Import configuration
try:
    from config import (
        AUTH_TOKEN,
        COLLECTOR_PORT,
        ANALYZER_URL,
        ANOMALY_DETECTOR_URL,
        ENABLE_ANOMALY_DETECTION,
        KAFKA_ENABLED,
        KAFKA_BOOTSTRAP_SERVERS
    )
    print("[Config] Loaded unified configuration")
except ImportError as e:
    print(f"[Config] Error importing config: {e}")
    print("[Config] Using default values")
    AUTH_TOKEN = "securetoken123"
    COLLECTOR_PORT = 5001
    ANALYZER_URL = "http://localhost:5002/analyze"
    ANOMALY_DETECTOR_URL = "http://localhost:5003/detect"
    ENABLE_ANOMALY_DETECTION = True
    KAFKA_ENABLED = False
    KAFKA_BOOTSTRAP_SERVERS = ['localhost:9092']

# Kafka setup (optional)
producer = None
if KAFKA_ENABLED:
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print(f"[Collector] Kafka enabled: {KAFKA_BOOTSTRAP_SERVERS}")
    except Exception as e:
        print(f"[Collector] Kafka setup failed: {e}")
        KAFKA_ENABLED = False

app = Flask(__name__)

# Statistics
collector_stats = {
    "total_received": 0,
    "total_forwarded": 0,
    "total_errors": 0,
    "by_kind": defaultdict(int)
}

# Recent events (keep last 100)
recent_events = []

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def forward_to_analyzer(event: dict) -> bool:
    """
    Forward event to analyzer (with optional anomaly detection)
    
    Flow:
    1. If ENABLE_ANOMALY_DETECTION = True:
       - Send to anomaly_detector first
       - Get enriched event with anomaly_score
    2. Forward to analyzer (via HTTP or Kafka)
    
    Args:
        event: Security event dict
        
    Returns:
        bool: Success status
    """
    
    # ========================================================================
    # ATELIER C - ANOMALY DETECTION INTEGRATION
    # ========================================================================
    if ENABLE_ANOMALY_DETECTION:
        try:
            headers = {
                "Authorization": f"Bearer {AUTH_TOKEN}",
                "Content-Type": "application/json"
            }
            
            # Wrap event in payload (anomaly_detector expects {"event": {...}})
            payload = {"event": event}
            
            print(f"[Collector] 🧠 Sending to anomaly detector: {event['id']}")
            
            response = requests.post(
                ANOMALY_DETECTOR_URL,
                json=payload,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                enriched_event = response.json()
                anomaly_score = enriched_event.get('anomaly_score', 0)
                
                print(f"[Collector] ✅ Anomaly score: {anomaly_score:.3f}")
                
                # Use enriched event (now has anomaly_score field)
                event = enriched_event
                
            elif response.status_code == 401:
                print(f"[Collector] ⚠️  Anomaly detector: Unauthorized (check AUTH_TOKEN)")
            else:
                print(f"[Collector] ⚠️  Anomaly detector error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[Collector] ⚠️  Anomaly detector not reachable at {ANOMALY_DETECTOR_URL}")
        except requests.exceptions.Timeout:
            print(f"[Collector] ⚠️  Anomaly detector timeout")
        except Exception as e:
            print(f"[Collector] ⚠️  Anomaly detector error: {e}")
    
    # ========================================================================
    # FORWARD TO ANALYZER
    # ========================================================================
    
    # Option 1: Kafka
    if KAFKA_ENABLED and producer:
        try:
            producer.send('soc.events.analyze', event)
            producer.flush()
            print(f"[Collector] 📤 Forwarded to Kafka: {event['id']}")
            return True
        except Exception as e:
            print(f"[Collector] ❌ Kafka forward error: {e}")
            return False
    
    # Option 2: HTTP (default)
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AUTH_TOKEN}"
        }
        
        try:
            response = requests.post(
                ANALYZER_URL,
                json=event,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[Collector] 📤 Forwarded to analyzer: {event['id']}")
                return True
            else:
                print(f"[Collector] ❌ Analyzer returned {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"[Collector] ❌ Analyzer not reachable at {ANALYZER_URL}")
            return False
        except requests.exceptions.Timeout:
            print(f"[Collector] ❌ Analyzer timeout")
            return False
        except Exception as e:
            print(f"[Collector] ❌ Forward error: {e}")
            return False


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/event', methods=['POST'])
def receive_event():
    """
    Receive security event from sensors (log_tailer, etc)
    
    Expected payload:
    {
        "id": "evt_123456",
        "kind": "ssh_failed",
        "src_ip": "192.168.1.100",
        "ts": "2024-12-29T12:00:00",
        "raw": "Failed password for root from 192.168.1.100 port 45678 ssh2"
    }
    
    Returns:
        JSON response with status
    """
    
    # Authentication
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get event
    event = request.get_json()
    
    if not event or 'id' not in event:
        return jsonify({"error": "Invalid event format"}), 400
    
    # Update stats
    collector_stats["total_received"] += 1
    collector_stats["by_kind"][event.get('kind', 'unknown')] += 1
    
    print(f"\n[Collector] 📥 Received: {event['id']} ({event.get('kind', 'unknown')}) from {event.get('src_ip', 'unknown')}")
    
    # Store in recent events
    event_summary = {
        "id": event['id'],
        "kind": event.get('kind', 'unknown'),
        "src_ip": event.get('src_ip', 'unknown'),
        "ts": event.get('ts', datetime.now().isoformat()),
        "received_at": datetime.now().isoformat()
    }
    recent_events.append(event_summary)
    
    # Keep only last 100
    if len(recent_events) > 100:
        recent_events.pop(0)
    
    # Forward to analyzer (via anomaly detector if enabled)
    success = forward_to_analyzer(event)
    
    if success:
        collector_stats["total_forwarded"] += 1
        return jsonify({
            "status": "collected_and_forwarded",
            "event_id": event['id']
        }), 200
    else:
        collector_stats["total_errors"] += 1
        return jsonify({
            "status": "collected_but_forward_failed",
            "event_id": event['id']
        }), 500


@app.route('/api/events', methods=['GET'])
def get_events():
    """Get recent events (API endpoint for dashboard)"""
    return jsonify({
        "events": recent_events[-50:],  # Last 50 events
        "total": len(recent_events)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get collector statistics"""
    return jsonify(collector_stats)


@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard to visualize collector statistics"""
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Event Collector</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 1400px;
                margin: 0 auto;
            }
            
            .header {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                margin-bottom: 30px;
                text-align: center;
            }
            
            .header h1 {
                color: #667eea;
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            
            .header .emoji {
                font-size: 3em;
                margin-bottom: 10px;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                text-align: center;
            }
            
            .stat-value {
                font-size: 3em;
                font-weight: bold;
                color: #667eea;
                margin: 10px 0;
            }
            
            .stat-label {
                color: #666;
                font-size: 1.1em;
                font-weight: 500;
            }
            
            .events-section {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            
            .events-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            
            .events-header h2 {
                color: #333;
                font-size: 1.8em;
            }
            
            .refresh-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1em;
                font-weight: 600;
                transition: all 0.3s;
            }
            
            .refresh-btn:hover {
                background: #5568d3;
                transform: translateY(-2px);
            }
            
            .event-item {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            
            .event-kind {
                display: inline-block;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 600;
                color: white;
                margin-bottom: 5px;
            }
            
            .kind-ssh_failed { background: #e74c3c; }
            .kind-port_scan { background: #f39c12; }
            .kind-web_fuzz { background: #3498db; }
            
            .event-details {
                color: #555;
                margin-top: 5px;
            }
            
            .no-events {
                text-align: center;
                color: #999;
                padding: 40px;
                font-size: 1.1em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="emoji">🛡️</div>
                <h1>Security Event Collector</h1>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="total-events">0</div>
                    <div class="stat-label">Total Events</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="ssh-failed">0</div>
                    <div class="stat-label">SSH Failed</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="port-scans">0</div>
                    <div class="stat-label">Port Scans</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value" id="web-fuzz">0</div>
                    <div class="stat-label">Web Fuzz</div>
                </div>
            </div>
            
            <div class="events-section">
                <div class="events-header">
                    <h2>Recent Events</h2>
                    <button class="refresh-btn" onclick="loadEvents()">🔄 Refresh</button>
                </div>
                <div id="events-list"></div>
            </div>
        </div>
        
        <script>
            function loadStats() {
                fetch('/api/stats')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('total-events').textContent = data.total_received;
                        document.getElementById('ssh-failed').textContent = data.by_kind.ssh_failed || 0;
                        document.getElementById('port-scans').textContent = data.by_kind.port_scan || 0;
                        document.getElementById('web-fuzz').textContent = data.by_kind.web_fuzz || 0;
                    })
                    .catch(err => console.error('Error loading stats:', err));
            }
            
            function loadEvents() {
                fetch('/api/events')
                    .then(response => response.json())
                    .then(data => {
                        const eventsList = document.getElementById('events-list');
                        
                        if (data.events.length === 0) {
                            eventsList.innerHTML = '<div class="no-events">No events yet...</div>';
                            return;
                        }
                        
                        eventsList.innerHTML = data.events.reverse().slice(0, 20).map(event => `
                            <div class="event-item">
                                <span class="event-kind kind-${event.kind}">${event.kind}</span>
                                <div class="event-details">
                                    <strong>IP:</strong> ${event.src_ip}<br>
                                    <strong>Time:</strong> ${event.ts}
                                </div>
                            </div>
                        `).join('');
                    })
                    .catch(err => console.error('Error loading events:', err));
            }
            
            // Auto-refresh every 5 seconds
            setInterval(() => {
                loadStats();
                loadEvents();
            }, 5000);
            
            // Initial load
            loadStats();
            loadEvents();
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("="*80)
    print("🛡️  SECURITY EVENT COLLECTOR STARTING")
    print("="*80)
    print(f"Port: {COLLECTOR_PORT}")
    print(f"Analyzer URL: {ANALYZER_URL}")
    print(f"Anomaly Detection: {'ENABLED' if ENABLE_ANOMALY_DETECTION else 'DISABLED'}")
    if ENABLE_ANOMALY_DETECTION:
        print(f"Anomaly Detector URL: {ANOMALY_DETECTOR_URL}")
    print(f"Kafka: {'ENABLED' if KAFKA_ENABLED else 'DISABLED'}")
    print("="*80)
    print(f"\n🌐 Dashboard: http://localhost:{COLLECTOR_PORT}")
    print(f"📡 API endpoint: POST /event")
    print("="*80)
    
    app.run(host='0.0.0.0', port=COLLECTOR_PORT, debug=False)
