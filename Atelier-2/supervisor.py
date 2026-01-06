#!/usr/bin/env python3
"""
Supervisor Agent - Atelier B
Monitoring centralisé pour le SOC avec Kafka
Utilise base/config.py pour la configuration unifiée
"""

from flask import Flask, request, jsonify, render_template_string
from kafka import KafkaAdminClient, KafkaConsumer
from kafka.admin import NewTopic
from kafka.errors import KafkaError
import requests
import threading
import json
import time
from datetime import datetime
from collections import defaultdict, deque
import sys
import os

# Importer la configuration unifiée
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'base'))
from config import (KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPICS,
                   SENSOR_PORT, COLLECTOR_PORT, ANALYZER_PORT, 
                   RESPONDER_PORT, SUPERVISOR_PORT)

app = Flask(__name__)

# Port du bridge
BRIDGE_PORT = 6011

# ============================================================================
# GLOBAL STATE
# ============================================================================

supervisor_stats = {
    "start_time": datetime.now().isoformat(),
    "kafka_healthy": False,
    "topics_status": {},
    "consumer_lag": {},
    "agents_status": {
        "log_tailer": {"status": "unknown", "port": SENSOR_PORT, "url": f"http://localhost:{SENSOR_PORT}"},
        "collector": {"status": "unknown", "port": COLLECTOR_PORT, "url": f"http://localhost:{COLLECTOR_PORT}"},
        "analyzer": {"status": "unknown", "port": ANALYZER_PORT, "url": f"http://localhost:{ANALYZER_PORT}"},
        "responder": {"status": "unknown", "port": RESPONDER_PORT, "url": f"http://localhost:{RESPONDER_PORT}"},
        "bridge": {"status": "unknown", "port": BRIDGE_PORT, "url": f"http://localhost:{BRIDGE_PORT}/health"}
    },
    "pipeline_metrics": {
        "total_events": 0,
        "analyzed_events": 0,
        "responded_events": 0,
        "failed_events": 0,
        "last_5min": deque(maxlen=300)
    },
    "threat_stats": {
        "high": 0,
        "medium": 0,
        "low": 0,
        "blocked_ips": 0,
        "tickets": 0,
        "ignored": 0
    }
}

recent_events = deque(maxlen=100)
alerts = deque(maxlen=50)

# ============================================================================
# KAFKA MONITORING
# ============================================================================

def check_kafka_health():
    """Check Kafka broker health"""
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            client_id='supervisor',
            request_timeout_ms=5000
        )
        cluster_metadata = admin.list_topics()
        admin.close()
        return True
    except Exception as e:
        print(f"[Supervisor] Kafka health check failed: {e}")
        return False


def get_topic_info():
    """Get information about Kafka topics"""
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            client_id='supervisor'
        )
        
        topics = list(KAFKA_TOPICS.values())
        metadata = admin.describe_topics(topics)
        
        topic_info = {}
        for topic_metadata in metadata:
            topic = topic_metadata['topic']
            partitions = len(topic_metadata['partitions'])
            topic_info[topic] = {
                "partitions": partitions,
                "status": "healthy"
            }
        
        admin.close()
        return topic_info
    except Exception as e:
        print(f"[Supervisor] Error getting topic info: {e}")
        return {}


def get_consumer_lag():
    """Monitor consumer lag across all topics"""
    lag_info = {}
    
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            client_id='supervisor'
        )
        
        groups = admin.list_consumer_groups()
        
        for group in groups:
            group_id = group[0]
            try:
                offsets = admin.list_consumer_group_offsets(group_id)
                lag_info[group_id] = {}
                
                for topic_partition, offset_metadata in offsets.items():
                    topic = topic_partition.topic
                    partition = topic_partition.partition
                    current_offset = offset_metadata.offset
                    
                    lag_info[group_id][f"{topic}-{partition}"] = {
                        "current_offset": current_offset,
                        "lag": "calculating..."
                    }
            except Exception as e:
                print(f"[Supervisor] Error getting lag for group {group_id}: {e}")
        
        admin.close()
        return lag_info
    except Exception as e:
        print(f"[Supervisor] Error in consumer lag monitoring: {e}")
        return {}


# ============================================================================
# AGENT HEALTH MONITORING
# ============================================================================

def check_agent_health(agent_name, url):
    """Check if an agent is responding"""
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return "up"
    except:
        pass
    return "down"


def monitor_agents():
    """Periodically check agent health"""
    while True:
        for agent_name, agent_info in supervisor_stats["agents_status"].items():
            status = check_agent_health(agent_name, agent_info["url"])
            agent_info["status"] = status
            agent_info["last_check"] = datetime.now().isoformat()
            
            if status == "down":
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "severity": "high",
                    "type": "agent_down",
                    "message": f"Agent {agent_name} is not responding",
                    "agent": agent_name
                }
                alerts.append(alert)
        
        time.sleep(30)


# ============================================================================
# KAFKA EVENT MONITORING
# ============================================================================

def monitor_kafka_events():
    """Monitor events flowing through Kafka topics"""
    try:
        consumer = KafkaConsumer(
            *list(KAFKA_TOPICS.values()),
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            group_id='supervisor-monitor',
            auto_offset_reset='latest'
        )
        
        print("[Supervisor] Kafka event monitor started")
        
        for message in consumer:
            topic = message.topic
            value = message.value
            
            # Update metrics
            if topic == KAFKA_TOPICS["events_raw"]:
                supervisor_stats["pipeline_metrics"]["total_events"] += 1
            elif topic == KAFKA_TOPICS["events_to_analyze"]:
                supervisor_stats["pipeline_metrics"]["analyzed_events"] += 1
            elif topic == KAFKA_TOPICS["decisions"]:
                supervisor_stats["pipeline_metrics"]["responded_events"] += 1
                
                if "analysis" in value:
                    analysis = value["analysis"]
                    severity = analysis.get("severity", "Low").lower()
                    action = analysis.get("recommended_action", "ignore")
                    
                    if severity in supervisor_stats["threat_stats"]:
                        supervisor_stats["threat_stats"][severity] += 1
                    
                    if action == "block_ip":
                        supervisor_stats["threat_stats"]["blocked_ips"] += 1
                    elif action == "create_ticket":
                        supervisor_stats["threat_stats"]["tickets"] += 1
                    else:
                        supervisor_stats["threat_stats"]["ignored"] += 1
            
            # Store recent events
            event_summary = {
                "timestamp": datetime.now().isoformat(),
                "topic": topic,
                "event_id": value.get("event_id") or value.get("event", {}).get("event_id", "unknown"),
                "type": value.get("kind") or value.get("event", {}).get("kind", "unknown"),
                "src_ip": value.get("src_ip") or value.get("event", {}).get("src_ip", "unknown")
            }
            recent_events.append(event_summary)
            
            supervisor_stats["pipeline_metrics"]["last_5min"].append({
                "timestamp": time.time(),
                "topic": topic
            })
            
    except Exception as e:
        print(f"[Supervisor] Kafka monitor error: {e}")
        supervisor_stats["pipeline_metrics"]["failed_events"] += 1


def monitor_kafka_health():
    """Periodically check Kafka health"""
    while True:
        supervisor_stats["kafka_healthy"] = check_kafka_health()
        if supervisor_stats["kafka_healthy"]:
            supervisor_stats["topics_status"] = get_topic_info()
            supervisor_stats["consumer_lag"] = get_consumer_lag()
        else:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "severity": "critical",
                "type": "kafka_down",
                "message": "Kafka broker is not responding"
            }
            alerts.append(alert)
        
        time.sleep(30)


# ============================================================================
# WEB DASHBOARD
# ============================================================================

HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>SOC Supervisor Dashboard - Atelier B</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 30px;
            text-align: center;
        }
        
        h1 {
            color: #1e3c72;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .supervisor-badge {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 10px 25px;
            border-radius: 25px;
            display: inline-block;
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .status-indicator {
            display: inline-block;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        .status-up { background: #4CAF50; }
        .status-down { background: #f5576c; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(1.1); }
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .card h2 {
            color: #1e3c72;
            font-size: 1.3em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .metric:last-child { border-bottom: none; }
        
        .metric-label {
            color: #666;
            font-weight: 500;
        }
        
        .metric-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .metric-value.high { color: #f5576c; }
        .metric-value.medium { color: #ff9800; }
        .metric-value.low { color: #4CAF50; }
        .metric-value.info { color: #2196F3; }
        
        .agent-list {
            list-style: none;
        }
        
        .agent-item {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .agent-name {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .topic-item {
            padding: 12px;
            margin: 8px 0;
            background: #f8f9fa;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .topic-name {
            font-weight: bold;
            color: #1e3c72;
            font-size: 0.9em;
        }
        
        .topic-status {
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            background: #4CAF50;
            color: white;
        }
        
        .event-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .event-item {
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .event-topic {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 8px;
        }
        
        .topic-raw { background: #2196F3; color: white; }
        .topic-analyze { background: #ff9800; color: white; }
        .topic-decisions { background: #4CAF50; color: white; }
        
        .refresh-btn {
            background: #1e3c72;
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: #2a5298;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎛️ SOC Supervisor Dashboard</h1>
            <div class="supervisor-badge">
                <span class="status-indicator status-up"></span>
                Atelier B - Kafka Mode
            </div>
            <div style="margin-top: 15px; color: #666;">
                <span id="uptime">Uptime: Calculating...</span>
            </div>
        </div>
        
        <div class="grid">
            <!-- Kafka Health -->
            <div class="card">
                <h2>📡 Kafka Health</h2>
                <div class="metric">
                    <span class="metric-label">Broker Status</span>
                    <span class="metric-value" id="kafka-status">...</span>
                </div>
                <div id="topics-list"></div>
            </div>
            
            <!-- Pipeline Metrics -->
            <div class="card">
                <h2>🔥 Event Pipeline</h2>
                <div class="metric">
                    <span class="metric-label">Total Events</span>
                    <span class="metric-value info" id="total-events">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Analyzed</span>
                    <span class="metric-value info" id="analyzed-events">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Responded</span>
                    <span class="metric-value info" id="responded-events">0</span>
                </div>
            </div>
            
            <!-- Threat Statistics -->
            <div class="card">
                <h2>⚠️ Threat Statistics</h2>
                <div class="metric">
                    <span class="metric-label">High Severity</span>
                    <span class="metric-value high" id="high-severity">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Medium Severity</span>
                    <span class="metric-value medium" id="medium-severity">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Blocked IPs</span>
                    <span class="metric-value high" id="blocked-ips">0</span>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <!-- Agents Status -->
            <div class="card">
                <h2>🤖 Agents Status</h2>
                <ul class="agent-list" id="agents-list"></ul>
            </div>
            
            <!-- Recent Events -->
            <div class="card">
                <h2>📊 Recent Events</h2>
                <div class="event-list" id="events-list">
                    <div style="text-align:center;color:#999;padding:40px;">
                        No events yet...
                    </div>
                </div>
            </div>
        </div>
        
        <div style="text-align:center;margin-top:30px;">
            <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh Now</button>
        </div>
    </div>

    <script>
        function formatUptime(startTime) {
            const start = new Date(startTime);
            const now = new Date();
            const diff = Math.floor((now - start) / 1000);
            const hours = Math.floor(diff / 3600);
            const mins = Math.floor((diff % 3600) / 60);
            const secs = diff % 60;
            return `Uptime: ${hours}h ${mins}m ${secs}s`;
        }

        function loadDashboard() {
            fetch('/api/supervisor')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('uptime').textContent = formatUptime(data.start_time);
                    
                    const kafkaStatus = data.kafka_healthy ? '✅ Online' : '❌ Offline';
                    document.getElementById('kafka-status').textContent = kafkaStatus;
                    document.getElementById('kafka-status').className = data.kafka_healthy ? 'metric-value low' : 'metric-value high';
                    
                    const topicsList = document.getElementById('topics-list');
                    topicsList.innerHTML = '';
                    for (const [topic, info] of Object.entries(data.topics_status)) {
                        topicsList.innerHTML += `
                            <div class="topic-item">
                                <span class="topic-name">${topic}</span>
                                <span class="topic-status">✅ Healthy</span>
                            </div>
                        `;
                    }
                    
                    const metrics = data.pipeline_metrics;
                    document.getElementById('total-events').textContent = metrics.total_events;
                    document.getElementById('analyzed-events').textContent = metrics.analyzed_events;
                    document.getElementById('responded-events').textContent = metrics.responded_events;
                    
                    document.getElementById('high-severity').textContent = data.threat_stats.high;
                    document.getElementById('medium-severity').textContent = data.threat_stats.medium;
                    document.getElementById('blocked-ips').textContent = data.threat_stats.blocked_ips;
                    
                    const agentsList = document.getElementById('agents-list');
                    agentsList.innerHTML = '';
                    for (const [name, info] of Object.entries(data.agents_status)) {
                        const statusClass = info.status === 'up' ? 'status-up' : 'status-down';
                        const statusText = info.status === 'up' ? '✅ UP' : '❌ DOWN';
                        agentsList.innerHTML += `
                            <li class="agent-item">
                                <div>
                                    <div class="agent-name">
                                        <span class="status-indicator ${statusClass}"></span>
                                        ${name.charAt(0).toUpperCase() + name.slice(1)}
                                    </div>
                                    <div style="color: #666; font-size: 0.9em;">Port: ${info.port} | ${statusText}</div>
                                </div>
                            </li>
                        `;
                    }
                    
                    const eventsList = document.getElementById('events-list');
                    if (data.recent_events.length === 0) {
                        eventsList.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No events yet...</div>';
                    } else {
                        eventsList.innerHTML = data.recent_events.slice().reverse().slice(0, 20).map(event => {
                            let topicClass = 'topic-raw';
                            if (event.topic.includes('analyze')) topicClass = 'topic-analyze';
                            if (event.topic.includes('decision')) topicClass = 'topic-decisions';
                            
                            return `
                                <div class="event-item">
                                    <span class="event-topic ${topicClass}">${event.topic.split('.').pop()}</span>
                                    <strong>IP:</strong> ${event.src_ip} | 
                                    <strong>Type:</strong> ${event.type} | 
                                    <strong>Time:</strong> ${new Date(event.timestamp).toLocaleTimeString()}
                                </div>
                            `;
                        }).join('');
                    }
                });
        }

        loadDashboard();
        setInterval(loadDashboard, 3000);
    </script>
</body>
</html>
"""

# ============================================================================
# FLASK ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    return render_template_string(HTML_DASHBOARD)


@app.route('/api/supervisor', methods=['GET'])
def get_supervisor_stats():
    return jsonify({
        "start_time": supervisor_stats["start_time"],
        "kafka_healthy": supervisor_stats["kafka_healthy"],
        "topics_status": supervisor_stats["topics_status"],
        "consumer_lag": supervisor_stats["consumer_lag"],
        "agents_status": supervisor_stats["agents_status"],
        "pipeline_metrics": {
            "total_events": supervisor_stats["pipeline_metrics"]["total_events"],
            "analyzed_events": supervisor_stats["pipeline_metrics"]["analyzed_events"],
            "responded_events": supervisor_stats["pipeline_metrics"]["responded_events"],
            "failed_events": supervisor_stats["pipeline_metrics"]["failed_events"]
        },
        "threat_stats": supervisor_stats["threat_stats"],
        "recent_events": list(recent_events),
        "alerts": list(alerts)
    })


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🎛️  SUPERVISOR AGENT STARTING (Atelier B)")
    print("="*80)
    print(f"🌐 Dashboard: http://localhost:{SUPERVISOR_PORT}")
    print(f"📡 Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"📊 Monitoring: 5 agents (4 base + bridge) + 3 Kafka topics")
    print("="*80 + "\n")
    
    print("[Supervisor] Starting monitoring threads...")
    
    kafka_health_thread = threading.Thread(target=monitor_kafka_health, daemon=True)
    kafka_health_thread.start()
    print("  ✅ Kafka health monitor started")
    
    agent_health_thread = threading.Thread(target=monitor_agents, daemon=True)
    agent_health_thread.start()
    print("  ✅ Agent health monitor started")
    
    kafka_event_thread = threading.Thread(target=monitor_kafka_events, daemon=True)
    kafka_event_thread.start()
    print("  ✅ Kafka event monitor started")
    
    time.sleep(2)
    
    print("\n[Supervisor] All monitors active")
    print(f"[Supervisor] Dashboard ready at http://localhost:{SUPERVISOR_PORT}\n")
    
    try:
        app.run(host='0.0.0.0', port=SUPERVISOR_PORT, debug=False)
    except KeyboardInterrupt:
        print("\n[Supervisor] Shutting down...")
