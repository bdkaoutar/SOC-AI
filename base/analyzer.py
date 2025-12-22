#!/usr/bin/env python3
# analyzer.py - Core Analysis Agent (DO NOT MODIFY)
# Analyzes events using heuristics + LM, forwards to responder

from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime

from config import (AUTH_TOKEN, RESPONDER_URL, HEURISTICS, ANALYZER_PORT, 
                   USE_HEURISTIC_FALLBACK, KAFKA_ENABLED,
                   ENABLE_TRUST_AGENT, TRUST_AGENT_URL,
                   ENABLE_MITRE_MAPPING, MITRE_MAPPER_URL,
                   ENABLE_XAI, XAI_EXPLAINER_URL)
from event_schema import SecurityEvent, AnalysisResult, validate_event, validate_analysis
from lm_client import query_lm

# Optional Kafka support
if KAFKA_ENABLED:
    try:
        from kafka import KafkaConsumer, KafkaProducer
        import json
        import threading
        
        consumer = KafkaConsumer(
            'soc.events.analyze',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        
        print("[Analyzer] Kafka initialized")
    except ImportError:
        KAFKA_ENABLED = False

app = Flask(__name__)
analysis_history = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Analyzer</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        h1 { color: #f5576c; font-size: 2.5em; }
        .ai-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
            font-weight: bold;
        }
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
        }
        .stat-number.high { color: #f5576c; }
        .stat-number.medium { color: #ff9800; }
        .stat-number.low { color: #4CAF50; }
        .analysis-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .analysis-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #f5576c;
        }
        .severity-badge {
            display: inline-block;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .severity-high { background: #f5576c; }
        .severity-medium { background: #ff9800; }
        .severity-low { background: #4CAF50; }
        .refresh-btn {
            background: #f5576c;
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
            <h1>🤖 AI Security Analyzer</h1>
            <div class="ai-badge">Powered by LM Studio</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total">0</div>
                <div>Total Analyses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high" id="high">0</div>
                <div>High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium" id="medium">0</div>
                <div>Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low" id="low">0</div>
                <div>Low Severity</div>
            </div>
        </div>
        
        <div class="analysis-container">
            <div style="display:flex;justify-content:space-between;margin-bottom:20px;">
                <h2>Recent Analyses</h2>
                <button class="refresh-btn" onclick="loadAnalysis()">🔄 Refresh</button>
            </div>
            <div id="analysis-list"></div>
        </div>
    </div>

    <script>
        function loadAnalysis() {
            fetch('/api/analysis')
                .then(response => response.json())
                .then(data => {
                    const analyses = data.analyses;
                    document.getElementById('total').textContent = analyses.length;
                    document.getElementById('high').textContent = analyses.filter(a => a.analysis.severity === 'High').length;
                    document.getElementById('medium').textContent = analyses.filter(a => a.analysis.severity === 'Medium').length;
                    document.getElementById('low').textContent = analyses.filter(a => a.analysis.severity === 'Low').length;
                    
                    const list = document.getElementById('analysis-list');
                    if (analyses.length === 0) {
                        list.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No analyses yet...</div>';
                        return;
                    }
                    
                    list.innerHTML = analyses.slice().reverse().map(item => {
                        const severity = item.analysis.severity || 'Unknown';
                        return `
                        <div class="analysis-card">
                            <span class="severity-badge severity-${severity.toLowerCase()}">${severity}</span>
                            <div><strong>IP:</strong> ${item.event.src_ip}</div>
                            <div><strong>Kind:</strong> ${item.event.kind}</div>
                            <div><strong>Action:</strong> ${item.analysis.recommended_action}</div>
                        </div>
                        `;
                    }).join('');
                });
        }
        loadAnalysis();
        setInterval(loadAnalysis, 5000);
    </script>
</body>
</html>
"""

def apply_heuristics(event: dict) -> dict:
    """Fallback heuristic-based analysis"""
    kind = event.get("kind")
    if kind not in HEURISTICS:
        return {
            "severity": "Low",
            "category": "other",
            "recommended_action": "ignore",
            "confidence": 0.3,
            "justification": "No heuristic rule matched"
        }
    
    rule = HEURISTICS[kind]
    return {
        "severity": "Medium",
        "category": rule["category"],
        "recommended_action": rule["default_action"],
        "target_ip": event.get("src_ip"),
        "confidence": 0.5,
        "justification": "Heuristic rule applied"
    }

def analyze_event(event: dict) -> dict:
    """Main analysis logic: LM + heuristics fusion"""
    print(f"[Analyzer] Analyzing {event.get('id')}...")
    
    # Try LM analysis first
    lm_result = query_lm(event)
    
    if lm_result:
        print(f"[Analyzer] ✅ LM analysis: {lm_result['severity']}")
        return lm_result
    elif USE_HEURISTIC_FALLBACK:
        print(f"[Analyzer] ⚠️ LM failed, using heuristics")
        return apply_heuristics(event)
    else:
        print(f"[Analyzer] ❌ Analysis failed")
        return apply_heuristics(event)  # Always provide some analysis

def forward_to_responder(event: dict, analysis: dict):
    """Forward analysis to responder (with optional extensions)"""
    
    # Optional: Atelier A - Trust Agent calibration
    if ENABLE_TRUST_AGENT:
        try:
            headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
            payload = {"event": event, "analysis": analysis}
            response = requests.post(TRUST_AGENT_URL, json=payload, headers=headers, timeout=5)
            if response.status_code == 200:
                analysis = response.json()  # Calibrated analysis
                print(f"[Analyzer] ✅ Trust agent applied calibration")
        except Exception as e:
            print(f"[Analyzer] ⚠️ Trust agent error: {e}")
    
    # Optional: Atelier D - MITRE mapping
    if ENABLE_MITRE_MAPPING:
        try:
            headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
            payload = {"event": event, "analysis": analysis}
            response = requests.post(MITRE_MAPPER_URL, json=payload, headers=headers, timeout=5)
            if response.status_code == 200:
                analysis = response.json()  # Enriched with MITRE
                print(f"[Analyzer] ✅ MITRE mapping applied")
        except Exception as e:
            print(f"[Analyzer] ⚠️ MITRE mapper error: {e}")
    
    # Optional: Atelier D - XAI explanation
    if ENABLE_XAI:
        try:
            headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
            payload = {"event": event, "analysis": analysis}
            response = requests.post(XAI_EXPLAINER_URL, json=payload, headers=headers, timeout=5)
            if response.status_code == 200:
                analysis = response.json()  # Enriched with explanation
                print(f"[Analyzer] ✅ XAI explanation added")
        except Exception as e:
            print(f"[Analyzer] ⚠️ XAI error: {e}")
    
    # Forward to responder (Kafka or HTTP)
    payload = {"event": event, "analysis": analysis}
    
    if KAFKA_ENABLED:
        try:
            producer.send('soc.decisions', payload)
            producer.flush()
            return True
        except Exception as e:
            print(f"[Analyzer] Kafka forward error: {e}")
            return False
    else:
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
        try:
            response = requests.post(RESPONDER_URL, json=payload, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[Analyzer] Forward error: {e}")
            return False

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analysis', methods=['GET'])
def get_analysis():
    return jsonify({"analyses": analysis_history})

@app.route("/analyze", methods=["POST"])
def analyze_endpoint():
    if request.headers.get("Authorization") != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    event = request.get_json()
    if not event or not validate_event(event):
        return jsonify({"error": "Invalid event"}), 400

    # Analyze
    analysis = analyze_event(event)
    
    # Store
    analysis_history.append({
        "event": event,
        "analysis": analysis,
        "timestamp": datetime.now().isoformat()
    })
    
    if len(analysis_history) > 100:
        analysis_history.pop(0)
    
    # Forward
    success = forward_to_responder(event, analysis)
    
    if success:
        return jsonify({"status": "analyzed_and_forwarded"}), 200
    else:
        return jsonify({"error": "forward_failed"}), 500

def kafka_consumer_loop():
    """Kafka consumer for Atelier B"""
    print("[Analyzer] Starting Kafka consumer...")
    for message in consumer:
        event = message.value
        analysis = analyze_event(event)
        
        analysis_history.append({
            "event": event,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        })
        
        if len(analysis_history) > 100:
            analysis_history.pop(0)
        
        forward_to_responder(event, analysis)

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🤖 ANALYZER AGENT STARTING")
    print("="*80)
    print(f"🔌 Mode: {'Kafka' if KAFKA_ENABLED else 'HTTP'}")
    print(f"🧠 LM Fallback: {USE_HEURISTIC_FALLBACK}")
    print(f"🔐 Trust Agent: {'Enabled' if ENABLE_TRUST_AGENT else 'Disabled'}")
    print(f"🗺️  MITRE Mapping: {'Enabled' if ENABLE_MITRE_MAPPING else 'Disabled'}")
    print(f"💡 XAI: {'Enabled' if ENABLE_XAI else 'Disabled'}")
    print(f"🌐 Port: {ANALYZER_PORT}")
    print("="*80 + "\n")
    
    if KAFKA_ENABLED:
        import threading
        kafka_thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
        kafka_thread.start()
    
    app.run(host='0.0.0.0', port=ANALYZER_PORT)