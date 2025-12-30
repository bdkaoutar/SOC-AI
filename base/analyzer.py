#!/usr/bin/env python3
# analyzer.py - AI Security Analyzer with ML + Heuristics + LLM Fusion
# Analyzes security events using anomaly detection scores, heuristics, and LLM

from flask import Flask, request, jsonify, render_template_string
import requests
import json
from datetime import datetime
from collections import defaultdict
import sys

# Import configuration
try:
    from config import (
        AUTH_TOKEN,
        ANALYZER_PORT,
        RESPONDER_URL,
        LM_API_URL,
        LM_MODEL,
        LM_TIMEOUT,
        USE_HEURISTIC_FALLBACK,
        HEURISTICS,
        ENABLE_ANOMALY_DETECTION,
        ANOMALY_THRESHOLD
    )
    print("[Config] Loaded unified configuration")
except ImportError as e:
    print(f"[Config] Error importing config: {e}")
    print("[Config] Using default values")
    AUTH_TOKEN = "securetoken123"
    ANALYZER_PORT = 5002
    RESPONDER_URL = "http://localhost:5004/respond"
    LM_API_URL = "http://192.168.137.1:1234/v1/chat/completions"
    LM_MODEL = "local-model"
    LM_TIMEOUT = 10
    USE_HEURISTIC_FALLBACK = True
    ENABLE_ANOMALY_DETECTION = True
    ANOMALY_THRESHOLD = 0.7
    HEURISTICS = {
        "ssh_failed": {
            "pattern": r"Failed password",
            "category": "brute_force",
            "default_action": "block_ip"
        },
        "port_scan": {
            "pattern": r"UFW BLOCK",
            "category": "reconnaissance",
            "default_action": "create_ticket"
        },
        "web_fuzz": {
            "pattern": r"404",
            "category": "web_attack",
            "default_action": "create_ticket"
        }
    }

app = Flask(__name__)

# Statistics
analyzer_stats = {
    "total_analyzed": 0,
    "by_severity": defaultdict(int),
    "by_action": defaultdict(int),
    "ml_used": 0,
    "heuristics_used": 0,
    "lm_used": 0
}

# Recent analyses (keep last 100)
recent_analyses = []


# ============================================================================
# CORE ANALYSIS FUNCTIONS
# ============================================================================

def analyze_with_heuristics(event: dict) -> dict:
    """
    Analyze event using heuristic rules
    
    Args:
        event: Security event dict
        
    Returns:
        dict with severity, action, confidence, reasoning
    """
    kind = event.get('kind', 'unknown')
    
    if kind in HEURISTICS:
        heuristic = HEURISTICS[kind]
        
        return {
            "severity": "Medium",  # Default severity for heuristics
            "action": heuristic.get("default_action", "create_ticket"),
            "confidence": 0.7,
            "reasoning": f"Heuristic match for {kind}: {heuristic.get('category', 'unknown')}",
            "source": "heuristics"
        }
    
    # Unknown event type
    return {
        "severity": "Low",
        "action": "ignore",
        "confidence": 0.5,
        "reasoning": "Unknown event type, no heuristic match",
        "source": "heuristics"
    }


def analyze_with_lm(event: dict) -> dict:
    """
    Analyze event using Language Model (LM Studio)
    
    Args:
        event: Security event dict
        
    Returns:
        dict with severity, action, confidence, reasoning
    """
    
    # Build prompt for LM
    prompt = f"""You are a cybersecurity expert analyzing security events. Analyze this event and provide a security assessment.

Event Details:
- Type: {event.get('kind', 'unknown')}
- Source IP: {event.get('src_ip', 'unknown')}
- Timestamp: {event.get('ts', 'unknown')}
- Raw log: {event.get('raw', 'No raw data')[:200]}

Provide your analysis in this EXACT JSON format (no other text):
{{
    "severity": "Low|Medium|High",
    "action": "ignore|create_ticket|block_ip",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}"""

    try:
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": LM_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 200
        }
        
        response = requests.post(LM_API_URL, json=payload, headers=headers, timeout=LM_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            content = data['choices'][0]['message']['content']
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                result["source"] = "lm"
                return result
            else:
                raise ValueError("No JSON found in LM response")
        else:
            raise Exception(f"LM API returned status {response.status_code}")
            
    except Exception as e:
        print(f"[Analyzer] ❌ LM error: {e}")
        return None


def fuse_ml_heuristics_lm(event: dict, anomaly_score: float, heuristic_result: dict, lm_result: dict = None) -> dict:
    """
    Fuse ML anomaly score, heuristics, and LM analysis to make final decision
    
    Priority:
    1. Very High ML score (>0.9) → High severity, block_ip
    2. High ML score (>0.7) + High LM severity → High severity, block_ip
    3. High ML score (>0.7) + Medium LM/Heuristic → Medium severity, action from heuristic
    4. Medium ML score (0.4-0.7) + High LM → Medium severity, create_ticket
    5. Low ML score (<0.4) → Trust LM or Heuristics
    
    Args:
        event: Security event
        anomaly_score: ML anomaly score (0-1)
        heuristic_result: Result from heuristics
        lm_result: Result from LM (optional)
        
    Returns:
        Final decision dict
    """
    
    # Default to heuristic result
    final_severity = heuristic_result["severity"]
    final_action = heuristic_result["action"]
    final_confidence = heuristic_result["confidence"]
    reasoning_parts = []
    
    # Track what was used
    ml_contribution = False
    lm_contribution = False
    heuristic_contribution = True
    
    # ========================================================================
    # FUSION LOGIC
    # ========================================================================
    
    # Case 1: Very High ML Score (>0.9) - Critical anomaly
    if anomaly_score > 0.9:
        final_severity = "High"
        final_action = "block_ip"
        final_confidence = 0.95
        reasoning_parts.append(f"Critical ML anomaly score: {anomaly_score:.3f}")
        ml_contribution = True
    
    # Case 2: High ML Score (>0.7)
    elif anomaly_score > ANOMALY_THRESHOLD:
        ml_contribution = True
        
        # Sub-case 2a: High ML + High LM severity
        if lm_result and lm_result.get("severity") == "High":
            final_severity = "High"
            final_action = "block_ip"
            final_confidence = 0.9
            reasoning_parts.append(f"High ML score ({anomaly_score:.3f}) + High LM severity")
            lm_contribution = True
        
        # Sub-case 2b: High ML + heuristic says block_ip
        elif heuristic_result["action"] == "block_ip":
            final_severity = "High"
            final_action = "block_ip"
            final_confidence = 0.85
            reasoning_parts.append(f"High ML score ({anomaly_score:.3f}) + Heuristic: block_ip")
        
        # Sub-case 2c: High ML but heuristic says create_ticket (like port_scan)
        else:
            final_severity = "Medium"
            final_action = heuristic_result["action"]
            final_confidence = 0.75
            reasoning_parts.append(f"High ML score ({anomaly_score:.3f}) but heuristic suggests ticket")
    
    # Case 3: Medium ML Score (0.4-0.7)
    elif anomaly_score > 0.4:
        ml_contribution = True
        
        # Sub-case 3a: Medium ML + High LM
        if lm_result and lm_result.get("severity") in ["High", "Medium"]:
            final_severity = "Medium"
            final_action = "create_ticket"
            final_confidence = 0.7
            reasoning_parts.append(f"Medium ML score ({anomaly_score:.3f}) + {lm_result['severity']} LM severity")
            lm_contribution = True
        
        # Sub-case 3b: Medium ML, trust heuristic
        else:
            reasoning_parts.append(f"Medium ML score ({anomaly_score:.3f}), using heuristic decision")
    
    # Case 4: Low ML Score (<0.4) - Trust LM or Heuristics
    else:
        if lm_result:
            final_severity = lm_result.get("severity", final_severity)
            final_action = lm_result.get("action", final_action)
            final_confidence = lm_result.get("confidence", final_confidence)
            reasoning_parts.append(f"Low ML score ({anomaly_score:.3f}), trusting LM analysis")
            lm_contribution = True
        else:
            reasoning_parts.append(f"Low ML score ({anomaly_score:.3f}), using heuristic")
    
    # Add heuristic reasoning
    reasoning_parts.append(f"Heuristic: {heuristic_result['reasoning']}")
    
    # Add LM reasoning if available
    if lm_result and lm_contribution:
        reasoning_parts.append(f"LM: {lm_result.get('reasoning', 'N/A')}")
    
    return {
        "severity": final_severity,
        "action": final_action,
        "confidence": final_confidence,
        "reasoning": " | ".join(reasoning_parts),
        "ml_score": anomaly_score,
        "ml_contribution": ml_contribution,
        "lm_contribution": lm_contribution,
        "heuristic_contribution": heuristic_contribution
    }


def analyze_event(event: dict) -> dict:
    """
    Main analysis function - coordinates ML, heuristics, and LM
    
    Args:
        event: Security event (may include anomaly_score from anomaly_detector)
        
    Returns:
        Analysis result dict
    """
    
    event_id = event.get('id', 'unknown')
    
    print(f"\n[Analyzer] Analyzing {event_id}...")
    
    # Extract anomaly score if present (from anomaly_detector)
    anomaly_score = event.get('anomaly_score', 0.0)
    
    if anomaly_score > 0:
        print(f"[Analyzer] ML anomaly score: {anomaly_score:.3f}")
        analyzer_stats["ml_used"] += 1
    
    # Get heuristic analysis
    heuristic_result = analyze_with_heuristics(event)
    analyzer_stats["heuristics_used"] += 1
    
    # Try LM analysis (optional)
    lm_result = None
    if USE_HEURISTIC_FALLBACK:
        lm_result = analyze_with_lm(event)
        if lm_result:
            print(f"[Analyzer] LM analysis: {lm_result['severity']} severity")
            analyzer_stats["lm_used"] += 1
    
    # Fuse all sources
    if ENABLE_ANOMALY_DETECTION and anomaly_score > 0:
        # Fusion: ML + Heuristics + LM
        final_result = fuse_ml_heuristics_lm(event, anomaly_score, heuristic_result, lm_result)
    elif lm_result:
        # LM + Heuristics (no ML)
        final_result = lm_result
    else:
        # Heuristics only
        final_result = heuristic_result
    
    print(f"[Analyzer] ✅ Decision: {final_result['severity']} severity, action: {final_result['action']}")
    
    # Update stats
    analyzer_stats["total_analyzed"] += 1
    analyzer_stats["by_severity"][final_result["severity"]] += 1
    analyzer_stats["by_action"][final_result["action"]] += 1
    
    # Build complete analysis result
    analysis = {
        "event_id": event_id,
        "event": event,
        "severity": final_result["severity"],
        "action": final_result["action"],
        "confidence": final_result["confidence"],
        "reasoning": final_result["reasoning"],
        "ml_score": anomaly_score,
        "timestamp": datetime.now().isoformat()
    }
    
    # Store in recent analyses
    recent_analyses.append({
        "event_id": event_id,
        "kind": event.get('kind', 'unknown'),
        "src_ip": event.get('src_ip', 'unknown'),
        "severity": final_result["severity"],
        "action": final_result["action"],
        "ml_score": anomaly_score,
        "timestamp": analysis["timestamp"]
    })
    
    # Keep only last 100
    if len(recent_analyses) > 100:
        recent_analyses.pop(0)
    
    return analysis


def forward_to_responder(analysis: dict) -> bool:
    """
    Forward analysis result to responder for action
    
    Args:
        analysis: Analysis result
        
    Returns:
        bool: Success status
    """
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AUTH_TOKEN}"
    }
    
    try:
        response = requests.post(RESPONDER_URL, json=analysis, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[Analyzer] 📤 Forwarded to responder: {analysis['event_id']}")
            return True
        else:
            print(f"[Analyzer] ❌ Responder returned {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[Analyzer] ❌ Responder not reachable at {RESPONDER_URL}")
        return False
    except Exception as e:
        print(f"[Analyzer] ❌ Forward error: {e}")
        return False


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze a security event
    
    Expected payload:
    {
        "id": "evt_123456",
        "kind": "ssh_failed",
        "src_ip": "192.168.1.100",
        "ts": "2024-12-29T12:00:00",
        "raw": "Failed password...",
        "anomaly_score": 0.85  (optional, from anomaly_detector)
    }
    
    Returns:
        Analysis result
    """
    
    # Authentication
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get event
    event = request.get_json()
    
    if not event or 'id' not in event:
        return jsonify({"error": "Invalid event format"}), 400
    
    # Analyze
    analysis = analyze_event(event)
    
    # Forward to responder
    forward_to_responder(analysis)
    
    return jsonify(analysis), 200


@app.route('/api/analysis', methods=['GET'])
def get_analysis():
    """Get recent analyses (API endpoint for dashboard)"""
    return jsonify({
        "analyses": recent_analyses[-50:],  # Last 50
        "total": len(recent_analyses)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get analyzer statistics"""
    return jsonify(analyzer_stats)


@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard to visualize analyzer statistics"""
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Security Analyzer</title>
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
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
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
                color: #f5576c;
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            
            .header .emoji {
                font-size: 3em;
                margin-bottom: 10px;
            }
            
            .header .badge {
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 10px 20px;
                border-radius: 25px;
                font-weight: 600;
                margin-top: 10px;
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
                margin: 10px 0;
            }
            
            .stat-value.high { color: #e74c3c; }
            .stat-value.medium { color: #f39c12; }
            .stat-value.low { color: #2ecc71; }
            
            .stat-label {
                color: #666;
                font-size: 1.1em;
                font-weight: 500;
            }
            
            .analyses-section {
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            
            .section-header h2 {
                color: #333;
                font-size: 1.8em;
            }
            
            .refresh-btn {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
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
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(245, 87, 108, 0.4);
            }
            
            .analysis-item {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-radius: 10px;
                border-left: 4px solid #f5576c;
            }
            
            .severity-badge {
                display: inline-block;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 600;
                color: white;
                margin-bottom: 5px;
            }
            
            .severity-high { background: #e74c3c; }
            .severity-medium { background: #f39c12; }
            .severity-low { background: #2ecc71; }
            
            .analysis-details {
                color: #555;
                margin-top: 5px;
            }
            
            .no-analyses {
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
                <div class="emoji">🤖</div>
                <h1>AI Security Analyzer</h1>
                <span class="badge">Powered by LM Studio</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="total-analyses">0</div>
                    <div class="stat-label">Total Analyses</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value high" id="high-severity">0</div>
                    <div class="stat-label">High Severity</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value medium" id="medium-severity">0</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value low" id="low-severity">0</div>
                    <div class="stat-label">Low Severity</div>
                </div>
            </div>
            
            <div class="analyses-section">
                <div class="section-header">
                    <h2>Recent Analyses</h2>
                    <button class="refresh-btn" onclick="loadAnalyses()">🔄 Refresh</button>
                </div>
                <div id="analyses-list"></div>
            </div>
        </div>
        
        <script>
            function loadStats() {
                fetch('/api/stats')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('total-analyses').textContent = data.total_analyzed;
                        document.getElementById('high-severity').textContent = data.by_severity.High || 0;
                        document.getElementById('medium-severity').textContent = data.by_severity.Medium || 0;
                        document.getElementById('low-severity').textContent = data.by_severity.Low || 0;
                    })
                    .catch(err => console.error('Error loading stats:', err));
            }
            
            function loadAnalyses() {
                fetch('/api/analysis')
                    .then(response => response.json())
                    .then(data => {
                        const analysesList = document.getElementById('analyses-list');
                        
                        if (data.analyses.length === 0) {
                            analysesList.innerHTML = '<div class="no-analyses">No analyses yet...</div>';
                            return;
                        }
                        
                        analysesList.innerHTML = data.analyses.reverse().slice(0, 20).map(analysis => `
                            <div class="analysis-item">
                                <span class="severity-badge severity-${analysis.severity.toLowerCase()}">${analysis.severity}</span>
                                <div class="analysis-details">
                                    <strong>IP:</strong> ${analysis.src_ip}<br>
                                    <strong>Kind:</strong> ${analysis.kind}<br>
                                    <strong>Action:</strong> ${analysis.action}
                                    ${analysis.ml_score > 0 ? `<br><strong>ML Score:</strong> ${analysis.ml_score.toFixed(3)}` : ''}
                                </div>
                            </div>
                        `).join('');
                    })
                    .catch(err => console.error('Error loading analyses:', err));
            }
            
            // Auto-refresh every 5 seconds
            setInterval(() => {
                loadStats();
                loadAnalyses();
            }, 5000);
            
            // Initial load
            loadStats();
            loadAnalyses();
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
    print("🤖 AI SECURITY ANALYZER STARTING")
    print("="*80)
    print(f"Port: {ANALYZER_PORT}")
    print(f"LM Studio: {LM_API_URL}")
    print(f"Heuristic Fallback: {USE_HEURISTIC_FALLBACK}")
    print(f"Anomaly Detection: {'ENABLED' if ENABLE_ANOMALY_DETECTION else 'DISABLED'}")
    if ENABLE_ANOMALY_DETECTION:
        print(f"Anomaly Threshold: {ANOMALY_THRESHOLD}")
    print("="*80)
    print(f"\n🌐 Dashboard: http://localhost:{ANALYZER_PORT}")
    print(f"📡 API endpoint: POST /analyze")
    print("="*80)
    
    app.run(host='0.0.0.0', port=ANALYZER_PORT, debug=False)
