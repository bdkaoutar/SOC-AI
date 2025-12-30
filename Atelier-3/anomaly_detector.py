#!/usr/bin/env python3
# anomaly_detector.py - Anomaly Detection Service
# Computes anomaly scores using trained Isolation Forest model

from flask import Flask, request, jsonify, render_template_string
import joblib
import json
import os
import sys
from datetime import datetime

# AJOUT: Ajouter le répertoire parent au path pour accéder à config.py
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(parent_dir, 'base'))

# Maintenant on peut importer config
from config import AUTH_TOKEN, ANOMALY_DETECTOR_PORT
from features import FeatureExtractor

app = Flask(__name__)

# Configuration
ANOMALY_DETECTOR_PORT = 5003
AUTH_TOKEN = "uFFdYgZHwioTZJU0dZXFeI4s4RfHfmXZThWqvXHaZwRu77Hx6q1mWzC7Bif57RrY"  # Should match config.py
MODEL_PATH = "anomaly_model.pkl"
SCALER_PATH = "anomaly_scaler.pkl"
MODEL_INFO_PATH = "model_info.json"

# Global variables
model = None
scaler = None
feature_extractor = None
feature_names = []
detection_history = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Anomaly Detector</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #8E2DE2 0%, #4A00E0 100%);
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
        h1 { color: #8E2DE2; font-size: 2.5em; }
        .ai-badge {
            background: linear-gradient(135deg, #8E2DE2 0%, #4A00E0 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
            font-weight: bold;
            margin-top: 10px;
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
            color: #8E2DE2;
        }
        .detections-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .detection-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #8E2DE2;
        }
        .score-badge {
            display: inline-block;
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
        }
        .score-low { background: #4CAF50; }
        .score-medium { background: #ff9800; }
        .score-high { background: #f5576c; }
        .refresh-btn {
            background: #8E2DE2;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
        }
        .model-status {
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .model-loaded { background: #d4edda; color: #155724; }
        .model-error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧠 Anomaly Detection System</h1>
            <div class="ai-badge">Isolation Forest ML Model</div>
            <div id="model-status" class="model-status">Loading...</div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total">0</div>
                <div>Total Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="high-risk">0</div>
                <div>High Risk (>0.7)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="medium-risk">0</div>
                <div>Medium Risk (0.4-0.7)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="low-risk">0</div>
                <div>Low Risk (<0.4)</div>
            </div>
        </div>

        <div class="detections-container">
            <div style="display:flex;justify-content:space-between;margin-bottom:20px;">
                <h2>Recent Detections</h2>
                <button class="refresh-btn" onclick="loadDetections()">🔄 Refresh</button>
            </div>
            <div id="detections-list"></div>
        </div>
    </div>

    <script>
        function loadDetections() {
            fetch('/api/detections')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    const detections = data.detections;
                    document.getElementById('total').textContent = detections.length;
                    document.getElementById('high-risk').textContent = detections.filter(d => d.anomaly_score > 0.7).length;
                    document.getElementById('medium-risk').textContent = detections.filter(d => d.anomaly_score >= 0.4 && d.anomaly_score <= 0.7).length;
                    document.getElementById('low-risk').textContent = detections.filter(d => d.anomaly_score < 0.4).length;

                    // Model status
                    const statusDiv = document.getElementById('model-status');
                    if (data.model_loaded) {
                        statusDiv.className = 'model-status model-loaded';
                        statusDiv.textContent = '✅ Model Loaded | AUC: ' + (data.model_info.auc_score || 'N/A').toFixed(3);
                    } else {
                        statusDiv.className = 'model-status model-error';
                        statusDiv.textContent = '❌ Model Not Loaded';
                    }

                    // Detections list
                    const list = document.getElementById('detections-list');
                    if (detections.length === 0) {
                        list.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No detections yet...</div>';
                        return;
                    }

                    list.innerHTML = detections.slice().reverse().map(item => {
                        const score = item.anomaly_score;
                        let scoreClass = 'score-low';
                        let riskLevel = 'Low Risk';
                        
                        if (score > 0.7) {
                            scoreClass = 'score-high';
                            riskLevel = 'High Risk';
                        } else if (score >= 0.4) {
                            scoreClass = 'score-medium';
                            riskLevel = 'Medium Risk';
                        }

                        return `
                        <div class="detection-card">
                            <span class="score-badge ${scoreClass}">${riskLevel} (${score.toFixed(3)})</span>
                            <div><strong>IP:</strong> ${item.event.src_ip}</div>
                            <div><strong>Type:</strong> ${item.event.kind}</div>
                            <div><strong>Time:</strong> ${new Date(item.timestamp).toLocaleString()}</div>
                        </div>
                        `;
                    }).join('');
                });
        }

        loadDetections();
        setInterval(loadDetections, 5000);
    </script>
</body>
</html>
"""

def load_model():
    """Load trained Isolation Forest model"""
    global model, scaler, feature_extractor, feature_names
    
    try:
        if not os.path.exists(MODEL_PATH):
            print(f"❌ Model file not found: {MODEL_PATH}")
            print("   Run train_model.ipynb first to train the model!")
            return False
        
        if not os.path.exists(SCALER_PATH):
            print(f"❌ Scaler file not found: {SCALER_PATH}")
            return False
        
        # Load model and scaler
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        
        # Load feature info
        if os.path.exists(MODEL_INFO_PATH):
            with open(MODEL_INFO_PATH, 'r') as f:
                info = json.load(f)
                feature_names = info.get('feature_names', [])
        
        # Initialize feature extractor
        feature_extractor = FeatureExtractor()
        
        print("="*80)
        print("✅ ANOMALY DETECTION MODEL LOADED")
        print("="*80)
        print(f"📊 Features: {len(feature_names)}")
        print(f"🎯 Model type: Isolation Forest")
        if os.path.exists(MODEL_INFO_PATH):
            print(f"📈 Training AUC: {info.get('auc_score', 'N/A'):.4f}")
        print("="*80 + "\n")
        
        return True
        
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

def compute_anomaly_score(event: dict) -> float:
    """
    Compute anomaly score for an event
    
    Args:
        event: Security event dict
    
    Returns:
        Anomaly score between 0 (normal) and 1 (highly anomalous)
    """
    if model is None or scaler is None or feature_extractor is None:
        print("⚠️ Model not loaded, returning default score")
        return 0.5
    
    try:
        # Extract features
        features_dict = feature_extractor.extract_features(event)
        
        # Convert to array in correct order
        features_array = []
        for fname in feature_names:
            features_array.append(features_dict.get(fname, 0))
        
        # Reshape for prediction
        import numpy as np
        X = np.array(features_array).reshape(1, -1)
        
        # Get raw score from Isolation Forest
        # More negative = more anomalous
        raw_score = -model.decision_function(X)[0]
        
        # Normalize to [0, 1]
        normalized_score = scaler.transform([[raw_score]])[0][0]
        
        # Clip to [0, 1] range
        normalized_score = max(0.0, min(1.0, normalized_score))
        
        return normalized_score
        
    except Exception as e:
        print(f"❌ Error computing score: {e}")
        return 0.5

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Get detection history and model status"""
    model_info = {}
    if os.path.exists(MODEL_INFO_PATH):
        with open(MODEL_INFO_PATH, 'r') as f:
            model_info = json.load(f)
    
    return jsonify({
        "detections": detection_history,
        "model_loaded": model is not None,
        "model_info": model_info
    })

@app.route('/detect', methods=['POST'])
def detect_anomaly():
    """
    Detect anomaly in event
    
    Expected input: {"event": {...}}
    Returns: {"event": {...}, "anomaly_score": 0.X}
    """
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data or 'event' not in data:
        return jsonify({"error": "Invalid request - missing 'event'"}), 400
    
    event = data['event']
    
    # Compute anomaly score
    anomaly_score = compute_anomaly_score(event)
    
    # Enrich event with anomaly score
    enriched_event = event.copy()
    enriched_event['anomaly_score'] = anomaly_score
    
    # Store in history
    detection_history.append({
        "event": event,
        "anomaly_score": anomaly_score,
        "timestamp": datetime.now().isoformat()
    })
    
    # Keep bounded
    if len(detection_history) > 100:
        detection_history.pop(0)
    
    print(f"[Anomaly Detector] {event.get('id')} → score: {anomaly_score:.3f}")
    
    return jsonify(enriched_event), 200

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🧠 ANOMALY DETECTOR STARTING")
    print("="*80)
    
    # Load model
    model_loaded = load_model()
    
    if not model_loaded:
        print("\n⚠️  WARNING: Model not loaded!")
        print("   The service will run but return default scores (0.5)")
        print("   To train the model, run: jupyter notebook train_model.ipynb\n")
    
    print(f"🌐 Dashboard: http://localhost:{ANOMALY_DETECTOR_PORT}")
    print(f"🔌 API endpoint: POST /detect")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=ANOMALY_DETECTOR_PORT, debug=False)
