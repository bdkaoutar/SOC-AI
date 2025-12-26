#!/usr/bin/env python3
"""
TRUST AGENT - Role: Calibrate AI confidence scores
-------------------------------------------------
This service receives analysis from the Analyzer and adjusts
the confidence score to be more realistic using two methods:
1. Temperature Scaling
2. Platt Scaling
"""

from flask import Flask, request, jsonify, render_template_string
import numpy as np
import json
import os
from datetime import datetime

app = Flask(__name__)

# ============================================================================
# GLOBAL VARIABLES - Store calibration settings
# ============================================================================
calibration_history = []  # Stores all calibrations for dashboard

# Default calibration parameters (will be updated by training)
CALIBRATION_METHOD = "temperature"  # "platt" or "temperature"
TEMPERATURE = 1.5  # T > 1 reduces overconfidence
PLATT_A = 1.0      # Platt scaling parameter a
PLATT_B = 0.0      # Platt scaling parameter b

# ============================================================================
# FUNCTION 1: Load trained calibration parameters from file
# ============================================================================
def load_calibration_params():
    """
    Role: Load previously trained calibration parameters
    When: At startup, so we use the best parameters from training
    """
    global TEMPERATURE, PLATT_A, PLATT_B, CALIBRATION_METHOD
    
    if os.path.exists('calibration_params.json'):
        with open('calibration_params.json', 'r') as f:
            params = json.load(f)
            CALIBRATION_METHOD = params.get('method', 'temperature')
            TEMPERATURE = params.get('temperature', 1.5)
            PLATT_A = params.get('platt_a', 1.0)
            PLATT_B = params.get('platt_b', 0.0)
        print(f"[Trust Agent] ✅ Loaded calibration params: method={CALIBRATION_METHOD}")
    else:
        print(f"[Trust Agent] ⚠️  No calibration params found, using defaults")

# ============================================================================
# FUNCTION 2: Temperature Scaling
# ============================================================================
def temperature_scaling(confidence, temperature=1.5):
    """
    Role: Apply temperature scaling to reduce overconfidence
    
    How it works:
    1. Convert probability to logit: logit = log(p / (1-p))
    2. Divide by temperature: scaled_logit = logit / T
    3. Convert back to probability: p_new = 1 / (1 + exp(-scaled_logit))
    
    Effect:
    - T = 1.0: No change
    - T > 1.0: Reduces confidence (less overconfident)
    - T < 1.0: Increases confidence (more confident)
    
    Example:
    - Input: confidence = 0.9, temperature = 1.5
    - Output: ~0.75 (less confident)
    """
    # Handle edge cases
    if confidence <= 0:
        return 0.001
    if confidence >= 1:
        return 0.999
    
    import math
    
    # Step 1: Convert probability to logit
    # Logit is the log-odds: log(p / (1-p))
    logit = math.log(confidence / (1 - confidence))
    
    # Step 2: Scale by temperature
    # Higher T = smaller scaled_logit = less confident
    scaled_logit = logit / temperature
    
    # Step 3: Convert back to probability using sigmoid
    # sigmoid(x) = 1 / (1 + exp(-x))
    calibrated = 1 / (1 + math.exp(-scaled_logit))
    
    return calibrated

# ============================================================================
# FUNCTION 3: Platt Scaling
# ============================================================================
def platt_scaling(confidence, a=1.0, b=0.0):
    """
    Role: Apply Platt scaling (trained logistic regression)
    
    How it works:
    1. Convert to logit
    2. Apply linear transformation: scaled_logit = a * logit + b
    3. Convert back to probability
    
    Parameters a and b are learned from training data using logistic regression
    
    Example:
    - Input: confidence = 0.9, a = 0.8, b = -0.2
    - Output: ~0.72 (calibrated based on training)
    """
    if confidence <= 0:
        return 0.001
    if confidence >= 1:
        return 0.999
    
    import math
    
    # Convert to logit
    logit = math.log(confidence / (1 - confidence))
    
    # Apply Platt transformation
    scaled_logit = a * logit + b
    
    # Convert back to probability
    calibrated = 1 / (1 + math.exp(-scaled_logit))
    
    return calibrated

# ============================================================================
# FUNCTION 4: Main Calibration Endpoint (THE HEART OF ATELIER A)
# ============================================================================
@app.route('/calibrate', methods=['POST'])
def calibrate():
    """
    Role: Main API endpoint - receives analysis, returns calibrated analysis
    
    Flow:
    1. Receive event + analysis from Analyzer
    2. Extract original confidence score
    3. Apply calibration (temperature or platt)
    4. Add calibrated_confidence to analysis
    5. Optionally adjust severity based on new confidence
    6. Return calibrated analysis to continue to Responder
    
    Input JSON:
    {
      "event": {"id": "evt-123", "kind": "ssh_failed", "src_ip": "1.2.3.4", ...},
      "analysis": {"confidence": 0.85, "severity": "High", ...}
    }
    
    Output JSON:
    {
      "confidence": 0.85,           ← Original
      "original_confidence": 0.85,  ← Saved for comparison
      "calibrated_confidence": 0.65, ← NEW: More realistic
      "severity": "Medium",          ← Adjusted based on calibrated confidence
      ...
    }
    """
    # Validate input
    data = request.json
    if not data or 'analysis' not in data or 'event' not in data:
        return jsonify({"error": "Invalid input"}), 400
    
    analysis = data['analysis']
    event = data['event']
    
    # Extract original confidence from LM
    original_confidence = analysis.get('confidence', 0.5)
    
    # Apply calibration based on chosen method
    if CALIBRATION_METHOD == "temperature":
        calibrated_confidence = temperature_scaling(original_confidence, TEMPERATURE)
    elif CALIBRATION_METHOD == "platt":
        calibrated_confidence = platt_scaling(original_confidence, PLATT_A, PLATT_B)
    else:
        calibrated_confidence = original_confidence  # No calibration
    
    # Ensure bounds [0.001, 0.999]
    calibrated_confidence = max(0.001, min(0.999, calibrated_confidence))
    
    # Add both confidences to analysis
    analysis['calibrated_confidence'] = round(calibrated_confidence, 3)
    analysis['original_confidence'] = round(original_confidence, 3)
    
    # Adjust severity based on CALIBRATED confidence (not original)
    # This is important: we now make decisions based on realistic confidence
    if calibrated_confidence >= 0.7:
        analysis['severity'] = 'High'
    elif calibrated_confidence >= 0.4:
        analysis['severity'] = 'Medium'
    else:
        analysis['severity'] = 'Low'
    
    # Store for dashboard visualization
    calibration_history.append({
        "event_kind": event.get('kind', 'unknown'),
        "source_ip": event.get('src_ip', 'unknown'),
        "original_confidence": round(original_confidence, 3),
        "calibrated_confidence": round(calibrated_confidence, 3),
        "severity": analysis['severity'],
        "timestamp": datetime.now().isoformat()
    })
    
    # Keep only last 100 entries in memory
    if len(calibration_history) > 100:
        calibration_history.pop(0)
    
    # Log the calibration
    print(f"[Trust Agent] {event.get('kind')} from {event.get('src_ip')}: "
          f"{original_confidence:.3f} → {calibrated_confidence:.3f} "
          f"({CALIBRATION_METHOD})")
    
    # Return calibrated analysis (will go to Responder next)
    return jsonify(analysis), 200

# ============================================================================
# FUNCTION 5: Dashboard - Visualize calibrations in real-time
# ============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Trust Agent - Calibration Dashboard</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
        h1 { color: #667eea; font-size: 2.5em; margin-bottom: 10px; }
        .badge {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
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
            color: #667eea;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 10px;
        }
        .calibrations-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .calibration-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        .confidence-display {
            display: flex;
            align-items: center;
            gap: 20px;
            margin: 10px 0;
        }
        .confidence-bar {
            flex: 1;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s;
        }
        .confidence-label {
            font-weight: bold;
            min-width: 150px;
        }
        .arrow {
            font-size: 1.5em;
            color: #667eea;
            text-align: center;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #5568d3;
            transform: translateY(-2px);
        }
        .method-indicator {
            background: #4CAF50;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Trust Agent - Confidence Calibration</h1>
            <div class="badge">Atelier A - Reducing AI Overconfidence</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-calibrations">0</div>
                <div class="stat-label">Total Calibrations</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="avg-original">0.00</div>
                <div class="stat-label">Avg Original Confidence</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="avg-calibrated">0.00</div>
                <div class="stat-label">Avg Calibrated Confidence</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="calibration-method">TEMP</div>
                <div class="stat-label">Method</div>
            </div>
        </div>
        
        <div class="calibrations-container">
            <div style="display:flex;justify-content:space-between;margin-bottom:20px;">
                <h2>Recent Calibrations (Before → After)</h2>
                <button class="refresh-btn" onclick="loadCalibrations()">🔄 Refresh</button>
            </div>
            <div id="calibrations-list"></div>
        </div>
    </div>

    <script>
        function loadCalibrations() {
            fetch('/api/calibrations')
                .then(response => response.json())
                .then(data => {
                    const calibrations = data.calibrations;
                    
                    // Update statistics
                    document.getElementById('total-calibrations').textContent = calibrations.length;
                    document.getElementById('calibration-method').textContent = data.method.toUpperCase();
                    
                    if (calibrations.length > 0) {
                        const avgOriginal = calibrations.reduce((sum, c) => sum + c.original_confidence, 0) / calibrations.length;
                        const avgCalibrated = calibrations.reduce((sum, c) => sum + c.calibrated_confidence, 0) / calibrations.length;
                        document.getElementById('avg-original').textContent = avgOriginal.toFixed(3);
                        document.getElementById('avg-calibrated').textContent = avgCalibrated.toFixed(3);
                    }
                    
                    // Display calibration cards
                    const list = document.getElementById('calibrations-list');
                    if (calibrations.length === 0) {
                        list.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No calibrations yet. Generate some attacks!</div>';
                        return;
                    }
                    
                    list.innerHTML = calibrations.slice().reverse().slice(0, 20).map(item => {
                        const original = item.original_confidence;
                        const calibrated = item.calibrated_confidence;
                        const change = ((calibrated - original) / original * 100).toFixed(1);
                        const changeIcon = calibrated > original ? '📈' : '📉';
                        
                        return `
                        <div class="calibration-card">
                            <div style="margin-bottom:10px;">
                                <strong>Event:</strong> ${item.event_kind} from ${item.source_ip}
                                <span class="method-indicator">${data.method}</span>
                            </div>
                            <div class="confidence-display">
                                <div class="confidence-label">Original: ${original.toFixed(3)}</div>
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: ${original * 100}%"></div>
                                </div>
                            </div>
                            <div style="text-align:center" class="arrow">⬇️ CALIBRATION</div>
                            <div class="confidence-display">
                                <div class="confidence-label">Calibrated: ${calibrated.toFixed(3)}</div>
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: ${calibrated * 100}%"></div>
                                </div>
                            </div>
                            <div style="margin-top:10px;color:#666;">
                                ${changeIcon} Change: ${change}% | 
                                New Severity: ${item.severity} | 
                                Time: ${item.timestamp.split('T')[1].split('.')[0]}
                            </div>
                        </div>
                        `;
                    }).join('');
                });
        }
        
        loadCalibrations();
        setInterval(loadCalibrations, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Role: Serve the web dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/calibrations', methods=['GET'])
def get_calibrations():
    """Role: API endpoint to get calibration history for dashboard"""
    return jsonify({
        "calibrations": calibration_history,
        "method": CALIBRATION_METHOD,
        "temperature": TEMPERATURE if CALIBRATION_METHOD == "temperature" else None,
        "platt_params": {"a": PLATT_A, "b": PLATT_B} if CALIBRATION_METHOD == "platt" else None
    })

# ============================================================================
# FUNCTION 6: Health Check
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    """Role: Simple health check endpoint"""
    return jsonify({
        "status": "ok",
        "method": CALIBRATION_METHOD,
        "total_calibrations": len(calibration_history)
    })

# ============================================================================
# FUNCTION 7: Update Parameters (for testing different calibrations)
# ============================================================================
@app.route('/set_params', methods=['POST'])
def set_params():
    """
    Role: Allow dynamic parameter updates for experimentation
    
    Example usage:
    curl -X POST http://localhost:6004/set_params \
         -H "Content-Type: application/json" \
         -d '{"method": "temperature", "temperature": 2.0}'
    """
    global CALIBRATION_METHOD, TEMPERATURE, PLATT_A, PLATT_B
    
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input"}), 400
    
    CALIBRATION_METHOD = data.get('method', CALIBRATION_METHOD)
    TEMPERATURE = data.get('temperature', TEMPERATURE)
    PLATT_A = data.get('platt_a', PLATT_A)
    PLATT_B = data.get('platt_b', PLATT_B)
    
    # Save to file
    params = {
        'method': CALIBRATION_METHOD,
        'temperature': TEMPERATURE,
        'platt_a': PLATT_A,
        'platt_b': PLATT_B
    }
    
    with open('calibration_params.json', 'w') as f:
        json.dump(params, f, indent=2)
    
    print(f"[Trust Agent] Updated params: {params}")
    
    return jsonify({"status": "ok", "params": params}), 200

# ============================================================================
# MAIN: Start the Flask server
# ============================================================================
if __name__ == "__main__":
    print("\n" + "="*80)
    print("🔐 TRUST AGENT STARTING (Atelier A)")
    print("="*80)
    print("📊 Calibration Methods: Temperature Scaling & Platt Scaling")
    print("🌐 Dashboard: http://localhost:6004")
    print("🔌 API Endpoint: POST /calibrate")
    print("📈 Purpose: Reduce AI overconfidence by calibrating probability scores")
    print("="*80 + "\n")
    
    # Load any previously trained parameters
    load_calibration_params()
    
    # Start Flask server on port 6004
    app.run(host='0.0.0.0', port=6004, debug=False)
