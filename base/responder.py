#!/usr/bin/env python3
# responder.py - Core Response Agent (DO NOT MODIFY)
# Executes security responses (block IP, create ticket, etc.)
# MUST RUN AS ROOT: sudo python3 responder.py

from flask import Flask, request, jsonify, render_template_string
import subprocess
import json
import os
import sys
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import (AUTH_TOKEN, DRY_RUN, BLOCK_METHOD, ALERT_LOG_PATH,
                   WHITELIST_IPS, RESPONDER_PORT, KAFKA_ENABLED,
                   EMAIL_ENABLED, SMTP_SERVER, SMTP_PORT, SMTP_USER,
                   SMTP_PASSWORD, ALERT_EMAIL, EMAIL_ALERT_SEVERITIES)
from event_schema import ResponseAction

# Optional Kafka
if KAFKA_ENABLED:
    try:
        from kafka import KafkaConsumer
        import threading
        
        consumer = KafkaConsumer(
            'soc.decisions',
            bootstrap_servers=['localhost:9092'],
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        print("[Responder] Kafka consumer initialized")
    except ImportError:
        KAFKA_ENABLED = False

app = Flask(__name__)
response_history = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Responder</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
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
        h1 { color: #43e97b; font-size: 2.5em; }
        .mode-indicator {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 10px;
        }
        .mode-dry { background: #ff9800; color: white; }
        .mode-live { background: #f5576c; color: white; }
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
        .stat-number.blocked { color: #f5576c; }
        .stat-number.ticket { color: #ff9800; }
        .response-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .response-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
        }
        .response-card.blocked { border-left: 4px solid #f5576c; }
        .response-card.ticket { border-left: 4px solid #ff9800; }
        .action-badge {
            display: inline-block;
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
        }
        .action-blocked { background: #f5576c; }
        .action-ticket { background: #ff9800; }
        .refresh-btn {
            background: #43e97b;
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
            <h1>🚨 Security Response System</h1>
            <div class="mode-indicator" id="mode-indicator">Loading...</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total">0</div>
                <div>Total Responses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number blocked" id="blocked">0</div>
                <div>IPs Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-number ticket" id="tickets">0</div>
                <div>Tickets Created</div>
            </div>
        </div>
        
        <div class="response-container">
            <div style="display:flex;justify-content:space-between;margin-bottom:20px;">
                <h2>Recent Responses</h2>
                <button class="refresh-btn" onclick="loadResponses()">🔄 Refresh</button>
            </div>
            <div id="responses-list"></div>
        </div>
    </div>

    <script>
        function loadResponses() {
            fetch('/api/responses')
                .then(response => response.json())
                .then(data => {
                    const responses = data.responses;
                    document.getElementById('total').textContent = responses.length;
                    document.getElementById('blocked').textContent = responses.filter(r => r.action === 'block_ip').length;
                    document.getElementById('tickets').textContent = responses.filter(r => r.action === 'create_ticket').length;
                    
                    const modeIndicator = document.getElementById('mode-indicator');
                    if (data.dry_run) {
                        modeIndicator.textContent = '🧪 DRY RUN MODE';
                        modeIndicator.className = 'mode-indicator mode-dry';
                    } else {
                        modeIndicator.textContent = '⚠️ LIVE MODE';
                        modeIndicator.className = 'mode-indicator mode-live';
                    }
                    
                    const list = document.getElementById('responses-list');
                    if (responses.length === 0) {
                        list.innerHTML = '<div style="text-align:center;color:#999;padding:40px;">No responses yet...</div>';
                        return;
                    }
                    
                    list.innerHTML = responses.slice().reverse().map(item => {
                        const action = item.action || 'none';
                        let actionClass = action === 'block_ip' ? 'blocked' : 'ticket';
                        let actionLabel = action === 'block_ip' ? '🚫 IP Blocked' : '🎫 Ticket Created';
                        
                        return `
                        <div class="response-card ${actionClass}">
                            <div class="action-badge action-${actionClass}">${actionLabel}</div>
                            <div><strong>IP:</strong> ${item.event.src_ip}</div>
                            <div><strong>Severity:</strong> ${item.analysis.severity}</div>
                            ${item.executed_command ? `<div><strong>Command:</strong> ${item.executed_command}</div>` : ''}
                        </div>
                        `;
                    }).join('');
                });
        }
        loadResponses();
        setInterval(loadResponses, 5000);
    </script>
</body>
</html>
"""

def check_root():
    """Verify root privileges"""
    if os.geteuid() != 0:
        print("\n" + "="*80)
        print("❌ ERROR: Responder must run as root!")
        print("="*80)
        print(f"\nRun: sudo python3 {__file__}")
        print("="*80 + "\n")
        return False
    return True

def validate_command(command: str, ip: str) -> tuple[bool, str, str]:
    """Validate and sanitize blocking command"""
    if ip in WHITELIST_IPS:
        return (False, None, f"IP {ip} is whitelisted")
    
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return (False, None, f"Invalid IP: {ip}")
    
    # Remove sudo prefix
    cmd_parts = command.strip().split()
    if cmd_parts[0] == "sudo":
        cmd_parts = cmd_parts[1:]
    
    allowed = ["ufw", "iptables"]
    if not cmd_parts or cmd_parts[0] not in allowed:
        return (False, None, f"Invalid command")
    
    sanitized = " ".join(cmd_parts)
    
    if ip not in sanitized:
        return (False, None, f"IP not in command")
    
    dangerous = [';', '&&', '||', '`', '$', '>', '<', '|']
    for char in dangerous:
        if char in sanitized:
            return (False, None, f"Dangerous character: {char}")
    
    return (True, sanitized, None)

def execute_block(command: str, ip: str) -> dict:
    """Execute blocking command"""
    is_valid, sanitized, error = validate_command(command, ip)
    
    if not is_valid:
        print(f"[Responder] ❌ Invalid command: {error}")
        return {"success": False, "reason": error}
    
    if DRY_RUN:
        print(f"[Responder] 🧪 DRY RUN: {sanitized}")
        return {"success": True, "command": sanitized, "simulated": True}
    
    try:
        print(f"[Responder] 🔒 Executing: {sanitized}")
        result = subprocess.run(sanitized, shell=True, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Reload firewall
            subprocess.run("ufw reload", shell=True, capture_output=True, timeout=10)
            print(f"[Responder] ✅ Command executed successfully")
            return {"success": True, "command": sanitized, "output": result.stdout}
        else:
            print(f"[Responder] ❌ Command failed: {result.stderr}")
            return {"success": False, "reason": result.stderr}
            
    except Exception as e:
        print(f"[Responder] ❌ Error: {e}")
        return {"success": False, "reason": str(e)}

def send_email(event: dict, analysis: dict, action_result: dict) -> bool:
    """Send email notification"""
    if not EMAIL_ENABLED:
        return False
    
    severity = analysis.get("severity", "Unknown")
    if severity not in EMAIL_ALERT_SEVERITIES:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['Subject'] = f"[SOC] {severity} - {event.get('src_ip')}"
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        
        body = f"""
Security Alert - {severity}

Event: {event.get('kind')}
Source IP: {event.get('src_ip')}
Action: {analysis.get('recommended_action')}
Justification: {analysis.get('justification', 'N/A')}

Command: {action_result.get('command_executed', 'N/A')}
Mode: {'DRY RUN' if DRY_RUN else 'LIVE'}
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"[Responder] ✅ Email sent")
        return True
        
    except Exception as e:
        print(f"[Responder] ❌ Email failed: {e}")
        return False

def log_alert(event: dict, analysis: dict, action_result: dict):
    """Log alert to file"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "analysis": analysis,
        "action": action_result,
        "dry_run": DRY_RUN
    }
    
    try:
        with open(ALERT_LOG_PATH, "a") as f:
            f.write(json.dumps(log_entry, indent=2) + "\n" + "="*80 + "\n")
    except Exception as e:
        print(f"[Responder] Log error: {e}")

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/responses')
def get_responses():
    return jsonify({"responses": response_history, "dry_run": DRY_RUN})

@app.route('/respond', methods=['POST'])
def respond():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data or 'event' not in data or 'analysis' not in data:
        return jsonify({"error": "Invalid data"}), 400
    
    event = data['event']
    analysis = data['analysis']
    action = analysis.get('recommended_action')
    
    print(f"[Responder] 🔥 Processing: {action}")
    
    action_result = {
        "action_taken": action,
        "timestamp": datetime.now().isoformat(),
        "command_executed": None,
        "success": False,
        "email_sent": False
    }
    
    if action == "block_ip":
        ip = analysis.get('target_ip') or event.get('src_ip')
        command = analysis.get('block_command', f"ufw insert 1 deny from {ip}")
        
        result = execute_block(command, ip)
        action_result["command_executed"] = command
        action_result["success"] = result.get("success", False)
        
    elif action == "create_ticket":
        print(f"[Responder] 🎫 Creating ticket")
        action_result["success"] = True
        
    else:  # ignore
        print(f"[Responder] ❌ Ignoring event")
        action_result["success"] = True
    
    # Email
    action_result["email_sent"] = send_email(event, analysis, action_result)
    
    # Log
    log_alert(event, analysis, action_result)
    
    # Store
    response_history.append({
        "event": event,
        "analysis": analysis,
        "action": action,
        "executed_command": action_result.get("command_executed"),
        "timestamp": action_result["timestamp"],
        "success": action_result["success"],
        "email_sent": action_result["email_sent"]
    })
    
    if len(response_history) > 100:
        response_history.pop(0)
    
    return jsonify({"status": "ok", "action": action}), 200

def kafka_consumer_loop():
    """Kafka consumer for Atelier B"""
    print("[Responder] Starting Kafka consumer...")
    for message in consumer:
        data = message.value
        # Process same as HTTP endpoint
        # (simplified for brevity)
        pass

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚨 RESPONDER AGENT STARTING")
    print("="*80)
    
    if not check_root():
        sys.exit(1)
    
    print(f"✅ Root privileges confirmed")
    print(f"🔌 Mode: {'Kafka' if KAFKA_ENABLED else 'HTTP'}")
    print(f"🧪 DRY_RUN: {DRY_RUN}")
    print(f"🔒 Method: {BLOCK_METHOD}")
    print(f"📧 Email: {'Enabled' if EMAIL_ENABLED else 'Disabled'}")
    print(f"🌐 Port: {RESPONDER_PORT}")
    print("="*80 + "\n")
    
    if KAFKA_ENABLED:
        kafka_thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
        kafka_thread.start()
    
    app.run(host='0.0.0.0', port=RESPONDER_PORT)