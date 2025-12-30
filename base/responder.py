#!/usr/bin/env python3
# responder.py - Blocage RÉEL des IPs avec priorité UFW

from flask import Flask, request, jsonify, render_template_string
import subprocess
import json
import os
from datetime import datetime
from collections import defaultdict
import sys

# Import configuration
try:
    from config import (
        AUTH_TOKEN,
        RESPONDER_PORT,
        DRY_RUN,
        BLOCK_METHOD,
        ALERT_LOG_PATH
    )
except ImportError as e:
    print(f"[Config] Error: {e}")
    AUTH_TOKEN = "uFFdYgZHwioTZJU0dZXFeI4s4RfHfmXZThWqvXHaZwRu77Hx6q1mWzC7Bif57RrY"
    RESPONDER_PORT = 6003
    DRY_RUN = False
    BLOCK_METHOD = "ufw"
    ALERT_LOG_PATH = "/tmp/alerts.log"

app = Flask(__name__)

# Statistics
responder_stats = {
    "total_responses": 0,
    "ips_blocked": 0,
    "tickets_created": 0,
    "by_severity": defaultdict(int)
}

recent_responses = []
blocked_ips = set()

def block_ip(ip: str, reason: str = "") -> bool:
    """
    Block an IP address using UFW or iptables
    IMPORTANT: Insère la règle en POSITION 1 pour avoir priorité sur ALLOW rules
    """
    if ip in blocked_ips:
        print(f"[Responder] ⚠️  IP {ip} already blocked")
        return True
    
    if DRY_RUN:
        print(f"[Responder] 🧪 DRY RUN: Would block IP {ip}")
        blocked_ips.add(ip)
        return True
    
    try:
        if BLOCK_METHOD == "ufw":
            # CRITIQUE: Insérer en position 1 pour avoir priorité sur les règles ALLOW
            # Utiliser 'ufw insert 1' au lieu de 'ufw deny'
            cmd = ["ufw", "insert", "1", "deny", "from", ip]
            
            print(f"[Responder] 🔒 Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"[Responder] 🚫 Blocked IP {ip} (inserted at position 1)")
                blocked_ips.add(ip)
                
                # Log l'action
                log_action("block_ip", ip, reason)
                
                # Vérifier que la règle est bien créée
                verify_cmd = ["ufw", "status", "numbered"]
                verify_result = subprocess.run(
                    verify_cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if ip in verify_result.stdout:
                    print(f"[Responder] ✅ Verified: Rule for {ip} is active")
                else:
                    print(f"[Responder] ⚠️  Warning: Rule may not be active")
                
                return True
            else:
                print(f"[Responder] ❌ UFW block failed: {result.stderr}")
                return False
                
        elif BLOCK_METHOD == "iptables":
            # Alternative: bloquer avec iptables directement
            # Insérer en position 1 dans la chaîne INPUT
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            
            print(f"[Responder] 🔒 Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"[Responder] 🚫 Blocked IP {ip} with iptables")
                blocked_ips.add(ip)
                log_action("block_ip", ip, reason)
                return True
            else:
                print(f"[Responder] ❌ iptables block failed: {result.stderr}")
                return False
        else:
            print(f"[Responder] ❌ Unknown block method: {BLOCK_METHOD}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[Responder] ❌ Block command timeout for {ip}")
        return False
    except Exception as e:
        print(f"[Responder] ❌ Block error: {e}")
        import traceback
        traceback.print_exc()
        return False


def unblock_ip(ip: str) -> bool:
    """
    Débloquer une IP (pour tests ou faux positifs)
    """
    try:
        if BLOCK_METHOD == "ufw":
            cmd = ["ufw", "delete", "deny", "from", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[Responder] ✅ Unblocked IP {ip}")
                blocked_ips.discard(ip)
                return True
            else:
                print(f"[Responder] ❌ Unblock failed: {result.stderr}")
                return False
                
        elif BLOCK_METHOD == "iptables":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[Responder] ✅ Unblocked IP {ip}")
                blocked_ips.discard(ip)
                return True
            else:
                return False
    except Exception as e:
        print(f"[Responder] ❌ Unblock error: {e}")
        return False


def create_ticket(event_id: str, ip: str, severity: str, reason: str) -> bool:
    """Create a security ticket"""
    ticket = {
        "ticket_id": f"TKT-{event_id}",
        "event_id": event_id,
        "ip": ip,
        "severity": severity,
        "reason": reason,
        "created_at": datetime.now().isoformat(),
        "status": "open"
    }
    
    print(f"[Responder] 🎫 Created ticket {ticket['ticket_id']} for {ip} ({severity})")
    
    log_action("create_ticket", ip, reason, ticket_data=ticket)
    
    return True


def log_action(action: str, ip: str, reason: str, ticket_data: dict = None):
    """Log action to file"""
    try:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "ip": ip,
            "reason": reason,
            "dry_run": DRY_RUN
        }
        
        if ticket_data:
            log_entry["ticket"] = ticket_data
        
        with open(ALERT_LOG_PATH, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
            
    except Exception as e:
        print(f"[Responder] ⚠️  Log write error: {e}")


def execute_action(analysis: dict) -> dict:
    """Execute security action"""
    event_id = analysis.get('event_id', 'unknown')
    event = analysis.get('event', {})
    src_ip = event.get('src_ip', 'unknown')
    severity = analysis.get('severity', 'Low')
    action = analysis.get('action', 'ignore')
    reasoning = analysis.get('reasoning', 'No reason')
    
    print(f"\n[Responder] 📥 Processing: {event_id} (IP: {src_ip}, Action: {action})")
    
    result = {
        "event_id": event_id,
        "ip": src_ip,
        "action": action,
        "severity": severity,
        "success": False,
        "timestamp": datetime.now().isoformat()
    }
    
    if action == "block_ip":
        success = block_ip(src_ip, reasoning)
        result["success"] = success
        if success:
            responder_stats["ips_blocked"] += 1
    
    elif action == "create_ticket":
        success = create_ticket(event_id, src_ip, severity, reasoning)
        result["success"] = success
        if success:
            responder_stats["tickets_created"] += 1
    
    elif action == "ignore":
        print(f"[Responder] ⏭️  Ignoring event {event_id}")
        result["success"] = True
    
    else:
        print(f"[Responder] ❌ Unknown action: {action}")
        result["success"] = False
    
    responder_stats["total_responses"] += 1
    responder_stats["by_severity"][severity] += 1
    
    recent_responses.append({
        "event_id": event_id,
        "ip": src_ip,
        "action": action,
        "severity": severity,
        "success": result["success"],
        "timestamp": result["timestamp"]
    })
    
    if len(recent_responses) > 100:
        recent_responses.pop(0)
    
    return result


@app.route('/respond', methods=['POST'])
def respond():
    """Receive analysis from analyzer"""
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    analysis = request.get_json()
    
    if not analysis:
        return jsonify({"error": "No JSON data"}), 400
    
    if 'event_id' not in analysis:
        return jsonify({"error": "Missing event_id"}), 400
    
    if 'action' not in analysis:
        return jsonify({"error": "Missing action"}), 400
    
    result = execute_action(analysis)
    return jsonify(result), 200


@app.route('/api/responses', methods=['GET'])
def get_responses():
    """Get recent responses"""
    return jsonify({
        "responses": recent_responses[-50:],
        "total": len(recent_responses)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics"""
    return jsonify(responder_stats)


@app.route('/api/blocked_ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    return jsonify({
        "blocked_ips": list(blocked_ips),
        "total": len(blocked_ips)
    })


@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock_ip(ip):
    """API endpoint to unblock an IP (pour débloquer manuellement)"""
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    success = unblock_ip(ip)
    return jsonify({"ip": ip, "unblocked": success}), 200 if success else 500


@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard HTML"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Response System</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; background: linear-gradient(135deg, #2ecc71, #27ae60); padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { background: white; padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 30px; }
            .header h1 { color: #27ae60; font-size: 2.5em; }
            .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: white; padding: 30px; border-radius: 15px; text-align: center; }
            .stat-value { font-size: 3em; font-weight: bold; margin: 10px 0; }
            .responses { background: white; padding: 30px; border-radius: 15px; margin-bottom: 30px; }
            .blocked-ips { background: white; padding: 30px; border-radius: 15px; }
            .response-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 10px; }
            .ip-item { background: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 5px; border-left: 4px solid #e74c3c; }
            .btn { background: #27ae60; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; }
            .btn:hover { background: #229954; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 Security Response System</h1>
                <span style="background: #e74c3c; color: white; padding: 10px 20px; border-radius: 25px;">⚠️ LIVE MODE</span>
            </div>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="total">0</div>
                    <div>Total Responses</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #e74c3c;" id="blocked">0</div>
                    <div>IPs Blocked</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f39c12;" id="tickets">0</div>
                    <div>Tickets Created</div>
                </div>
            </div>
            <div class="responses">
                <h2>Recent Responses <button class="btn" onclick="load()">🔄 Refresh</button></h2>
                <div id="list"></div>
            </div>
            <div class="blocked-ips">
                <h2>🚫 Blocked IPs</h2>
                <div id="blocked-list"></div>
            </div>
        </div>
        <script>
            function load() {
                fetch('/api/stats').then(r => r.json()).then(d => {
                    document.getElementById('total').textContent = d.total_responses;
                    document.getElementById('blocked').textContent = d.ips_blocked;
                    document.getElementById('tickets').textContent = d.tickets_created;
                });
                fetch('/api/responses').then(r => r.json()).then(d => {
                    const list = document.getElementById('list');
                    if (d.responses.length === 0) {
                        list.innerHTML = '<p style="text-align:center; color:#999;">No responses yet...</p>';
                    } else {
                        list.innerHTML = d.responses.reverse().slice(0, 20).map(r => `
                            <div class="response-item">
                                <strong>${r.action.toUpperCase()}</strong><br>
                                IP: ${r.ip} | Severity: ${r.severity} | ${r.success ? '✅ Success' : '❌ Failed'}
                            </div>
                        `).join('');
                    }
                });
                fetch('/api/blocked_ips').then(r => r.json()).then(d => {
                    const blockedList = document.getElementById('blocked-list');
                    if (d.blocked_ips.length === 0) {
                        blockedList.innerHTML = '<p style="text-align:center; color:#999;">No blocked IPs yet...</p>';
                    } else {
                        blockedList.innerHTML = d.blocked_ips.map(ip => `
                            <div class="ip-item">
                                🚫 ${ip}
                            </div>
                        `).join('');
                    }
                });
            }
            setInterval(load, 5000);
            load();
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


if __name__ == '__main__':
    # Vérifier les privilèges root
    if os.geteuid() != 0 and not DRY_RUN:
        print("="*80)
        print("⚠️  ERROR: Root privileges required!")
        print("="*80)
        print("This script needs root access to modify firewall rules.")
        print("")
        print("Please run with:")
        print(f"  sudo python3 {sys.argv[0]}")
        print("")
        print("Or set DRY_RUN=True in config.py for testing without root.")
        print("="*80)
        sys.exit(1)
    
    print("="*80)
    print("🚨 RESPONDER AGENT STARTING")
    print("="*80)
    
    if os.geteuid() == 0:
        print("✅ Root privileges confirmed")
    
    print(f"Port: {RESPONDER_PORT}")
    print(f"DRY_RUN: {DRY_RUN}")
    print(f"Block method: {BLOCK_METHOD}")
    print(f"Alert log: {ALERT_LOG_PATH}")
    print("="*80)
    print(f"\n🌐 Dashboard: http://localhost:{RESPONDER_PORT}")
    print(f"📡 API endpoint: POST /respond")
    print(f"🚫 Blocked IPs: GET /api/blocked_ips")
    print("="*80)
    
    app.run(host='0.0.0.0', port=RESPONDER_PORT, debug=False)
