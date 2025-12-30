#!/usr/bin/env python3
# config.py - Unified Configuration for SOC-AI System

import os

# ============================================================================
# AUTHENTICATION
# ============================================================================
AUTH_TOKEN = "uFFdYgZHwioTZJU0dZXFeI4s4RfHfmXZThWqvXHaZwRu77Hx6q1mWzC7Bif57RrY"

# ============================================================================
# NETWORK & PORTS
# ============================================================================
SENSOR_PORT = 6000
COLLECTOR_PORT = 6001
ANALYZER_PORT = 6002
RESPONDER_PORT = 6003
ANOMALY_DETECTOR_PORT = 5003  # Atelier C - Port unique!

# Additional ports for other ateliers
TRUST_AGENT_PORT = 6004      # Atelier A
SUPERVISOR_PORT = 6005        # Atelier B
MITRE_MAPPER_PORT = 6007      # Atelier D
XAI_EXPLAINER_PORT = 6008     # Atelier D

# ============================================================================
# LM STUDIO API (Windows Host)
# ============================================================================
LM_HOST_IP = "192.168.137.161"
LM_API_URL = f"http://{LM_HOST_IP}:1234/v1/chat/completions"
LM_MODEL = "mistral-7b-instruct-v0.3"
LM_TIMEOUT = 30

# ============================================================================
# INTERNAL API ENDPOINTS
# ============================================================================
COLLECTOR_URL = f"http://127.0.0.1:{COLLECTOR_PORT}/event"
ANALYZER_URL = f"http://127.0.0.1:{ANALYZER_PORT}/analyze"
RESPONDER_URL = f"http://127.0.0.1:{RESPONDER_PORT}/respond"
ANOMALY_DETECTOR_URL = f"http://localhost:{ANOMALY_DETECTOR_PORT}/detect"  # Atelier C

# Atelier extension URLs
TRUST_AGENT_URL = f"http://127.0.0.1:{TRUST_AGENT_PORT}/calibrate"
MITRE_MAPPER_URL = f"http://127.0.0.1:{MITRE_MAPPER_PORT}/map"
XAI_EXPLAINER_URL = f"http://127.0.0.1:{XAI_EXPLAINER_PORT}/explain"

# ============================================================================
# KAFKA/RABBITMQ SETTINGS (Atelier B)
# ============================================================================
KAFKA_ENABLED = False
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPICS = {
    "events_raw": "soc.events.raw",
    "events_to_analyze": "soc.events.analyze",
    "decisions": "soc.decisions"
}

# ============================================================================
# LOG MONITORING
# ============================================================================
LOGS_TO_MONITOR = [
    "/var/log/auth.log",
    "/var/log/ufw.log",
    "/var/log/nginx/access.log"
]
LOGS_TO_MONITOR = [log for log in LOGS_TO_MONITOR if log and os.path.exists(log)]

# ============================================================================
# HEURISTICS & THRESHOLDS
# ============================================================================
HEURISTICS = {
    "ssh_failed": {
        "pattern": r"Failed password.*ssh",
        "severity_threshold": 3,
        "category": "brute_force",
        "default_action": "block_ip"
    },
    "port_scan": {
        "pattern": r"UFW BLOCK.*PROTO=TCP.*DPT",
        "severity_threshold": 5,
        "category": "port_scan",
        "default_action": "create_ticket"
    },
    "web_fuzz": {
        "pattern": r" 404 ",
        "severity_threshold": 10,
        "category": "web_fuzz",
        "default_action": "create_ticket"
    }
}

# ============================================================================
# RESPONDER SETTINGS
# ============================================================================
DRY_RUN = False  # Set to True to simulate actions without executing
BLOCK_METHOD = "ufw"  # "ufw" or "iptables"
ALERT_LOG_PATH = "/tmp/alerts.log"
WEBHOOK_URL = None

# ============================================================================
# EMAIL NOTIFICATION SETTINGS
# ============================================================================
EMAIL_ENABLED = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = ""
SMTP_PASSWORD = ""
ALERT_EMAIL = ""
EMAIL_ALERT_SEVERITIES = ["High", "Medium"]

# ============================================================================
# SECURITY - WHITELISTED IPs
# ============================================================================
WHITELIST_IPS = [
    "127.0.0.1",
    "192.168.3.97",
    "192.168.180.48",
    "192.168.254.134"
]

# ============================================================================
# ADVANCED SETTINGS
# ============================================================================
USE_HEURISTIC_FALLBACK = True
EVENT_TRACKING_WINDOW = 60
MAX_EVENTS_MEMORY = 100
LOG_LEVEL = "INFO"

# ============================================================================
# ATELIER-SPECIFIC FEATURE FLAGS
# ============================================================================
ENABLE_TRUST_AGENT = True       # Atelier A
ENABLE_KAFKA = False             # Atelier B
ENABLE_ANOMALY_DETECTION = True  # Atelier C - ACTIVÉ!
ENABLE_MITRE_MAPPING = False     # Atelier D
ENABLE_XAI = False               # Atelier D

# ============================================================================
# ATELIER C - ANOMALY DETECTION SETTINGS
# ============================================================================
ANOMALY_THRESHOLD = 0.7  # Score > 0.7 = high risk

# ============================================================================
# STARTUP MESSAGE
# ============================================================================
print(f"[Config] Loaded unified configuration")
print(f"  - Core agents: log_tailer, collector, analyzer, responder")
print(f"  - DRY_RUN: {DRY_RUN}")
print(f"  - LM Studio: {LM_API_URL}")
print(f"  - Logs monitored: {len(LOGS_TO_MONITOR)}")
