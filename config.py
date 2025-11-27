# config.py
# Enhanced configuration with email settings and improved parameters
# Central configuration file for the mini-SOC project.

import os

# ============================================================================
# GENERAL SETTINGS
# ============================================================================
DRY_RUN = False  # Set to False to enable actual blocking. CAUTION: Test first!
AUTH_TOKEN = "****************"

# ============================================================================
# NETWORK & PORTS (Ubuntu VM)
# ============================================================================
SENSOR_PORT = 6000
COLLECTOR_PORT = 6001
ANALYZER_PORT = 6002
RESPONDER_PORT = 6003

# ============================================================================
# LM STUDIO API (Windows Host)
# ============================================================================
LM_HOST_IP = "192.168.1.10"
LM_API_URL = f"http://{LM_HOST_IP}:1234/v1/chat/completions"
LM_MODEL = "local-model"  # Mistral 7B Instruct v0.3 or similar

# ============================================================================
# RESPONDER SETTINGS
# ============================================================================
BLOCK_METHOD = "ufw"  # "ufw" or "iptables"
ALERT_LOG_PATH = "/tmp/alerts.log"

# Webhook for external integrations (n8n, Slack, etc.)
WEBHOOK_URL = None  # Example: "http://localhost:5678/webhook/soc-alert"

# ============================================================================
# EMAIL NOTIFICATION SETTINGS
# ============================================================================
EMAIL_ENABLED = False  # Set to True to enable email alerts

# Gmail SMTP settings (use App Password, not regular password)
EMAIL_ENABLED = True
SMTP_SERVER = "smtp.gmail.com"             # Gmail SMTP server (DON'T change this)
SMTP_PORT = 587                            # Gmail SMTP port (DON'T change this)
SMTP_USER = ""    # Your Gmail address
SMTP_PASSWORD = ""         # 16-char Gmail App Password
ALERT_EMAIL = ""  # Recipient email address

# Email alerts will be sent for:
EMAIL_ALERT_SEVERITIES = ["High", "Medium", "Low"]  # ["High", "Medium", "Low"]

# ============================================================================
# LOG MONITORING
# ============================================================================
LOGS_TO_MONITOR = [
    "/var/log/auth.log",           # SSH authentication attempts
    "/var/log/ufw.log",            # Firewall blocks (port scans)
    "/var/log/nginx/access.log"    # Web server access (if nginx installed)
]

# Filter out None values (logs that don't exist)
LOGS_TO_MONITOR = [log for log in LOGS_TO_MONITOR if log and os.path.exists(log)]

# ============================================================================
# HEURISTICS & THRESHOLDS
# ============================================================================
HEURISTICS = {
    "ssh_failed": {
        "pattern": r"Failed password.*ssh",
        "severity_threshold": 3,  # Failed attempts to trigger alert
        "category": "brute_force",
        "default_action": "block_ip"
    },
    "port_scan": {
        "pattern": r"UFW BLOCK.*PROTO=TCP.*DPT",
        "severity_threshold": 5,  # Blocked ports from same IP
        "category": "port_scan",
        "default_action": "create_ticket"
    },
    "web_fuzz": {
        "pattern": r" 404 ",  # 404 errors (directory fuzzing)
        "severity_threshold": 10,  # Requests per minute
        "category": "web_fuzz",
        "default_action": "create_ticket"
    }
}

# ============================================================================
# INTERNAL API ENDPOINTS
# ============================================================================
COLLECTOR_URL = f"http://127.0.0.1:{COLLECTOR_PORT}/event"
ANALYZER_URL = f"http://127.0.0.1:{ANALYZER_PORT}/analyze"
RESPONDER_URL = f"http://127.0.0.1:{RESPONDER_PORT}/respond"

# ============================================================================
# SECURITY - WHITELISTED IPs
# ============================================================================
# IPs that should NEVER be blocked (admin machines, localhost, etc.)
WHITELIST_IPS = [
    "127.0.0.1",
    "192.168.1.4",      # VirtualBox host
    "192.168.1.10",     # Windows host (LM Studio)
]

# ============================================================================
# ADVANCED SETTINGS
# ============================================================================

# LM Studio timeout (seconds)
LM_TIMEOUT = 30

# Maximum events to keep in memory (for dashboards)
MAX_EVENTS_MEMORY = 100

# Fallback to heuristics if LM fails
USE_HEURISTIC_FALLBACK = True
EVENT_TRACKING_WINDOW = 60
# Log level
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# ============================================================================
# VALIDATION
# ============================================================================
print(f"[Config] Loaded configuration:")
print(f"  - DRY_RUN: {DRY_RUN}")
print(f"  - LM Studio: {LM_API_URL}")
print(f"  - Email enabled: {EMAIL_ENABLED}")
print(f"  - Logs to monitor: {len(LOGS_TO_MONITOR)}")
print(f"  - Whitelisted IPs: {len(WHITELIST_IPS)}")
