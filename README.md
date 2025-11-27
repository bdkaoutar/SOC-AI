# Mini-SOC: AI-Powered Security Operations Center

![SOC Dashboard Example](<img width="1919" height="1040" alt="Screenshot 2025-10-31 150018" src="https://github.com/user-attachments/assets/2239f6d0-2dc7-4093-a8ad-60d695b884d0" />
<img width="1847" height="954" alt="Screenshot 2025-10-31 150201" src="https://github.com/user-attachments/assets/64089f92-14a3-49a4-a726-dc5ddb69fc23" />
<img width="1847" height="966" alt="Screenshot 2025-10-31 150257" src="https://github.com/user-attachments/assets/690919f5-975d-4f10-a0a9-16da1b32c0d0" />

) <!-- Replace with actual image if available -->

## Overview

Mini-SOC is a lightweight, AI-assisted Security Operations Center (SOC) implemented in Python. It monitors system logs for potential security threats (e.g., brute-force attacks, port scans, web fuzzing), analyzes them using a local large language model (via LM Studio), and responds automatically—such as blocking malicious IPs or sending email alerts. This project demonstrates a basic SOC pipeline with event detection, collection, analysis, and response.

Key highlights:
- **AI Integration**: Uses a local LLM (e.g., Mistral 7B) for threat classification and response recommendations.
- **Automated Response**: Blocks IPs using UFW/iptables, creates "tickets" (logs), or ignores benign events.
- **Email Notifications**: Sends alerts via Gmail SMTP for configurable severity levels.
- **Web Dashboards**: Each component has a modern, responsive web interface for monitoring.
- **Heuristic Fallback**: Rule-based detection if AI is unavailable.
- **Dry Run Mode**: Test without actual blocking.

This project is designed for educational purposes or small-scale deployments on a Ubuntu VM, with LM Studio running on a Windows host.

## Features

- **Log Monitoring**: Tails multiple logs (/var/log/auth.log, /var/log/ufw.log, /var/log/nginx/access.log).
- **Threat Detection**: Patterns for SSH brute-force, port scans, and web fuzzing.
- **AI Analysis**: Severity (Low/Medium/High), category, recommended action, and executable commands.
- **Automated Actions**: IP blocking, ticket creation, email alerts.
- **Whitelisting**: Prevent blocking admin IPs.
- **Web Interfaces**: Dashboards for Sensor (Log Tailer), Collector, Analyzer, and Responder.
- **Secure Communication**: Uses auth tokens for inter-component API calls.
- **Extensible**: Configurable heuristics, thresholds, and integrations (e.g., webhooks).

## Architecture

The system follows a pipeline architecture:

1. **Log Tailer (Sensor)**: Monitors logs, detects patterns, generates events, sends to Collector. (Port: 6000)
2. **Collector**: Aggregates events, forwards to Analyzer. (Port: 6001)
3. **Analyzer**: Applies heuristics or queries LM Studio for analysis, forwards decisions to Responder. (Port: 6002)
4. **Responder**: Executes actions (block IP, send email), logs alerts. Must run as root. (Port: 6003)
5. **LM Client**: Wrapper for API calls to LM Studio (running on Windows host).
6. **Config**: Central settings file.

Events flow: Log Tailer → Collector → Analyzer → Responder.

```
[Logs] → Log Tailer → [HTTP] → Collector → [HTTP] → Analyzer → [LM Studio API] → [HTTP] → Responder → [Actions: Block/Email]
```

## Requirements

- **OS**: Ubuntu (VM) for the SOC components; Windows host for LM Studio.
- **Python**: 3.10+ with libraries: Flask, requests.
- **LM Studio**: Installed on Windows host (e.g., IP: 192.168.1.10:1234). Load a model like Mistral 7B Instruct v0.3.
- **Firewall**: UFW or iptables enabled.
- **Email**: Gmail account with App Password (for SMTP).
- **Optional**: Nginx for web fuzz detection; n8n/Slack for webhooks.

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/your-repo/mini-soc.git
   cd mini-soc
   ```

2. **Install Dependencies**:
   ```
   pip install flask requests
   ```

3. **Setup LM Studio**:
   - Install LM Studio on Windows.
   - Load a compatible model (e.g., Mistral 7B).
   - Start the local server (default: http://localhost:1234).
   - Update `config.py` with `LM_HOST_IP` (Windows IP visible to Ubuntu VM).

4. **Configure**:
   - Edit `config.py`:
     - Set `DRY_RUN = False` for live mode (caution!).
     - Update email settings (Gmail App Password).
     - Add whitelisted IPs.
     - Enable/disable features (e.g., `EMAIL_ENABLED`).

5. **Run Components** (in separate terminals or as services):
   - Responder (as root): `sudo python3 responder.py`
   - Analyzer: `python3 analyzer.py`
   - Collector: `python3 collector.py`
   - Log Tailer: `sudo python3 log_tailer.py` (needs root for log access)

   Note: Order matters—start Responder first, then Analyzer, Collector, Log Tailer.

## Usage

1. **Monitor Dashboards**:
   - Sensor (Log Tailer): http://localhost:6000
   - Collector: http://localhost:6001
   - Analyzer: http://localhost:6002
   - Responder: http://localhost:6003

   Dashboards auto-refresh and show stats, recent events, and analyses.

2. **Generate Test Events**:
   - SSH brute-force: Attempt failed logins via SSH.
   - Port scan: Use `nmap` from another machine.
   - Web fuzz: Use `ffuf` or curl on Nginx endpoints.

3. **View Alerts**:
   - Check `/tmp/alerts.log` for detailed logs.
   - Emails sent to `ALERT_EMAIL` for matching severities.

4. **Custom Integration**:
   - Set `WEBHOOK_URL` in config.py for external notifications (e.g., Slack).

## Configuration Details

- **config.py**: All settings here. Key sections:
  - General: DRY_RUN, AUTH_TOKEN.
  - Network: Ports, LM API.
  - Responder: Block method, email, webhook.
  - Logs: Paths to monitor.
  - Heuristics: Patterns and thresholds.
  - Whitelist: IPs to protect.

- **LM Prompt**: In `lm_client.py`—customize for better AI responses.

## Troubleshooting

- **LM Errors**: Check LM Studio is running and accessible from Ubuntu (ping LM_HOST_IP).
- **Permissions**: Run Responder and Log Tailer as root.
- **No Events**: Ensure logs exist and are writable; test with manual log writes.
- **Email Issues**: Verify Gmail App Password; allow less secure apps if needed.
- **Blocking Fails**: Ensure UFW/iptables is installed and enabled.

## Limitations

- In-memory storage (no persistence—use a DB for production).
- Basic IP extraction—improve regex for accuracy.
- Demo-scale: Not for large environments.
- AI Dependency: Local model quality affects analysis.

---

Built with ❤️ by Niama Aqarial | Date: November 27, 2025
