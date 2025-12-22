#!/usr/bin/env python3
# lm_client.py - LM Studio Interface (DO NOT MODIFY)
# Unified LM query interface for all ateliers

import requests
import json
from config import LM_API_URL, LM_MODEL, LM_TIMEOUT

def query_lm(event: dict, custom_prompt: str = None) -> dict | None:
    """
    Query LM Studio with security event
    
    Args:
        event: Security event dict
        custom_prompt: Optional custom prompt (for atelier extensions)
    
    Returns:
        Analysis dict or None on failure
    """
    
    # Default prompt
    if custom_prompt is None:
        prompt = f"""You are a JSON-only security analyst AI for a Security Operations Center (SOC).
Analyze the security event and respond with ONLY valid JSON, no explanations.

Event to analyze:
{json.dumps(event, indent=2)}

Your analysis must include:
1. Severity assessment (Low/Medium/High)
2. Attack category classification
3. Recommended action
4. If blocking is needed, provide the exact command to execute
5. Justification for your decision (for explainability)

Return EXACTLY this JSON structure:
{{
  "severity": "Low|Medium|High",
  "category": "brute_force|port_scan|web_fuzz|other",
  "recommended_action": "block_ip|create_ticket|ignore",
  "target_ip": "{event.get('src_ip', 'unknown')}",
  "block_command": "sudo ufw insert 1 deny from {event.get('src_ip', 'IP')}",
  "justification": "Brief explanation of why this action is recommended",
  "confidence": 0.0-1.0
}}

Rules:
- If recommended_action is "block_ip", block_command must contain valid ufw or iptables command
- For ssh_failed events with severity High, recommend block_ip
- For port_scan events, analyze frequency before blocking
- For web_fuzz, consider creating ticket first unless severity is High
- Justify your decision for explainability (required for XAI)
"""
    else:
        prompt = custom_prompt

    payload = {
        "model": LM_MODEL,
        "messages": [
		{
        		"role": "user",
        		"content": (
            			"You are a JSON-only security analyst AI for a SOC. "
            			"You MUST answer with pure JSON, no markdown, no explanations.\n\n"
            			+ prompt
        		)
    		}
        ],
        "temperature": 0.1,
        "max_tokens": 300
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(LM_API_URL, json=payload, headers=headers, timeout=LM_TIMEOUT)
        response.raise_for_status()
        
        content = response.json()["choices"][0]["message"]["content"].strip()
        
        # Clean markdown code blocks if present
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        
        parsed = json.loads(content)
        
        # Validate required fields
        required_fields = ["severity", "category", "recommended_action", "confidence"]
        if not all(field in parsed for field in required_fields):
            print(f"[LM Client] Missing required fields in response")
            return None
        
        print(f"[LM Client] ✅ Analysis: {parsed['severity']} severity, action: {parsed['recommended_action']}")
        return parsed
        
    except requests.RequestException as e:
        print(f"[LM Client] ❌ HTTP error: {e}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"[LM Client] ❌ Parse error: {e}")
        if 'content' in locals():
            print(f"[LM Client] Raw content: {content[:200]}...")
        return None
    except Exception as e:
        print(f"[LM Client] ❌ Unexpected error: {e}")
        return None


def query_lm_with_confidence(event: dict) -> tuple[dict | None, float]:
    """
    Query LM and extract confidence score separately
    Used by Atelier A for calibration
    
    Returns:
        (analysis_dict, raw_confidence)
    """
    result = query_lm(event)
    if result:
        confidence = result.get("confidence", 0.5)
        return result, confidence
    return None, 0.0


def query_lm_for_mitre(event: dict, analysis: dict) -> dict | None:
    """
    Query LM for MITRE ATT&CK mapping
    Used by Atelier D
    
    Returns:
        Dict with MITRE techniques and tactics
    """
    prompt = f"""You are a MITRE ATT&CK expert. Map this security event to MITRE techniques.

Event:
{json.dumps(event, indent=2)}

Analysis:
{json.dumps(analysis, indent=2)}

Return ONLY valid JSON:
{{
  "techniques": ["T1110", "T1078"],
  "tactics": ["Credential Access", "Initial Access"],
  "description": "Brief description of the attack pattern"
}}
"""
    
    return query_lm(event, custom_prompt=prompt)


def query_lm_for_explanation(event: dict, analysis: dict) -> str | None:
    """
    Query LM for XAI explanation
    Used by Atelier D
    
    Returns:
        Human-readable explanation string
    """
    prompt = f"""You are an explainable AI assistant. Explain this security decision in simple terms.

Event:
{json.dumps(event, indent=2)}

Decision:
{json.dumps(analysis, indent=2)}

Provide a 2-3 sentence explanation that a security analyst would understand.
Return ONLY the explanation text, no JSON.
"""
    
    payload = {
        "model": LM_MODEL,
        "messages": [
            {"role": "system", "content": "You are an explainable AI assistant."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 150
    }
    
    try:
        response = requests.post(LM_API_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=LM_TIMEOUT)
        response.raise_for_status()
        explanation = response.json()["choices"][0]["message"]["content"].strip()
        return explanation
    except Exception as e:
        print(f"[LM Client] XAI error: {e}")
        return None


# Health check function
def check_lm_health() -> bool:
    """Check if LM Studio is responding"""
    try:
        response = requests.get(LM_API_URL.replace('/v1/chat/completions', '/v1/models'), timeout=5)
        return response.status_code == 200
    except:
        return False


if __name__ == "__main__":
    # Test the LM client
    print("Testing LM Studio connection...")
    
    if not check_lm_health():
        print("❌ LM Studio not responding. Make sure it's running on", LM_API_URL)
    else:
        print("✅ LM Studio is responding")
        
        # Test query
        test_event = {
            "id": "evt-test123",
            "ts": "2024-01-01T12:00:00Z",
            "kind": "ssh_failed",
            "src_ip": "192.168.1.100",
            "dst": "ubuntu-vm",
            "raw": "Failed password for root from 192.168.1.100"
        }
        
        print("\nTesting analysis query...")
        result = query_lm(test_event)
        
        if result:
            print("✅ Analysis successful:")
            print(json.dumps(result, indent=2))
        else:
            print("❌ Analysis failed")
