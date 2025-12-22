# event_schema.py - Unified Event Schema
# This ensures all agents speak the same language

from datetime import datetime
from typing import Dict, Optional, Any
import uuid

class SecurityEvent:
    """Standard security event format for all ateliers"""
    
    def __init__(self, kind: str, src_ip: str, raw: str, dst: str = "ubuntu-vm"):
        self.id = f"evt-{uuid.uuid4().hex[:8]}"
        self.ts = datetime.now().isoformat() + "Z"
        self.kind = kind  # ssh_failed, port_scan, web_fuzz
        self.src_ip = src_ip
        self.dst = dst
        self.raw = raw
        
        # Extension fields for ateliers
        self.anomaly_score = None      # Atelier C
        self.mitre_technique = None    # Atelier D
        self.confidence_calibrated = None  # Atelier A
        
    def to_dict(self) -> Dict:
        """Convert to JSON-serializable dict"""
        result = {
            "id": self.id,
            "ts": self.ts,
            "kind": self.kind,
            "src_ip": self.src_ip,
            "dst": self.dst,
            "raw": self.raw
        }
        
        # Include optional fields if present
        if self.anomaly_score is not None:
            result["anomaly_score"] = self.anomaly_score
        if self.mitre_technique:
            result["mitre_technique"] = self.mitre_technique
        if self.confidence_calibrated is not None:
            result["confidence_calibrated"] = self.confidence_calibrated
            
        return result
    
    @staticmethod
    def from_dict(data: Dict) -> 'SecurityEvent':
        """Create event from dict"""
        event = SecurityEvent(
            kind=data.get("kind", "unknown"),
            src_ip=data.get("src_ip", "unknown"),
            raw=data.get("raw", ""),
            dst=data.get("dst", "ubuntu-vm")
        )
        event.id = data.get("id", event.id)
        event.ts = data.get("ts", event.ts)
        
        # Restore optional fields
        event.anomaly_score = data.get("anomaly_score")
        event.mitre_technique = data.get("mitre_technique")
        event.confidence_calibrated = data.get("confidence_calibrated")
        
        return event


class AnalysisResult:
    """Standard analysis format from analyzer/LM"""
    
    def __init__(self, event_id: str):
        self.event_id = event_id
        self.severity: str = "Low"  # Low, Medium, High
        self.category: str = "other"  # brute_force, port_scan, web_fuzz, other
        self.recommended_action: str = "ignore"  # block_ip, create_ticket, ignore
        self.target: Optional[str] = None  # IP to block
        self.block_command: Optional[str] = None
        self.justification: str = ""
        self.confidence: float = 0.5
        
        # Extension fields
        self.calibrated_confidence: Optional[float] = None  # Atelier A
        self.mitre_tactics: list = []  # Atelier D
        self.explanation: Optional[str] = None  # Atelier D
        
    def to_dict(self) -> Dict:
        """Convert to JSON-serializable dict"""
        result = {
            "event_id": self.event_id,
            "severity": self.severity,
            "category": self.category,
            "recommended_action": self.recommended_action,
            "target": self.target,
            "block_command": self.block_command,
            "justification": self.justification,
            "confidence": self.confidence
        }
        
        # Include optional fields
        if self.calibrated_confidence is not None:
            result["calibrated_confidence"] = self.calibrated_confidence
        if self.mitre_tactics:
            result["mitre_tactics"] = self.mitre_tactics
        if self.explanation:
            result["explanation"] = self.explanation
            
        return result
    
    @staticmethod
    def from_dict(data: Dict) -> 'AnalysisResult':
        """Create analysis from dict"""
        analysis = AnalysisResult(data.get("event_id", "unknown"))
        analysis.severity = data.get("severity", "Low")
        analysis.category = data.get("category", "other")
        analysis.recommended_action = data.get("recommended_action", "ignore")
        analysis.target = data.get("target")
        analysis.block_command = data.get("block_command")
        analysis.justification = data.get("justification", "")
        analysis.confidence = data.get("confidence", 0.5)
        
        # Restore optional fields
        analysis.calibrated_confidence = data.get("calibrated_confidence")
        analysis.mitre_tactics = data.get("mitre_tactics", [])
        analysis.explanation = data.get("explanation")
        
        return analysis


class ResponseAction:
    """Standard response action format"""
    
    def __init__(self, event_id: str, action: str):
        self.event_id = event_id
        self.action = action
        self.timestamp = datetime.now().isoformat()
        self.command_executed: Optional[str] = None
        self.success: bool = False
        self.details: Dict[str, Any] = {}
        self.email_sent: bool = False
        
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "action": self.action,
            "timestamp": self.timestamp,
            "command_executed": self.command_executed,
            "success": self.success,
            "details": self.details,
            "email_sent": self.email_sent
        }


def validate_event(data: Dict) -> bool:
    """Validate event structure"""
    required = ["kind", "src_ip"]
    return all(field in data for field in required)


def validate_analysis(data: Dict) -> bool:
    """Validate analysis structure"""
    required = ["severity", "category", "recommended_action"]
    valid_severities = ["Low", "Medium", "High"]
    valid_actions = ["block_ip", "create_ticket", "ignore"]
    
    if not all(field in data for field in required):
        return False
    
    if data["severity"] not in valid_severities:
        return False
    
    if data["recommended_action"] not in valid_actions:
        return False
    
    return True