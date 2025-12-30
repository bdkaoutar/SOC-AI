#!/usr/bin/env python3
# features.py - Feature Extraction Module (FIXED VERSION)

from datetime import datetime
from collections import defaultdict
import re

class FeatureExtractor:
    """Extract features from security events for ML models"""
    
    def __init__(self):
        # Store event history for temporal features
        self.event_history = defaultdict(list)
        self.max_history = 1000
    
    def extract_features(self, event: dict) -> dict:
        """Extract features from a security event"""
        features = {}
        
        # Basic features
        features['src_ip_hash'] = self._hash_ip(event.get('src_ip', 'unknown'))
        features['kind_encoded'] = self._encode_kind(event.get('kind', 'unknown'))
        
        # Temporal features
        timestamp = event.get('ts', datetime.now().isoformat())
        features.update(self._extract_temporal_features(timestamp))
        
        # Event-specific features
        kind = event.get('kind', 'unknown')
        if kind == 'ssh_failed':
            features.update(self._extract_ssh_features(event))
        elif kind == 'port_scan':
            features.update(self._extract_port_scan_features(event))
        elif kind == 'web_fuzz':
            features.update(self._extract_web_features(event))
        
        # Behavioral features (frequency analysis) - MUST BE CALLED BEFORE UPDATE HISTORY
        src_ip = event.get('src_ip', 'unknown')
        features.update(self._extract_behavioral_features(src_ip, kind, timestamp))
        
        # Store in history AFTER extracting features
        self._update_history(event)
        
        return features
    
    def _hash_ip(self, ip: str) -> int:
        """Convert IP to numerical hash"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return int(parts[0]) * 1000000 + int(parts[1]) * 10000 + int(parts[2]) * 100 + int(parts[3])
            return hash(ip) % 1000000
        except:
            return 0
    
    def _encode_kind(self, kind: str) -> int:
        """Encode event kind as number"""
        mapping = {
            'ssh_failed': 1,
            'port_scan': 2,
            'web_fuzz': 3,
            'unknown': 0
        }
        return mapping.get(kind, 0)
    
    def _extract_temporal_features(self, timestamp: str) -> dict:
        """Extract time-based features"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            dt = datetime.now()
        
        return {
            'hour_of_day': dt.hour,
            'day_of_week': dt.weekday(),
            'is_weekend': 1 if dt.weekday() >= 5 else 0,
            'is_night': 1 if dt.hour < 6 or dt.hour > 22 else 0,
            'is_business_hours': 1 if 9 <= dt.hour <= 17 and dt.weekday() < 5 else 0
        }
    
    def _extract_ssh_features(self, event: dict) -> dict:
        """Extract SSH-specific features"""
        raw = event.get('raw', '')
        
        features = {
            'ssh_username_length': 0,
            'ssh_has_root': 0,
            'ssh_has_admin': 0,
            'ssh_invalid_user': 0
        }
        
        # Extract username
        username_match = re.search(r'user[=\s]+(\w+)', raw, re.IGNORECASE)
        if username_match:
            username = username_match.group(1)
            features['ssh_username_length'] = len(username)
            features['ssh_has_root'] = 1 if 'root' in username.lower() else 0
            features['ssh_has_admin'] = 1 if 'admin' in username.lower() else 0
        
        features['ssh_invalid_user'] = 1 if 'invalid user' in raw.lower() else 0
        
        return features
    
    def _extract_port_scan_features(self, event: dict) -> dict:
        """Extract port scan features"""
        raw = event.get('raw', '')
        
        features = {
            'port_number': 0,
            'is_common_port': 0,
            'is_high_port': 0
        }
        
        # Extract port number
        port_match = re.search(r'DPT[=:](\d+)', raw)
        if port_match:
            port = int(port_match.group(1))
            features['port_number'] = port
            
            # Common ports: 22, 80, 443, 3306, etc.
            common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
            features['is_common_port'] = 1 if port in common_ports else 0
            features['is_high_port'] = 1 if port > 1024 else 0
        
        return features
    
    def _extract_web_features(self, event: dict) -> dict:
        """Extract web fuzzing features"""
        raw = event.get('raw', '')
        
        features = {
            'http_status_code': 0,
            'is_error_code': 0,
            'url_length': 0,
            'has_sql_keywords': 0,
            'has_path_traversal': 0,
            'has_xss_attempt': 0
        }
        
        # Extract HTTP status code
        status_match = re.search(r'HTTP/[\d.]+"\s+(\d{3})', raw)
        if status_match:
            status = int(status_match.group(1))
            features['http_status_code'] = status
            features['is_error_code'] = 1 if status >= 400 else 0
        
        # Extract URL
        url_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^\s"]+)', raw)
        if url_match:
            url = url_match.group(1)
            features['url_length'] = len(url)
            
            # Detect attack patterns
            url_lower = url.lower()
            features['has_sql_keywords'] = 1 if any(kw in url_lower for kw in ['select', 'union', 'insert', 'drop', '--', ';']) else 0
            features['has_path_traversal'] = 1 if '../' in url or '..\\' in url else 0
            features['has_xss_attempt'] = 1 if any(kw in url_lower for kw in ['<script', 'javascript:', 'onerror=']) else 0
        
        return features
    
    def _extract_behavioral_features(self, src_ip: str, kind: str, current_timestamp: str) -> dict:
        """Extract behavioral features based on history - FIXED VERSION"""
        features = {
            'request_count_1min': 0,
            'request_count_5min': 0,
            'unique_kinds_count': 0,
            'avg_time_between_requests': 0
        }
        
        if src_ip not in self.event_history:
            return features
        
        history = self.event_history[src_ip]
        
        # Parse current timestamp
        try:
            current_dt = datetime.fromisoformat(current_timestamp.replace('Z', '+00:00'))
        except:
            current_dt = datetime.now()
        
        # Count recent requests
        recent_1min = []
        recent_5min = []
        
        for event_record in history:
            time_diff = (current_dt - event_record['timestamp']).total_seconds()
            
            if time_diff < 60:  # Within 1 minute
                recent_1min.append(event_record)
            
            if time_diff < 300:  # Within 5 minutes
                recent_5min.append(event_record)
        
        features['request_count_1min'] = len(recent_1min)
        features['request_count_5min'] = len(recent_5min)
        
        # Unique event kinds
        if recent_5min:
            unique_kinds = set(e['kind'] for e in recent_5min)
            features['unique_kinds_count'] = len(unique_kinds)
        
        # Average time between requests
        if len(recent_5min) >= 2:
            times = sorted([e['timestamp'] for e in recent_5min])
            intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
            features['avg_time_between_requests'] = sum(intervals) / len(intervals)
        
        return features
    
    def _update_history(self, event: dict):
        """Update event history for an IP"""
        src_ip = event.get('src_ip', 'unknown')
        
        try:
            timestamp = datetime.fromisoformat(event.get('ts', datetime.now().isoformat()).replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
        
        self.event_history[src_ip].append({
            'timestamp': timestamp,
            'kind': event.get('kind', 'unknown')
        })
        
        # Keep only recent history (last 10 minutes)
        now = timestamp  # Use event timestamp, not current time
        self.event_history[src_ip] = [
            e for e in self.event_history[src_ip]
            if (now - e['timestamp']).total_seconds() < 600
        ]
        
        # Limit total history size
        if len(self.event_history) > self.max_history:
            # Remove oldest IP
            oldest_ip = min(self.event_history.keys(), 
                          key=lambda k: max(e['timestamp'] for e in self.event_history[k]) if self.event_history[k] else now)
            del self.event_history[oldest_ip]
    
    def get_feature_names(self) -> list:
        """Return list of all possible feature names"""
        return [
            'src_ip_hash', 'kind_encoded',
            'hour_of_day', 'day_of_week', 'is_weekend', 'is_night', 'is_business_hours',
            'ssh_username_length', 'ssh_has_root', 'ssh_has_admin', 'ssh_invalid_user',
            'port_number', 'is_common_port', 'is_high_port',
            'http_status_code', 'is_error_code', 'url_length', 
            'has_sql_keywords', 'has_path_traversal', 'has_xss_attempt',
            'request_count_1min', 'request_count_5min', 'unique_kinds_count', 
            'avg_time_between_requests'
        ]


def extract_features(event: dict, extractor: FeatureExtractor = None) -> dict:
    """Extract features from an event"""
    if extractor is None:
        extractor = FeatureExtractor()
    
    return extractor.extract_features(event)