#!/usr/bin/env python3
# generate_dataset.py - FIXED VERSION with proper temporal ordering

import random
import json
from datetime import datetime, timedelta
from features import FeatureExtractor
import pandas as pd

class DatasetGenerator:
    """Generate synthetic security events for training"""
    
    def __init__(self, seed=42):
        random.seed(seed)
        # Don't create extractor here - create it during feature extraction
        
        # Realistic IP pools
        self.normal_ips = self._generate_ip_pool(50)
        self.attacker_ips = self._generate_ip_pool(20)
        
        # Usernames
        self.normal_usernames = ['john', 'alice', 'bob', 'sarah', 'michael', 'david']
        self.attack_usernames = [
            'root', 'admin', 'administrator', 'oracle', 'postgres',
            'mysql', 'apache', 'test', 'guest', '123456', 'password',
            'user', 'ftp', 'webmaster', 'backup'
        ]
        
        # Ports
        self.common_ports = [22, 80, 443]
        self.uncommon_ports = [8080, 8443, 3389, 5900, 5432, 3306, 27017, 6379, 9200]
    
    def _generate_ip_pool(self, count: int) -> list:
        """Generate pool of realistic IPs"""
        ips = []
        for _ in range(count):
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    def generate_normal_ssh_event(self, base_time: datetime) -> dict:
        ip = random.choice(self.normal_ips)
        username = random.choice(self.normal_usernames)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'ssh_failed',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'Failed password for {username} from {ip} port {random.randint(50000, 60000)} ssh2',
            'label': 0
        }
    
    def generate_attack_ssh_event(self, base_time: datetime) -> dict:
        ip = random.choice(self.attacker_ips)
        username = random.choice(self.attack_usernames)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'ssh_failed',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'Failed password for invalid user {username} from {ip} port {random.randint(40000, 50000)} ssh2',
            'label': 1
        }
    
    def generate_normal_port_scan(self, base_time: datetime) -> dict:
        ip = random.choice(self.normal_ips)
        port = random.choice(self.common_ports)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'port_scan',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 DPT={port}',
            'label': 0
        }
    
    def generate_attack_port_scan(self, base_time: datetime) -> dict:
        ip = random.choice(self.attacker_ips)
        port = random.choice(self.uncommon_ports)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'port_scan',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 DPT={port}',
            'label': 1
        }
    
    def generate_normal_web_event(self, base_time: datetime) -> dict:
        ip = random.choice(self.normal_ips)
        paths = ['/index.html', '/about', '/contact', '/products', '/api/users', '/blog']
        status = random.choice([200, 200, 200, 200, 304, 404])
        path = random.choice(paths)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'web_fuzz',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'{ip} - - [01/Jan/2024:12:00:00] "GET {path} HTTP/1.1" {status} {random.randint(500, 5000)}',
            'label': 0
        }
    
    def generate_attack_web_event(self, base_time: datetime) -> dict:
        ip = random.choice(self.attacker_ips)
        attack_paths = [
            '/../../../../etc/passwd',
            '/?id=1%27+UNION+SELECT+1,2,3--',
            '/search?q=<script>alert(1)</script>',
            '/.env',
            '/admin/../../etc/passwd',
        ]
        status = random.choice([403, 401, 404, 500])
        path = random.choice(attack_paths)
        return {
            'id': f'evt_{random.randint(100000, 999999)}',
            'kind': 'web_fuzz',
            'src_ip': ip,
            'ts': base_time.isoformat(),
            'raw': f'{ip} - - [01/Jan/2024:12:00:00] "GET {path} HTTP/1.1" {status} 0',
            'label': 1
        }
    
    def generate_dataset(self, total_events=1500, anomaly_ratio=0.15) -> pd.DataFrame:
        num_anomalies = int(total_events * anomaly_ratio)
        num_normal = total_events - num_anomalies
        
        print(f"Generating dataset: {total_events} events")
        print(f"  - Normal: {num_normal} ({(1-anomaly_ratio)*100:.1f}%)")
        print(f"  - Anomalies: {num_anomalies} ({anomaly_ratio*100:.1f}%)")
        
        events = []
        base_time = datetime.now() - timedelta(days=7)
        
        # Normal events
        print("\n[1/2] Generating normal events...")
        for i in range(num_normal):
            time_offset = random.randint(0, 7*24*3600)
            event_time = base_time + timedelta(seconds=time_offset)
            event_type = random.choice(['ssh', 'ssh', 'port', 'web', 'web', 'web'])
            
            if event_type == 'ssh':
                event = self.generate_normal_ssh_event(event_time)
            elif event_type == 'port':
                event = self.generate_normal_port_scan(event_time)
            else:
                event = self.generate_normal_web_event(event_time)
            
            events.append(event)
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{num_normal} normal events")
        
        # Anomalous events WITH BURSTS
        print("\n[2/2] Generating anomalous events (with bursts)...")
        generated_anomalies = 0
        
        while generated_anomalies < num_anomalies:
            time_offset = random.randint(0, 7*24*3600)
            event_time = base_time + timedelta(seconds=time_offset)
            
            # 60% bursts
            if random.random() < 0.6 and (num_anomalies - generated_anomalies) >= 3:
                burst_size = min(random.randint(3, 8), num_anomalies - generated_anomalies)
                attacker_ip = random.choice(self.attacker_ips)
                attack_type = random.choice(['ssh', 'port', 'web'])
                
                for j in range(burst_size):
                    burst_time = event_time + timedelta(seconds=j * 2)  # 2 sec apart
                    
                    if attack_type == 'ssh':
                        event = self.generate_attack_ssh_event(burst_time)
                    elif attack_type == 'port':
                        event = self.generate_attack_port_scan(burst_time)
                    else:
                        event = self.generate_attack_web_event(burst_time)
                    
                    event['src_ip'] = attacker_ip  # Same IP for burst
                    events.append(event)
                    generated_anomalies += 1
                
                if generated_anomalies % 50 == 0 or burst_size > 1:
                    print(f"  Burst: {burst_size} events from {attacker_ip}")
            else:
                event_type = random.choice(['ssh', 'port', 'web'])
                if event_type == 'ssh':
                    event = self.generate_attack_ssh_event(event_time)
                elif event_type == 'port':
                    event = self.generate_attack_port_scan(event_time)
                else:
                    event = self.generate_attack_web_event(event_time)
                
                events.append(event)
                generated_anomalies += 1
            
            if generated_anomalies % 50 == 0:
                print(f"  Generated {generated_anomalies}/{num_anomalies}")
        
        # CRITICAL: Sort by timestamp BEFORE feature extraction
        print("\n[3/4] Sorting events by timestamp...")
        events.sort(key=lambda e: e['ts'])
        
        # Feature extraction with temporal order
        print("\n[4/4] Extracting features (with temporal history)...")
        extractor = FeatureExtractor()  # Create fresh extractor
        dataset = []
        
        for i, event in enumerate(events):
            features = extractor.extract_features(event)
            
            row = {
                'event_id': event['id'],
                'src_ip': event['src_ip'],
                'kind': event['kind'],
                'timestamp': event['ts'],
                'label': event['label']
            }
            row.update(features)
            dataset.append(row)
            
            if (i + 1) % 200 == 0:
                print(f"  Extracted {i + 1}/{len(events)} events")
        
        df = pd.DataFrame(dataset)
        
        # Verification
        actual_ratio = df['label'].mean()
        print(f"\n✅ Dataset: {len(df)} rows, {len(df.columns)} columns")
        print(f"   Anomaly ratio: {actual_ratio:.2%}")
        
        anomalies = df[df['label'] == 1]
        normal = df[df['label'] == 0]
        
        print(f"\n📊 BEHAVIORAL FEATURES:")
        print(f"   request_count_1min:")
        print(f"      Normal:  {normal['request_count_1min'].mean():.2f}")
        print(f"      Anomaly: {anomalies['request_count_1min'].mean():.2f}")
        ratio = anomalies['request_count_1min'].mean() / (normal['request_count_1min'].mean() + 0.01)
        print(f"      Ratio: {ratio:.2f}x")
        
        print(f"\n   Pattern features:")
        print(f"      ssh_has_root (anomaly): {anomalies['ssh_has_root'].mean():.2%}")
        print(f"      has_path_traversal (anomaly): {anomalies['has_path_traversal'].mean():.2%}")
        
        # Quality checks
        checks = 0
        if ratio > 2.0:
            print(f"\n✅ Check 1: Request count ratio OK ({ratio:.1f}x)")
            checks += 1
        else:
            print(f"\n❌ Check 1: Request count ratio LOW ({ratio:.1f}x)")
        
        if anomalies['has_path_traversal'].mean() > 0.05:
            print(f"✅ Check 2: Attack patterns detected")
            checks += 1
        
        if anomalies['ssh_has_root'].mean() > normal['ssh_has_root'].mean():
            print(f"✅ Check 3: SSH patterns OK")
            checks += 1
        
        print(f"\n📊 Quality: {checks}/3 checks passed")
        if checks == 3:
            print("✅ Dataset GOOD!")
        elif checks >= 2:
            print("⚠️  Dataset OK")
        else:
            print("❌ Dataset POOR!")
        
        return df


def main():
    print("="*80)
    print("🔬 DATASET GENERATOR - FIXED VERSION")
    print("="*80)
    
    generator = DatasetGenerator(seed=42)
    df = generator.generate_dataset(total_events=1500, anomaly_ratio=0.15)
    
    df.to_csv('dataset.csv', index=False)
    print(f"\n💾 Saved: dataset.csv")
    
    print("\n" + "="*80)
    print("📊 STATISTICS")
    print("="*80)
    print(f"Total: {len(df)}")
    print(f"\n{df['kind'].value_counts()}")
    print(f"\n{df['label'].value_counts()}")
    print("\n✅ Done!")


if __name__ == "__main__":
    main()