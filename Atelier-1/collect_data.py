#!/usr/bin/env python3
"""
collect_dataset.py - Collect and Label Events for Calibration Training
----------------------------------------------------------------------
This script helps you:
1. Collect events from the analyzer
2. Manually label them (true positive / false positive)
3. Save a labeled dataset for training

Usage:
    # Collect from analyzer API
    python3 collect_dataset.py --collect --output dataset.json
    
    # Label interactively
    python3 collect_dataset.py --label --input dataset.json
    
    # Auto-label based on severity (quick start)
    python3 collect_dataset.py --auto-label --input dataset.json
"""

import json
import requests
import argparse
from datetime import datetime
from pathlib import Path


def collect_from_analyzer(analyzer_url='http://127.0.0.1:6002', output_file='dataset_raw.json'):
    """Collect analysis history from analyzer API"""
    print(f"[Collect] Fetching data from {analyzer_url}/api/analysis...")
    
    try:
        response = requests.get(f'{analyzer_url}/api/analysis', timeout=10)
        response.raise_for_status()
        data = response.json()
        
        analyses = data.get('analyses', [])
        print(f"[Collect] Retrieved {len(analyses)} analyses")
        
        # Transform to dataset format
        dataset = []
        for item in analyses:
            event = item.get('event', {})
            analysis = item.get('analysis', {})
            
            dataset_entry = {
                'event_id': event.get('id', 'unknown'),
                'event_kind': event.get('kind', 'unknown'),
                'src_ip': event.get('src_ip', 'unknown'),
                'timestamp': item.get('timestamp', datetime.now().isoformat()),
                'lm_confidence': analysis.get('confidence', 0.5),
                'severity': analysis.get('severity', 'Unknown'),
                'category': analysis.get('category', 'other'),
                'recommended_action': analysis.get('recommended_action', 'ignore'),
                'justification': analysis.get('justification', ''),
                'ground_truth': None,  # To be labeled
                'notes': ''
            }
            dataset.append(dataset_entry)
        
        # Save raw dataset
        with open(output_file, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        print(f"[Collect] ✅ Saved {len(dataset)} entries to {output_file}")
        print(f"[Collect] Next step: Label the dataset using --label or --auto-label")
        
        return dataset
        
    except Exception as e:
        print(f"[Collect] ❌ Error: {e}")
        return []


def label_interactively(input_file='dataset_raw.json', output_file='dataset_labeled.json'):
    """Interactively label each event"""
    with open(input_file, 'r') as f:
        dataset = json.load(f)
    
    print("\n" + "="*80)
    print("INTERACTIVE LABELING")
    print("="*80)
    print("For each event, mark as:")
    print("  1 = True Positive (correctly identified threat)")
    print("  0 = False Positive (incorrectly identified as threat)")
    print("  s = Skip this entry")
    print("  q = Quit and save")
    print("="*80 + "\n")
    
    labeled_count = 0
    for i, entry in enumerate(dataset):
        if entry.get('ground_truth') is not None:
            labeled_count += 1
            continue
        
        print(f"\n[{i+1}/{len(dataset)}] Event: {entry['event_kind']} from {entry['src_ip']}")
        print(f"  Confidence: {entry['lm_confidence']:.3f}")
        print(f"  Severity: {entry['severity']}")
        print(f"  Action: {entry['recommended_action']}")
        print(f"  Justification: {entry['justification'][:100]}...")
        
        while True:
            label = input("\n  Label (1=TP, 0=FP, s=skip, q=quit): ").strip().lower()
            
            if label == 'q':
                print("\n[Label] Quitting and saving...")
                break
            elif label == 's':
                print("  Skipped.")
                break
            elif label == '1':
                entry['ground_truth'] = 1
                labeled_count += 1
                print("  ✓ Labeled as True Positive")
                break
            elif label == '0':
                entry['ground_truth'] = 0
                labeled_count += 1
                print("  ✓ Labeled as False Positive")
                break
            else:
                print("  Invalid input. Try again.")
        
        if label == 'q':
            break
    
    # Save labeled dataset
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\n[Label] ✅ Saved {labeled_count} labeled entries to {output_file}")
    return dataset


def auto_label(input_file='dataset_raw.json', output_file='dataset_labeled.json'):
    """
    Auto-label based on simple heuristics (quick start)
    
    Rules:
    - High severity SSH brute force from external IP = True Positive
    - Port scans with medium/high severity = True Positive
    - Low severity web fuzz = False Positive (likely normal traffic)
    
    Note: This is approximate! Manual labeling is better for scientific rigor.
    """
    with open(input_file, 'r') as f:
        dataset = json.load(f)
    
    print("\n[Auto-Label] Applying heuristic rules...")
    
    labeled_count = 0
    for entry in dataset:
        kind = entry['event_kind']
        severity = entry['severity']
        src_ip = entry['src_ip']
        
        # Skip already labeled
        if entry.get('ground_truth') is not None:
            labeled_count += 1
            continue
        
        # Heuristic rules
        if kind == 'ssh_failed':
            if severity == 'High' and not src_ip.startswith('192.168'):
                entry['ground_truth'] = 1
                entry['notes'] = 'Auto-labeled: External SSH brute force'
            elif severity == 'Low':
                entry['ground_truth'] = 0
                entry['notes'] = 'Auto-labeled: Low severity, likely benign'
            else:
                entry['ground_truth'] = 1
                entry['notes'] = 'Auto-labeled: Medium severity SSH'
        
        elif kind == 'port_scan':
            if severity in ['High', 'Medium']:
                entry['ground_truth'] = 1
                entry['notes'] = 'Auto-labeled: Port scan detected'
            else:
                entry['ground_truth'] = 0
                entry['notes'] = 'Auto-labeled: Low severity scan'
        
        elif kind == 'web_fuzz':
            if severity == 'High':
                entry['ground_truth'] = 1
                entry['notes'] = 'Auto-labeled: Aggressive web fuzzing'
            else:
                entry['ground_truth'] = 0
                entry['notes'] = 'Auto-labeled: Normal web traffic'
        
        else:
            # Unknown event kind - default to False Positive
            entry['ground_truth'] = 0
            entry['notes'] = 'Auto-labeled: Unknown event type'
        
        labeled_count += 1
    
    # Save
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    # Print statistics
    total = len(dataset)
    tp_count = sum(1 for e in dataset if e.get('ground_truth') == 1)
    fp_count = sum(1 for e in dataset if e.get('ground_truth') == 0)
    
    print(f"\n[Auto-Label] ✅ Labeled {labeled_count} entries")
    print(f"[Auto-Label] True Positives: {tp_count} ({tp_count/total*100:.1f}%)")
    print(f"[Auto-Label] False Positives: {fp_count} ({fp_count/total*100:.1f}%)")
    print(f"[Auto-Label] Saved to {output_file}")
    print("\n[Auto-Label] ⚠️  Note: Auto-labeling is approximate!")
    print("[Auto-Label] For best results, manually review with --label option")
    
    return dataset


def validate_dataset(input_file='dataset_labeled.json'):
    """Validate that dataset is ready for training"""
    with open(input_file, 'r') as f:
        dataset = json.load(f)
    
    total = len(dataset)
    labeled = sum(1 for e in dataset if e.get('ground_truth') is not None)
    unlabeled = total - labeled
    
    if labeled == 0:
        print(f"\n[Validate] ❌ No labeled data! Use --label or --auto-label first")
        return False
    
    tp_count = sum(1 for e in dataset if e.get('ground_truth') == 1)
    fp_count = sum(1 for e in dataset if e.get('ground_truth') == 0)
    
    print("\n" + "="*80)
    print("DATASET VALIDATION")
    print("="*80)
    print(f"Total entries: {total}")
    print(f"Labeled: {labeled} ({labeled/total*100:.1f}%)")
    print(f"Unlabeled: {unlabeled}")
    print(f"\nLabel distribution:")
    print(f"  True Positives: {tp_count} ({tp_count/labeled*100:.1f}%)")
    print(f"  False Positives: {fp_count} ({fp_count/labeled*100:.1f}%)")
    print("="*80)
    
    if labeled < 20:
        print(f"\n[Validate] ⚠️  Warning: Only {labeled} labeled samples")
        print("[Validate] Recommendation: Collect at least 30-50 samples for reliable training")
    
    if tp_count == 0 or fp_count == 0:
        print(f"\n[Validate] ⚠️  Warning: Imbalanced dataset!")
        print(f"[Validate] You need both TP and FP samples for calibration")
        return False
    
    print(f"\n[Validate] ✅ Dataset is valid and ready for training!")
    return True


def show_statistics(input_file='dataset_labeled.json'):
    """Show detailed dataset statistics"""
    with open(input_file, 'r') as f:
        dataset = json.load(f)
    
    # Filter labeled only
    labeled = [e for e in dataset if e.get('ground_truth') is not None]
    
    if not labeled:
        print("[Stats] No labeled data found.")
        return
    
    # Statistics by event kind
    print("\n" + "="*80)
    print("DATASET STATISTICS")
    print("="*80)
    
    event_kinds = {}
    for entry in labeled:
        kind = entry['event_kind']
        gt = entry['ground_truth']
        
        if kind not in event_kinds:
            event_kinds[kind] = {'tp': 0, 'fp': 0}
        
        if gt == 1:
            event_kinds[kind]['tp'] += 1
        else:
            event_kinds[kind]['fp'] += 1
    
    print("\nBy Event Type:")
    for kind, counts in event_kinds.items():
        total = counts['tp'] + counts['fp']
        print(f"  {kind:15} - TP: {counts['tp']:3} | FP: {counts['fp']:3} | Total: {total:3}")
    
    # Confidence distribution
    import numpy as np
    confidences = [e['lm_confidence'] for e in labeled]
    print(f"\nConfidence Statistics:")
    print(f"  Mean: {np.mean(confidences):.3f}")
    print(f"  Median: {np.median(confidences):.3f}")
    print(f"  Std: {np.std(confidences):.3f}")
    print(f"  Min: {np.min(confidences):.3f}")
    print(f"  Max: {np.max(confidences):.3f}")
    
    print("="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(description='Collect and label dataset for calibration training')
    parser.add_argument('--collect', action='store_true', help='Collect events from analyzer API')
    parser.add_argument('--label', action='store_true', help='Interactively label dataset')
    parser.add_argument('--auto-label', action='store_true', help='Auto-label using heuristics (quick start)')
    parser.add_argument('--validate', action='store_true', help='Validate dataset is ready for training')
    parser.add_argument('--stats', action='store_true', help='Show dataset statistics')
    parser.add_argument('--input', type=str, default='dataset_raw.json', help='Input file')
    parser.add_argument('--output', type=str, default='dataset_labeled.json', help='Output file')
    parser.add_argument('--analyzer-url', type=str, default='http://127.0.0.1:6002', help='Analyzer API URL')
    
    args = parser.parse_args()
    
    if args.collect:
        collect_from_analyzer(args.analyzer_url, args.output)
    
    elif args.label:
        label_interactively(args.input, args.output)
    
    elif args.auto_label:
        auto_label(args.input, args.output)
    
    elif args.validate:
        validate_dataset(args.input)
    
    elif args.stats:
        show_statistics(args.input)
    
    else:
        print("Usage:")
        print("  python3 collect_dataset.py --collect --output dataset_raw.json")
        print("  python3 collect_dataset.py --auto-label --input dataset_raw.json --output dataset_labeled.json")
        print("  python3 collect_dataset.py --validate --input dataset_labeled.json")
        print("  python3 collect_dataset.py --stats --input dataset_labeled.json")


if __name__ == "__main__":
    main()
